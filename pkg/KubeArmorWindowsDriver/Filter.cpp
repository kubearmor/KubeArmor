// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor


#include "Filter.h"
#include "Context.h"
#include "Buffer.h"
#include "Protocol.h"
#include "FileEvent.h"
#include "FilenameInformationGuard.h"
#include "AsyncEventDispatcher.h"
#include "Globals.h"

extern Globals g_State;

constexpr auto EVENT_TAG = 'evnt';
static const HANDLE g_systemProcessId = reinterpret_cast<HANDLE>(4);

// STATUS_TOO_MANY_CONNECTIONS may not be declared in older WDK ntstatus.h builds.
// Define it locally from its canonical value; the #ifndef means a future SDK
// definition will silently win.
#ifndef STATUS_TOO_MANY_CONNECTIONS
#define STATUS_TOO_MANY_CONNECTIONS ((NTSTATUS)0xC0000173L)
#endif

// ============================================================================
//  Filter registration tables (single definition \u2014 extern-declared in Filter.h)
// ============================================================================

#ifdef ALLOC_PRAGMA
    #pragma alloc_text(PAGE, InstanceFilterUnloadCallback)
    #pragma alloc_text(PAGE, InstanceSetupCallback)
    #pragma alloc_text(PAGE, InstanceQueryTeardownCallback)
#endif

const FLT_OPERATION_REGISTRATION g_callbacks[] =
{
    { IRP_MJ_CREATE,          0,                                          PreCreateCallback,         PostCreateCallback         },
    { IRP_MJ_READ,            0,                                          PreReadCallback,           PostReadCallback           },
    { IRP_MJ_WRITE,           0,                                          PreWriteCallback,          PostWriteCallback          },
    { IRP_MJ_SET_INFORMATION, FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO, PreSetInformationCallback, PostSetInformationCallback },
    { IRP_MJ_CLEANUP,         0,                                          PreCleanupCallback,        PostCleanupCallback        },
    { IRP_MJ_OPERATION_END }
};

const FLT_CONTEXT_REGISTRATION g_ContextCallbacks[] = {
    { FLT_INSTANCE_CONTEXT,     0, InstanceContextCleanup,     sizeof(InstanceContext),     c_CtxAllocTag },
    { FLT_STREAMHANDLE_CONTEXT, 0, StreamHandleContextCleanup, sizeof(StreamHandleContext), c_CtxAllocTag },
    { FLT_CONTEXT_END }
};

const FLT_REGISTRATION g_filterRegistration =
{
    sizeof(FLT_REGISTRATION),           //  Size
    FLT_REGISTRATION_VERSION,           //  Version
    0,                                  //  Flags
    g_ContextCallbacks,                 //  Context registration
    g_callbacks,                        //  Operation callbacks
    InstanceFilterUnloadCallback,       //  FilterUnload
    InstanceSetupCallback,              //  InstanceSetup
    InstanceQueryTeardownCallback,      //  InstanceQueryTeardown
    InstanceStartTeardownCallback,      //  InstanceTeardownStart
    InstanceCompleteTeardownCallback,   //  InstanceTeardownComplete
    NULL,                               //  GenerateFileName
    NULL,                               //  GenerateDestinationFileName
    NULL                                //  NormalizeNameComponent
};
// ==========================
// ==== Filter Callbacks ====
// ==========================

static BOOLEAN SkipReadWriteIo(_In_ PFLT_CALLBACK_DATA data)
{
    if (data->Iopb->IrpFlags & IRP_PAGING_IO)             return TRUE;
    if (data->Iopb->IrpFlags & IRP_SYNCHRONOUS_PAGING_IO) return TRUE;
    if (FLT_IS_FASTIO_OPERATION(data))                     return TRUE;
    return FALSE;
}

BOOLEAN SkipEvent(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects)
{
    if (KeGetCurrentIrql() > PASSIVE_LEVEL ||
        IoGetTopLevelIrp() ||
        FLT_IS_FASTIO_OPERATION(Data) ||
        !FLT_IS_IRP_OPERATION(Data))
        return TRUE;

    if (PsGetCurrentProcessId() == g_systemProcessId)
        return TRUE;

    if (FltObjects->FileObject->Flags & (FO_NAMED_PIPE | FO_MAILSLOT | FO_VOLUME_OPEN))
        return TRUE;

    return FALSE;
}

// ============================================================================
//  IRP_MJ_CREATE
// ============================================================================

FLT_PREOP_CALLBACK_STATUS PreCreateCallback(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext)
{
    UNREFERENCED_PARAMETER(CompletionContext);

    if (!Data || !FltObjects)                          return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (KeGetCurrentIrql() > PASSIVE_LEVEL ||
        IoGetTopLevelIrp() ||
        FLT_IS_FASTIO_OPERATION(Data) ||
        !FLT_IS_IRP_OPERATION(Data))                   return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (PsGetCurrentProcessId() == g_systemProcessId)  return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (FltObjects->FileObject->Flags &
        (FO_NAMED_PIPE | FO_MAILSLOT | FO_VOLUME_OPEN))return FLT_PREOP_SUCCESS_NO_CALLBACK;

    // === File enforcement: check file rules ===
    PFLT_FILE_NAME_INFORMATION fileNameInfo = NULL;
    NTSTATUS status = FltGetFileNameInformation(
        Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &fileNameInfo);

    if (NT_SUCCESS(status)) {
        FltParseFileNameInformation(fileNameInfo);

        // Look up file rule by normalized NT path
        PRULE_ENTRY rule = g_State.LookupFileRule(&fileNameInfo->Name);

        if (rule) {
            // ReadOnly flag: block write access regardless of whether the
            // base action is Block or Allow. A readOnly:true policy means
            // "allow reads, block writes" — this applies to both action:Block
            // and action:Allow rules that carry RULE_FLAG_READONLY.
            if (rule->Flags & RULE_FLAG_READONLY) {
                ACCESS_MASK desiredAccess =
                    Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
                ULONG createOptions =
                    Data->Iopb->Parameters.Create.Options & 0x00FFFFFF;

                // Write-specific access flags. MAXIMUM_ALLOWED is intentionally
                // excluded — it means "give me the maximum permitted access" and
                // is used by read-only openers such as Explorer. Blocking it
                // would deny reads, which defeats the purpose of readOnly.
                constexpr ACCESS_MASK WRITE_ACCESS_MASK =
                    FILE_WRITE_DATA   |  // write file content
                    FILE_APPEND_DATA  |  // append to file
                    FILE_WRITE_EA     |  // write extended attributes
                    FILE_WRITE_ATTRIBUTES | // write timestamps/attribs
                    DELETE |             // delete the file
                    GENERIC_WRITE |      // generic write (maps to the above)
                    GENERIC_ALL;         // all-access (includes writes)

                if ((desiredAccess & WRITE_ACCESS_MASK) ||
                    (createOptions & FILE_DELETE_ON_CLOSE)) {
                    KdPrint(("[kubearmor] Karmor: BLOCKED write access (readOnly) to: %wZ\n", &fileNameInfo->Name));
                    g_AsyncDispatcher.EnqueueFileEvent(
                        &fileNameInfo->Name,
                        HandleToULong(PsGetCurrentProcessId()), TRUE);
                    Data->IoStatus.Status = STATUS_ACCESS_DENIED;
                    Data->IoStatus.Information = 0;
                    FltReleaseFileNameInformation(fileNameInfo);
                    return FLT_PREOP_COMPLETE;
                }
                // Read-only access is allowed through — fall to bottom
            } else if (rule->Action == RuleAction::Block) {
                // Full block: deny all access
                KdPrint(("[kubearmor] Karmor: BLOCKED access to: %wZ\n", &fileNameInfo->Name));
                g_AsyncDispatcher.EnqueueFileEvent(
                    &fileNameInfo->Name,
                    HandleToULong(PsGetCurrentProcessId()), TRUE);
                Data->IoStatus.Status = STATUS_ACCESS_DENIED;
                Data->IoStatus.Information = 0;
                FltReleaseFileNameInformation(fileNameInfo);
                return FLT_PREOP_COMPLETE;
            } else if (rule->Action == RuleAction::Audit) {
                // Audit mode: allow access, but queue a MatchHostPolicy event
                KdPrint(("[kubearmor] Karmor: AUDIT access to: %wZ\n", &fileNameInfo->Name));
                g_AsyncDispatcher.EnqueueFileEvent(
                    &fileNameInfo->Name,
                    HandleToULong(PsGetCurrentProcessId()), FALSE);
            }
            // Action == Allow (without ReadOnly): pass through
        }

        FltReleaseFileNameInformation(fileNameInfo);
    }

    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS PostCreateCallback(
    _Inout_ PFLT_CALLBACK_DATA data,
    _In_ PCFLT_RELATED_OBJECTS fltObjects,
    _In_ PVOID completionContext,
    _In_ FLT_POST_OPERATION_FLAGS flags)
{
    UNREFERENCED_PARAMETER(completionContext);

    if (flags & FLTFL_POST_OPERATION_DRAINING)         return FLT_POSTOP_FINISHED_PROCESSING;
    if (!NT_SUCCESS(data->IoStatus.Status) ||
        data->IoStatus.Status == STATUS_REPARSE)        return FLT_POSTOP_FINISHED_PROCESSING;
    if (SkipEvent(data, fltObjects))                    return FLT_POSTOP_FINISHED_PROCESSING;

    StreamHandleContext* pStrHandleCtx = nullptr;
    InstanceContext* pInstCtx = nullptr;

    __try {
        NTSTATUS status = FltAllocateContext(
            fltObjects->Filter, FLT_STREAMHANDLE_CONTEXT,
            sizeof(StreamHandleContext), NonPagedPool,
            (PFLT_CONTEXT*)&pStrHandleCtx);
        if (!NT_SUCCESS(status)) __leave;

        status = Context::InitializeStreamHandleContext(data, fltObjects, pStrHandleCtx);
        if (!NT_SUCCESS(status)) __leave;

        status = FltSetStreamHandleContext(
            fltObjects->Instance, fltObjects->FileObject,
            FLT_SET_CONTEXT_REPLACE_IF_EXISTS, pStrHandleCtx, nullptr);
        if (!NT_SUCCESS(status)) __leave;

        status = FltGetInstanceContext(fltObjects->Instance, (PFLT_CONTEXT*)&pInstCtx);
        if (!NT_SUCCESS(status)) __leave;

        if (pStrHandleCtx->fileIoStatus == FILE_CREATED)
            g_AsyncDispatcher.Enqueue(protocol::EVENT_TYPE::EVENT_TYPE_FILE_CREATE,
                pStrHandleCtx, pInstCtx);
    }
    __finally {
        if (pStrHandleCtx) FltReleaseContext((PFLT_CONTEXT)pStrHandleCtx);
        if (pInstCtx)      FltReleaseContext((PFLT_CONTEXT)pInstCtx);
    }

    return FLT_POSTOP_FINISHED_PROCESSING;
}

// ============================================================================
//  IRP_MJ_READ
// ============================================================================

FLT_PREOP_CALLBACK_STATUS PreReadCallback(
    _Inout_ PFLT_CALLBACK_DATA data,
    _In_ PCFLT_RELATED_OBJECTS fltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* completionContext)
{
    UNREFERENCED_PARAMETER(completionContext);

    if (SkipReadWriteIo(data))    return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (SkipEvent(data, fltObjects)) return FLT_PREOP_SUCCESS_NO_CALLBACK;

    StreamHandleContext* pStrHandleCtx = nullptr;
    NTSTATUS status = FltGetStreamHandleContext(
        fltObjects->Instance, fltObjects->FileObject,
        (PFLT_CONTEXT*)&pStrHandleCtx);
    if (!NT_SUCCESS(status)) return FLT_PREOP_SUCCESS_NO_CALLBACK;

    FltReleaseContext(pStrHandleCtx);
    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS PostReadCallback(
    _Inout_ PFLT_CALLBACK_DATA data,
    _In_ PCFLT_RELATED_OBJECTS fltObjects,
    _In_ PVOID completionContext,
    _In_ FLT_POST_OPERATION_FLAGS flags)
{
    UNREFERENCED_PARAMETER(completionContext);

    if (SkipEvent(data, fltObjects) || (flags & FLTFL_POST_OPERATION_DRAINING))
        return FLT_POSTOP_FINISHED_PROCESSING;
    if (!NT_SUCCESS(data->IoStatus.Status) || data->IoStatus.Information == 0)
        return FLT_POSTOP_FINISHED_PROCESSING;

    StreamHandleContext* pStrHandleCtx = nullptr;
    if (NT_SUCCESS(FltGetStreamHandleContext(fltObjects->Instance, fltObjects->FileObject,
        (PFLT_CONTEXT*)&pStrHandleCtx))
        && pStrHandleCtx)
    {
        pStrHandleCtx->wasRead = TRUE;
        FltReleaseContext(pStrHandleCtx);
    }
    return FLT_POSTOP_FINISHED_PROCESSING;
}

// ============================================================================
//  IRP_MJ_WRITE
// ============================================================================

FLT_PREOP_CALLBACK_STATUS PreWriteCallback(
    _Inout_ PFLT_CALLBACK_DATA data,
    _In_ PCFLT_RELATED_OBJECTS fltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* completionContext)
{
    UNREFERENCED_PARAMETER(completionContext);

    if (SkipReadWriteIo(data))       return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (SkipEvent(data, fltObjects)) return FLT_PREOP_SUCCESS_NO_CALLBACK;

    StreamHandleContext* pStrHandleCtx = nullptr;
    NTSTATUS status = FltGetStreamHandleContext(
        fltObjects->Instance, fltObjects->FileObject,
        (PFLT_CONTEXT*)&pStrHandleCtx);
    if (!NT_SUCCESS(status)) return FLT_PREOP_SUCCESS_NO_CALLBACK;

    // === File enforcement: defense-in-depth readOnly write blocking ===
    // Even if PreCreateCallback allowed the handle (read-only open),
    // block any actual write I/O to files with readOnly rules.
    // This applies to BOTH Block+ReadOnly and Allow+ReadOnly semantics.
    if (pStrHandleCtx->filePath.Length > 0) {
        PRULE_ENTRY rule = g_State.LookupFileRule(&pStrHandleCtx->filePath);
        if (rule && (rule->Flags & RULE_FLAG_READONLY)) {
            KdPrint(("[kubearmor] Karmor: BLOCKED write I/O to readOnly file: %wZ\n",
                &pStrHandleCtx->filePath));
            FltReleaseContext(pStrHandleCtx);
            data->IoStatus.Status = STATUS_ACCESS_DENIED;
            return FLT_PREOP_COMPLETE;
        }
    }

    if (!pStrHandleCtx->readOnly || data->Iopb->Parameters.Write.Length == 0)
    {
        FltReleaseContext(pStrHandleCtx);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    FltReleaseContext(pStrHandleCtx);
    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS PostWriteCallback(
    _Inout_ PFLT_CALLBACK_DATA data,
    _In_ PCFLT_RELATED_OBJECTS fltObjects,
    _In_ PVOID completionContext,
    _In_ FLT_POST_OPERATION_FLAGS flags)
{
    UNREFERENCED_PARAMETER(completionContext);

    if (SkipEvent(data, fltObjects) || (flags & FLTFL_POST_OPERATION_DRAINING))
        return FLT_POSTOP_FINISHED_PROCESSING;
    if (!NT_SUCCESS(data->IoStatus.Status) || data->IoStatus.Information == 0)
        return FLT_POSTOP_FINISHED_PROCESSING;

    StreamHandleContext* pStrHandleCtx = nullptr;
    if (NT_SUCCESS(FltGetStreamHandleContext(fltObjects->Instance, fltObjects->FileObject,
        (PFLT_CONTEXT*)&pStrHandleCtx))
        && pStrHandleCtx)
    {
        pStrHandleCtx->wasChanged = TRUE;
        FltReleaseContext(pStrHandleCtx);
    }
    return FLT_POSTOP_FINISHED_PROCESSING;
}

// ============================================================================
//  IRP_MJ_SET_INFORMATION
// ============================================================================

FLT_PREOP_CALLBACK_STATUS PreSetInformationCallback(
    _Inout_ PFLT_CALLBACK_DATA data,
    _In_ PCFLT_RELATED_OBJECTS fltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* completionContext)
{
    UNREFERENCED_PARAMETER(completionContext);

    if (SkipEvent(data, fltObjects)) return FLT_PREOP_SUCCESS_NO_CALLBACK;

    FILE_INFORMATION_CLASS infoClass =
        data->Iopb->Parameters.SetFileInformation.FileInformationClass;

    BOOLEAN isDelete = (infoClass == FileDispositionInformation ||
        infoClass == FileDispositionInformationEx);
    BOOLEAN isRename = (infoClass == FileRenameInformation ||
        infoClass == FileRenameInformationEx);

    if (!isDelete && !isRename) return FLT_PREOP_SUCCESS_NO_CALLBACK;

    StreamHandleContext* pStrHandleCtx = nullptr;
    NTSTATUS status = FltGetStreamHandleContext(
        fltObjects->Instance, fltObjects->FileObject,
        (PFLT_CONTEXT*)&pStrHandleCtx);
    if (!NT_SUCCESS(status)) return FLT_PREOP_SUCCESS_NO_CALLBACK;

    // === File enforcement: block rename/delete on protected files ===
    if (pStrHandleCtx->filePath.Length > 0) {
        PRULE_ENTRY rule = g_State.LookupFileRule(&pStrHandleCtx->filePath);
        if (rule) {
            if (rule->Action == RuleAction::Block) {
                // Full block: deny both rename and delete
                // ReadOnly block: also deny rename and delete (they are write operations)
                KdPrint(("[kubearmor] Karmor: BLOCKED %s on protected file: %wZ\n",
                    isDelete ? "delete" : "rename", &pStrHandleCtx->filePath));
                g_AsyncDispatcher.EnqueueFileEvent(
                    &pStrHandleCtx->filePath,
                    HandleToULong(PsGetCurrentProcessId()), TRUE);
                FltReleaseContext(pStrHandleCtx);
                data->IoStatus.Status = STATUS_ACCESS_DENIED;
                data->IoStatus.Information = 0;
                return FLT_PREOP_COMPLETE;
            } else if (rule->Action == RuleAction::Audit) {
                KdPrint(("[kubearmor] Karmor: AUDIT %s on protected file: %wZ\n",
                    isDelete ? "delete" : "rename", &pStrHandleCtx->filePath));
                g_AsyncDispatcher.EnqueueFileEvent(
                    &pStrHandleCtx->filePath,
                    HandleToULong(PsGetCurrentProcessId()), FALSE);
            }
        }
    }

    FltReleaseContext(pStrHandleCtx);
    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS PostSetInformationCallback(
    _Inout_ PFLT_CALLBACK_DATA data,
    _In_ PCFLT_RELATED_OBJECTS fltObjects,
    _In_ PVOID completionContext,
    _In_ FLT_POST_OPERATION_FLAGS flags)
{
    UNREFERENCED_PARAMETER(completionContext);

    if (SkipEvent(data, fltObjects) || (flags & FLTFL_POST_OPERATION_DRAINING))
        return FLT_POSTOP_FINISHED_PROCESSING;
    if (!NT_SUCCESS(data->IoStatus.Status))
        return FLT_POSTOP_FINISHED_PROCESSING;

    StreamHandleContext* pStrHandleCtx = nullptr;
    InstanceContext* pInstCtx = nullptr;

    __try {
        NTSTATUS status = FltGetStreamHandleContext(
            fltObjects->Instance, fltObjects->FileObject,
            (PFLT_CONTEXT*)&pStrHandleCtx);
        if (!NT_SUCCESS(status)) __leave;

        FILE_INFORMATION_CLASS infoClass =
            data->Iopb->Parameters.SetFileInformation.FileInformationClass;

        BOOLEAN isDelete = (infoClass == FileDispositionInformation ||
            infoClass == FileDispositionInformationEx);
        BOOLEAN isRename = (infoClass == FileRenameInformation ||
            infoClass == FileRenameInformationEx);

        if (!isDelete && !isRename) __leave;

        if (isDelete)
            pStrHandleCtx->dispositionDelete = TRUE;

        if (isRename)
        {
            pStrHandleCtx->dispositionRename = TRUE;
            status = FltGetInstanceContext(fltObjects->Instance, (PFLT_CONTEXT*)&pInstCtx);
            if (NT_SUCCESS(status))
                g_AsyncDispatcher.Enqueue(protocol::EVENT_TYPE::EVENT_TYPE_FILE_RENAME,
                    pStrHandleCtx, pInstCtx);
        }
    }
    __finally {
        if (pStrHandleCtx) FltReleaseContext(pStrHandleCtx);
        if (pInstCtx)      FltReleaseContext(pInstCtx);
    }

    return FLT_POSTOP_FINISHED_PROCESSING;
}

// ============================================================================
//  IRP_MJ_CLEANUP
// ============================================================================

FLT_PREOP_CALLBACK_STATUS PreCleanupCallback(
    _Inout_ PFLT_CALLBACK_DATA data,
    _In_ PCFLT_RELATED_OBJECTS fltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* completionContext)
{
    UNREFERENCED_PARAMETER(completionContext);

    if (SkipEvent(data, fltObjects)) return FLT_PREOP_SUCCESS_NO_CALLBACK;

    StreamHandleContext* pStrHandleCtx = nullptr;
    NTSTATUS status = FltGetStreamHandleContext(
        fltObjects->Instance, fltObjects->FileObject,
        (PFLT_CONTEXT*)&pStrHandleCtx);
    if (!NT_SUCCESS(status)) return FLT_PREOP_SUCCESS_NO_CALLBACK;

    FltReleaseContext(pStrHandleCtx);
    return FLT_PREOP_SYNCHRONIZE;
}

FLT_POSTOP_CALLBACK_STATUS PostCleanupCallback(
    _Inout_ PFLT_CALLBACK_DATA data,
    _In_ PCFLT_RELATED_OBJECTS fltObjects,
    _In_ PVOID completionContext,
    _In_ FLT_POST_OPERATION_FLAGS flags)
{
    UNREFERENCED_PARAMETER(completionContext);

    if (SkipEvent(data, fltObjects) || (flags & FLTFL_POST_OPERATION_DRAINING))
        return FLT_POSTOP_FINISHED_PROCESSING;
    if (!NT_SUCCESS(data->IoStatus.Status))
        return FLT_POSTOP_FINISHED_PROCESSING;

    StreamHandleContext* pStrHandleCtx = nullptr;
    InstanceContext* pInstCtx = nullptr;

    __try {
        NTSTATUS status = FltGetStreamHandleContext(
            fltObjects->Instance, fltObjects->FileObject,
            (PFLT_CONTEXT*)&pStrHandleCtx);
        if (!NT_SUCCESS(status)) __leave;

        status = FltGetInstanceContext(fltObjects->Instance, (PFLT_CONTEXT*)&pInstCtx);
        if (!NT_SUCCESS(status)) __leave;

        BOOLEAN deleted = pStrHandleCtx->deleteOnClose | pStrHandleCtx->dispositionDelete;

        if (pStrHandleCtx->wasRead)
            g_AsyncDispatcher.Enqueue(protocol::EVENT_TYPE::EVENT_TYPE_FILE_READ,
                pStrHandleCtx, pInstCtx);

        if (pStrHandleCtx->wasChanged && !deleted)
            g_AsyncDispatcher.Enqueue(protocol::EVENT_TYPE::EVENT_TYPE_FILE_WRITE,
                pStrHandleCtx, pInstCtx);

        if (deleted && pStrHandleCtx->fileIoStatus != FILE_CREATED)
            g_AsyncDispatcher.Enqueue(protocol::EVENT_TYPE::EVENT_TYPE_FILE_DELETE,
                pStrHandleCtx, pInstCtx);
        else if (!deleted && !pStrHandleCtx->dispositionRename)
            g_AsyncDispatcher.Enqueue(protocol::EVENT_TYPE::EVENT_TYPE_FILE_CLOSE,
                pStrHandleCtx, pInstCtx);
    }
    __finally {
        if (pStrHandleCtx) FltReleaseContext(pStrHandleCtx);
        if (pInstCtx)      FltReleaseContext(pInstCtx);
    }

    return FLT_POSTOP_FINISHED_PROCESSING;
}

// ============================================================================
//  Port connect / disconnect
// ============================================================================

NTSTATUS ScannerPortConnect(
    _In_ PFLT_PORT ClientPort,
    _In_opt_ PVOID ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Outptr_result_maybenull_ PVOID* ConnectionCookie)
{
    PAGED_CODE();
    UNREFERENCED_PARAMETER(ServerPortCookie);
    UNREFERENCED_PARAMETER(ConnectionContext);
    UNREFERENCED_PARAMETER(SizeOfContext);
    UNREFERENCED_PARAMETER(ConnectionCookie = NULL);

    // Graceful guard: reject a second connection attempt.
    if (g_ScannerData.ClientPort != NULL)
        return STATUS_TOO_MANY_CONNECTIONS;

    g_ScannerData.UserProcess = PsGetCurrentProcess();
    g_ScannerData.ClientPort = ClientPort;

    // Dispatcher gets its own copy; FltCloseClientPort stays in Disconnect.
    g_AsyncDispatcher.OnClientConnected(ClientPort);

    KdPrint(("[kubearmor] filter port connected=0x%p\n", ClientPort));
    return STATUS_SUCCESS;
}

VOID ScannerPortDisconnect(_In_opt_ PVOID ConnectionCookie)
{
    UNREFERENCED_PARAMETER(ConnectionCookie);
    PAGED_CODE();

    KdPrint(("[kubearmor] filter port disconnected\n"));

    // Clear dispatcher's port reference BEFORE closing the handle so the
    // worker cannot call FltSendMessage on a handle that is about to be freed.
    g_AsyncDispatcher.OnClientDisconnected();

    FltCloseClientPort(g_ScannerData.Filter, &g_ScannerData.ClientPort);
    g_ScannerData.UserProcess = NULL;
}

// ============================================================================
//  Unload
// ============================================================================

NTSTATUS FLTAPI InstanceFilterUnloadCallback(_In_ FLT_FILTER_UNLOAD_FLAGS Flags)
{
    PAGED_CODE();
    UNREFERENCED_PARAMETER(Flags);

    // Stop the async worker thread first, while the FLT port is still alive.
    // This must happen before FltCloseCommunicationPort / FltUnregisterFilter
    // so the worker thread can finish any in-flight FltSendMessage calls.
    // Uninitialize() is idempotent — checks m_initialized internally.
    g_AsyncDispatcher.Uninitialize();

    if (g_ScannerData.ClientPort) {
        FltCloseClientPort(g_ScannerData.Filter, &g_ScannerData.ClientPort);
        g_ScannerData.ClientPort = NULL;
    }

    if (g_ScannerData.ServerPort) {
        FltCloseCommunicationPort(g_ScannerData.ServerPort);
        g_ScannerData.ServerPort = NULL;
    }

    if (g_ScannerData.Filter) {
        FltUnregisterFilter(g_ScannerData.Filter);
        g_ScannerData.Filter = NULL;
    }

    // NOTE: We do NOT free hash tables or ProcessCache here.
    // FltUnregisterFilter above blocks until all minifilter callbacks
    // complete, but DriverUnload (KarmorUnload) is still pending.
    // All state destruction happens there, under the guarantee that
    // no callbacks can fire once FltUnregisterFilter has returned.

    return STATUS_SUCCESS;
}

// ============================================================================
//  InstanceContext callbacks
// ============================================================================

NTSTATUS InstanceSetupCallback(
    _In_ PCFLT_RELATED_OBJECTS fltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS flags,
    _In_ DEVICE_TYPE volumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE volumeFilesystemType)
{
    UNREFERENCED_PARAMETER(flags);
    UNREFERENCED_PARAMETER(volumeDeviceType);
    UNREFERENCED_PARAMETER(volumeFilesystemType);

    KdPrint(("[kubearmor] InstanceSetupCallback\n"));

    InstanceContext* pCtx = nullptr;
    NTSTATUS         status = STATUS_SUCCESS;

    __try {
        PFLT_CONTEXT pFltCtx = NULL;
        status = FltAllocateContext(fltObjects->Filter, FLT_INSTANCE_CONTEXT,
            sizeof(InstanceContext), NonPagedPool, &pFltCtx);
        if (!NT_SUCCESS(status)) __leave;

        pCtx = (InstanceContext*)pFltCtx;
        status = Context::InitializeInstanceContext(fltObjects, pCtx);
        if (!NT_SUCCESS(status)) { FltReleaseContext(pCtx); __leave; }

#ifdef DBG
        PrintInstanceContext(pCtx);
#endif

        status = FltSetInstanceContext(fltObjects->Instance,
            FLT_SET_CONTEXT_REPLACE_IF_EXISTS,
            pCtx, nullptr);
        if (!NT_SUCCESS(status)) { FltReleaseContext(pCtx); __leave; }
    }
    __finally {
        if (pCtx) FltReleaseContext(pCtx);
    }
    return status;
}

NTSTATUS InstanceQueryTeardownCallback(_In_ PCFLT_RELATED_OBJECTS,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS)
{
    return STATUS_SUCCESS;
}

VOID InstanceStartTeardownCallback(_In_ PCFLT_RELATED_OBJECTS,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS) {
}

VOID InstanceCompleteTeardownCallback(_In_ PCFLT_RELATED_OBJECTS pFltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS)
{
    InstanceContext* pCtx = NULL;
    __try { FltGetInstanceContext(pFltObjects->Instance, (PFLT_CONTEXT*)&pCtx); }
    __finally { if (pCtx) FltReleaseContext(pCtx); }
}

VOID InstanceContextCleanup(_In_ PFLT_CONTEXT pContext, _In_ FLT_CONTEXT_TYPE)
{
    if (pContext) Context::CleanupInstanceContext((InstanceContext*)pContext);
}

VOID StreamHandleContextCleanup(_In_ PFLT_CONTEXT pContext, _In_ FLT_CONTEXT_TYPE contextType)
{
    UNREFERENCED_PARAMETER(contextType);
    if (pContext) Context::CleanupStreamHandleContext((StreamHandleContext*)pContext);
}

// ============================================================================
//  RegisterFilter
// ============================================================================

NTSTATUS RegisterFilter(_In_ PDRIVER_OBJECT DriverObject)
{
    PSECURITY_DESCRIPTOR sd;
    OBJECT_ATTRIBUTES    oa;
    UNICODE_STRING       uniString;
    NTSTATUS             status;

    RtlInitUnicodeString(&uniString, L"\\ScannerPort");

    status = FltRegisterFilter(DriverObject, &g_filterRegistration, &g_ScannerData.Filter);
    if (!NT_SUCCESS(status)) return status;

    KdPrint(("[kubearmor] KdPrint:fsminifilter driver loaded"));

    status = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);
    if (!NT_SUCCESS(status)) { FltUnregisterFilter(g_ScannerData.Filter); return status; }

    InitializeObjectAttributes(&oa, &uniString,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, sd);

    status = FltCreateCommunicationPort(
        g_ScannerData.Filter, &g_ScannerData.ServerPort,
        &oa, NULL,
        ScannerPortConnect, ScannerPortDisconnect, NULL, 1);

    FltFreeSecurityDescriptor(sd);

    if (!NT_SUCCESS(status)) { FltUnregisterFilter(g_ScannerData.Filter); return status; }

    status = g_AsyncDispatcher.Initialize(g_ScannerData.Filter);
    if (!NT_SUCCESS(status))
    {
        KdPrint(("[kubearmor] AsyncDispatcher init failed: %08X\n", status));
        FltCloseCommunicationPort(g_ScannerData.ServerPort);
        FltUnregisterFilter(g_ScannerData.Filter);
        return status;
    }

    status = FltStartFiltering(g_ScannerData.Filter);
    if (!NT_SUCCESS(status))
    {
        g_AsyncDispatcher.Uninitialize(); // stop worker before closing port
        FltCloseCommunicationPort(g_ScannerData.ServerPort);
        FltUnregisterFilter(g_ScannerData.Filter);
        return status;
    }

    return STATUS_SUCCESS;
}
