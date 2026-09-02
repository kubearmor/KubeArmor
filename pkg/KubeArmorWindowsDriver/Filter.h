// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor


#pragma once
#include "pch.h"
#include "Context.h"

EXTERN_C_START

// ==========================
// ==== Filter Callbacks ====
// ==========================

// create
FLT_PREOP_CALLBACK_STATUS FLTAPI PreCreateCallback(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
);

FLT_POSTOP_CALLBACK_STATUS PostCreateCallback(
    _Inout_ PFLT_CALLBACK_DATA data,
    _In_ PCFLT_RELATED_OBJECTS fltObjects,
    _In_ PVOID completionContext,
    _In_ FLT_POST_OPERATION_FLAGS flags);

// write
FLT_PREOP_CALLBACK_STATUS PreWriteCallback(
    _Inout_ PFLT_CALLBACK_DATA data,
    _In_ PCFLT_RELATED_OBJECTS fltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* completionContext);

FLT_POSTOP_CALLBACK_STATUS PostWriteCallback(
    _Inout_ PFLT_CALLBACK_DATA data,
    _In_ PCFLT_RELATED_OBJECTS fltObjects,
    _In_ PVOID completionContext,
    _In_ FLT_POST_OPERATION_FLAGS flags);

// read
FLT_PREOP_CALLBACK_STATUS PreReadCallback(
    _Inout_ PFLT_CALLBACK_DATA data,
    _In_ PCFLT_RELATED_OBJECTS fltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* completionContext);

FLT_POSTOP_CALLBACK_STATUS PostReadCallback(
    _Inout_ PFLT_CALLBACK_DATA data,
    _In_ PCFLT_RELATED_OBJECTS fltObjects,
    _In_ PVOID completionContext,
    _In_ FLT_POST_OPERATION_FLAGS flags);

// set information
FLT_PREOP_CALLBACK_STATUS PreSetInformationCallback(
    _Inout_ PFLT_CALLBACK_DATA data,
    _In_ PCFLT_RELATED_OBJECTS fltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* completionContext);

FLT_POSTOP_CALLBACK_STATUS PostSetInformationCallback(
    _Inout_ PFLT_CALLBACK_DATA data,
    _In_ PCFLT_RELATED_OBJECTS fltObjects,
    _In_ PVOID completionContext,
    _In_ FLT_POST_OPERATION_FLAGS flags);

// cleanup
FLT_PREOP_CALLBACK_STATUS PreCleanupCallback(
    _Inout_ PFLT_CALLBACK_DATA data,
    _In_ PCFLT_RELATED_OBJECTS fltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* completionContext);

FLT_POSTOP_CALLBACK_STATUS PostCleanupCallback(
    _Inout_ PFLT_CALLBACK_DATA data,
    _In_ PCFLT_RELATED_OBJECTS fltObjects,
    _In_ PVOID completionContext,
    _In_ FLT_POST_OPERATION_FLAGS flags);

// ==== // Filter Callbacks

NTSTATUS FLTAPI InstanceFilterUnloadCallback(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
);

NTSTATUS FLTAPI InstanceSetupCallback(
    _In_ PCFLT_RELATED_OBJECTS  FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS  Flags,
    _In_ DEVICE_TYPE  VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE  VolumeFilesystemType
);

NTSTATUS FLTAPI InstanceQueryTeardownCallback(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
);

VOID InstanceStartTeardownCallback(
    _In_ PCFLT_RELATED_OBJECTS,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS);

VOID InstanceCompleteTeardownCallback(
    _In_ PCFLT_RELATED_OBJECTS pFltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS);

VOID InstanceContextCleanup(
    _In_ PFLT_CONTEXT pContext, 
    _In_ FLT_CONTEXT_TYPE);

VOID StreamHandleContextCleanup(
    _In_ PFLT_CONTEXT pContext,
    _In_ FLT_CONTEXT_TYPE contextType);

NTSTATUS
ScannerPortConnect(
    _In_ PFLT_PORT ClientPort,
    _In_opt_ PVOID ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Outptr_result_maybenull_ PVOID* ConnectionCookie
);

VOID
ScannerPortDisconnect(
    _In_opt_ PVOID ConnectionCookie
);

NTSTATUS RegisterFilter(
    _In_ PDRIVER_OBJECT DriverObject
);

EXTERN_C_END

extern const FLT_OPERATION_REGISTRATION g_callbacks[];
extern const FLT_CONTEXT_REGISTRATION   g_ContextCallbacks[];
extern const FLT_REGISTRATION           g_filterRegistration;

typedef struct _SCANNER_DATA {

    PFLT_FILTER Filter;
    PFLT_PORT ServerPort;
    PEPROCESS UserProcess;
    PFLT_PORT ClientPort;

} SCANNER_DATA, * PSCANNER_DATA;

extern SCANNER_DATA g_ScannerData;

#define MAX_FILTER_EVENT_SIZE (64 * 1024)

#include "EventStructs.h"
