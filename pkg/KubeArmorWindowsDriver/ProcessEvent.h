// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor


#pragma once

#include "Buffer.h"
#include "Serializer.h"
#include "Protocol.h"
#include "Context.h"
#include "ProcessNode.h"
#include "EventStructs.h"

struct ProcessContext {

    // Process identification
    HANDLE processId;
    LARGE_INTEGER createTime;
    LARGE_INTEGER exitTime;      // Set on exit
    
    BOOLEAN hasExited;
    ULONG exitCode;

    // Process image
    UNICODE_STRING imagePath;
    WCHAR imagePathBuffer[260];

    // Command line
    UNICODE_STRING commandLine;
    WCHAR commandLineBuffer[32767];

    // Parent process information
    HANDLE parentProcessId;
    UNICODE_STRING parentImagePath;
    WCHAR parentImagePathBuffer[260];

    // Creator process information (could differ from parent)
    HANDLE creatorProcessId;
    UNICODE_STRING creatorImagePath;
    WCHAR creatorImagePathBuffer[260];

    // Security context
    PSID userSid;
    ULONG sidLength;
    BOOLEAN isElevated;
};

class ProcessEventSerializer {
public:
    static NTSTATUS SerializeProcessEvent(
        _Inout_ Buffer& buffer,
        _In_ protocol::EVENT_TYPE eventType,
        _In_ PEPROCESS Process,
        _In_ HANDLE ProcessId,
        _In_ PPS_CREATE_NOTIFY_INFO CreateInfo,
        _In_ BOOLEAN IsBlocked = FALSE,
        _In_ BOOLEAN IsPolicyMatch = FALSE)
    {
        UNREFERENCED_PARAMETER(eventType);
        UNREFERENCED_PARAMETER(Process);
        
        if (!buffer.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        LARGE_INTEGER timestamp;
        KeQuerySystemTime(&timestamp);

        EVENT ev = { 0 };
        ev.timestamp = timestamp.QuadPart;
        ev.type = (IsBlocked || IsPolicyMatch) ? EventType_MatchHostPolicy : EventType_HostLog;
        ev.operation = EventOperation_Process;
        ev.blocked = IsBlocked;

        PROCESS_EVENT pe = { 0 };
        pe.operation = (CreateInfo != nullptr) ? 0 /*P_CREATE*/ : 1 /*P_TERMINATE*/;
        pe.process_id = HandleToULong(ProcessId);
        
        if (!buffer.WriteBytes(&ev, sizeof(EVENT))) {
            return STATUS_BUFFER_TOO_SMALL;
        }

        if (CreateInfo) {
            pe.parent_process_id = HandleToULong(CreateInfo->ParentProcessId);

            NTSTATUS status = ProcessCache::GetInstance().AddProcess(
                ProcessId,
                CreateInfo->ParentProcessId,
                CreateInfo->CreatingThreadId.UniqueProcess,
                CreateInfo->ImageFileName
            );
            UNREFERENCED_PARAMETER(status);

            if (CreateInfo->FileOpenNameAvailable && CreateInfo->ImageFileName &&
                CreateInfo->ImageFileName->Buffer != nullptr && CreateInfo->ImageFileName->Length > 0) {
                pe.process_path_offset = buffer.GetCurrentSize();
                pe.process_path_length = CreateInfo->ImageFileName->Length;
                buffer.WriteBytes(CreateInfo->ImageFileName->Buffer, CreateInfo->ImageFileName->Length);
            }

            if (CreateInfo->CommandLine &&
                CreateInfo->CommandLine->Buffer != nullptr && CreateInfo->CommandLine->Length > 0) {
                pe.command_line_offset = buffer.GetCurrentSize();
                pe.command_line_length = CreateInfo->CommandLine->Length;
                buffer.WriteBytes(CreateInfo->CommandLine->Buffer, CreateInfo->CommandLine->Length);
            }

            if (ProcessCache::GetInstance().IsProcessCached(CreateInfo->ParentProcessId)) {
                ProcessEntry* p_parentProcessCtx = nullptr;
                NTSTATUS parentStatus = ProcessCache::GetInstance().GetProcessContext(
                    CreateInfo->ParentProcessId,
                    &p_parentProcessCtx
                );
                if (NT_SUCCESS(parentStatus) && p_parentProcessCtx != nullptr) {
                    if (p_parentProcessCtx->imagePath.Buffer != nullptr &&
                        p_parentProcessCtx->imagePath.Length > 0) {
                        pe.parent_process_path_offset = buffer.GetCurrentSize();
                        pe.parent_process_path_length = p_parentProcessCtx->imagePath.Length;
                        buffer.WriteBytes(p_parentProcessCtx->imagePath.Buffer, p_parentProcessCtx->imagePath.Length);
                    }
                    ProcessCache::GetInstance().ReleaseProcessContext(p_parentProcessCtx);
                }
            }
        } else {
            ProcessEntry* p_ctx = nullptr;
            ProcessCache::GetInstance().GetProcessContext(ProcessId, &p_ctx);
            if (p_ctx != nullptr) {
                pe.parent_process_id = HandleToULong(p_ctx->parentProcessId);
                if (p_ctx->imagePath.Buffer != nullptr && p_ctx->imagePath.Length > 0) {
                    pe.process_path_offset = buffer.GetCurrentSize();
                    pe.process_path_length = p_ctx->imagePath.Length;
                    buffer.WriteBytes(p_ctx->imagePath.Buffer, p_ctx->imagePath.Length);
                }
                ProcessCache::GetInstance().ReleaseProcessContext(p_ctx);
                ProcessCache::GetInstance().RemoveProcess(ProcessId);
            }
        }

        ev.data.Process = pe;

        // Guard: only write back the header if the buffer is still valid
        if (buffer.GetBuffer() != nullptr && !buffer.HasOverflow()) {
            RtlCopyMemory(buffer.GetBuffer(), &ev, sizeof(EVENT));
        }

        if (buffer.HasOverflow()) {
            return STATUS_BUFFER_TOO_SMALL;
        }

        return STATUS_SUCCESS;
    }
private:
    // Get process information helpers
    NTSTATUS GetProcessImagePath(
        _In_ HANDLE processId,
        _Out_ PUNICODE_STRING imagePath);

};
