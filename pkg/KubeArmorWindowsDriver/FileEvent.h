// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor


#pragma once

#include "Buffer.h"
#include "Serializer.h"
#include "Protocol.h"
#include "Context.h"
#include "ProcessNode.h"
#include "EventStructs.h"

class FileEventSerializer {
public:
    // Serialize file create event
    static NTSTATUS SerializeFileEvent(
        _Inout_ Buffer& buffer,
        _In_ protocol::EVENT_TYPE eventType,
        _In_ StreamHandleContext* ptrStrHandleCtx,
        _In_ InstanceContext* pInstCtx)
    {
        UNREFERENCED_PARAMETER(pInstCtx);

        if (!buffer.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        LARGE_INTEGER timestamp;
        KeQuerySystemTime(&timestamp);

        EVENT ev = { 0 };
        ev.timestamp = timestamp.QuadPart;
        ev.type = EventType_HostLog;
        ev.operation = EventOperation_File;
        ev.blocked = FALSE;

        FILE_EVENT fe = { 0 };
        switch (eventType) {
            case protocol::EVENT_TYPE_FILE_CREATE: fe.Operation = 0; break;
            case protocol::EVENT_TYPE_FILE_READ: fe.Operation = 1; break;
            case protocol::EVENT_TYPE_FILE_WRITE: fe.Operation = 2; break;
            case protocol::EVENT_TYPE_FILE_DELETE: fe.Operation = 3; break;
            case protocol::EVENT_TYPE_FILE_RENAME: fe.Operation = 4; break;
            case protocol::EVENT_TYPE_FILE_SET_INFO: fe.Operation = 5; break;
            case protocol::EVENT_TYPE_FILE_CLOSE: fe.Operation = 7; break;
            default: fe.Operation = 0;
        }
        fe.ProcessId = HandleToULong(ptrStrHandleCtx->processId);

        ProcessEntry* pContext = nullptr;
        NTSTATUS status = STATUS_UNSUCCESSFUL;
        
        if (KeGetCurrentIrql() == PASSIVE_LEVEL) {
            status = ProcessCache::GetInstance().GetOrPopulateProcessContext(ptrStrHandleCtx->processId, &pContext);
        } else {
            status = ProcessCache::GetInstance().GetProcessContext(ptrStrHandleCtx->processId, &pContext);
        }

        if (NT_SUCCESS(status) && pContext != nullptr) {
            fe.ParentProcessId = HandleToULong(pContext->parentProcessId);
        } else {
            fe.ParentProcessId = 0;
        }

        if (!buffer.WriteBytes(&ev, sizeof(EVENT))) {
            if (pContext) ProcessCache::GetInstance().ReleaseProcessContext(pContext);
            return STATUS_BUFFER_TOO_SMALL;
        }

        if (ptrStrHandleCtx->processPath.Length > 0 && ptrStrHandleCtx->processPath.Buffer != nullptr) {
            fe.ProcessPathOffset = buffer.GetCurrentSize();
            fe.ProcessPathLength = ptrStrHandleCtx->processPath.Length;
            buffer.WriteBytes(ptrStrHandleCtx->processPath.Buffer, ptrStrHandleCtx->processPath.Length);
        }

        if (ptrStrHandleCtx->filePath.Length > 0 && ptrStrHandleCtx->filePath.Buffer != nullptr) {
            fe.FilePathOffset = buffer.GetCurrentSize();
            fe.FilePathLength = ptrStrHandleCtx->filePath.Length;
            buffer.WriteBytes(ptrStrHandleCtx->filePath.Buffer, ptrStrHandleCtx->filePath.Length);
        }

        if (NT_SUCCESS(status) && pContext != nullptr) {
            ProcessEntry* parentContext = nullptr;
            NTSTATUS parentStatus = STATUS_UNSUCCESSFUL;
            
            if (KeGetCurrentIrql() == PASSIVE_LEVEL) {
                parentStatus = ProcessCache::GetInstance().GetOrPopulateProcessContext(pContext->parentProcessId, &parentContext);
            } else {
                parentStatus = ProcessCache::GetInstance().GetProcessContext(pContext->parentProcessId, &parentContext);
            }
            
            if (NT_SUCCESS(parentStatus) && parentContext != nullptr) {
                if (parentContext->imagePath.Length > 0 && parentContext->imagePath.Buffer != nullptr) {
                    fe.ParentProcessPathOffset = buffer.GetCurrentSize();
                    fe.ParentProcessPathLength = parentContext->imagePath.Length;
                    buffer.WriteBytes(parentContext->imagePath.Buffer, parentContext->imagePath.Length);
                } else {
                    fe.ParentProcessPathOffset = 0;
                    fe.ParentProcessPathLength = 0;
                }
                ProcessCache::GetInstance().ReleaseProcessContext(parentContext);
            } else {
                fe.ParentProcessPathOffset = 0;
                fe.ParentProcessPathLength = 0;
            }
            ProcessCache::GetInstance().ReleaseProcessContext(pContext);
        } else {
            fe.ParentProcessPathOffset = 0;
            fe.ParentProcessPathLength = 0;
        }

        ev.data.File = fe;

        // Guard: only write back the header if the buffer is still valid
        if (buffer.GetBuffer() != nullptr && !buffer.HasOverflow()) {
            RtlCopyMemory(buffer.GetBuffer(), &ev, sizeof(EVENT));
        }

        if (buffer.HasOverflow()) {
            return STATUS_BUFFER_TOO_SMALL;
        }

        return STATUS_SUCCESS;
    }
};
