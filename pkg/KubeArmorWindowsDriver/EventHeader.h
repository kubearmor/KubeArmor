// EventHeader.h
#pragma once

#include "Serializer.h"
#include "Protocol.h"

class EventHeader {
public:
    static BOOLEAN WriteCommonFields(
        Serializer& serializer,
        protocol::EVENT_TYPE eventType,
        HANDLE ProcessId,
        HANDLE ThreadId)
    {
        UNREFERENCED_PARAMETER(ProcessId);
        UNREFERENCED_PARAMETER(ThreadId);

        LARGE_INTEGER timestamp;
        KeQuerySystemTime(&timestamp);

        // Write event type
        if (!serializer.WriteFieldULong(FIELD_EVENT_TYPE, static_cast<ULONG>(eventType))) {
            return FALSE;
        }

        // Write timestamp
        if (!serializer.WriteFieldULongLong(FIELD_TIMESTAMP, timestamp.QuadPart)) {
            return FALSE;
        }

        return TRUE;
    }
};