#pragma once

#include <wdf.h>
#include "KarmorLogs.h"

// ETW registration handle (defined in Karmor.cpp)
extern REGHANDLE g_EtwRegHandle;

// Function declarations
NTSTATUS InitializeETW();
VOID CleanupETW();

// Process event data structure
typedef struct _PROCESS_EVENT_DATA {
    ULONG ProcessId;
    ULONG ParentProcessId;
    UNICODE_STRING ImagePath;
    UNICODE_STRING CommandLine;
    UNICODE_STRING UserSid;
    UNICODE_STRING RuleName;
} PROCESS_EVENT_DATA, * PPROCESS_EVENT_DATA;