#pragma once

#include <wdf.h>
#include "KarmorLogs.h"

// ETW registration handle
REGHANDLE g_EtwRegHandle = 0;

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