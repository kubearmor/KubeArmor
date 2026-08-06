#pragma once
#include "FastMutex.h"

#ifndef _NTPSAPI_H
#ifndef PROCESS_QUERY_LIMITED_INFORMATION

#define PROCESS_QUERY_LIMITED_INFORMATION 0x1000

#endif
#endif

// ZwQueryInformationProcess is not always declared in the WDK
// headers when compiling C++. Provide an extern "C" prototype.
extern "C" {
    NTSYSAPI NTSTATUS NTAPI ZwQueryInformationProcess(
        _In_      HANDLE           ProcessHandle,
        _In_      PROCESSINFOCLASS ProcessInformationClass,
        _Out_     PVOID            ProcessInformation,
        _In_      ULONG            ProcessInformationLength,
        _Out_opt_ PULONG           ReturnLength
    );
}

//============================================
// ProcessContext - Cached process information
//============================================

struct ProcessEntry {
    LIST_ENTRY ListEntry;
    // Reference counting
    volatile LONG referenceCount;

    // Process identification
    HANDLE processId;
    HANDLE parentProcessId;
    HANDLE createrProcessId;
    LARGE_INTEGER createTime;
    LARGE_INTEGER exitTime;      // Set on exit
    BOOLEAN hasExited;

    // Process image
    UNICODE_STRING imagePath;
    WCHAR imagePathBuffer[260];

};

//==========================================
// ProcessCache - Hash table for fast lookup
//==========================================

class ProcessCache {
private:
    static const ULONG HASH_TABLE_SIZE = 4096;  // Power of 2 for fast modulo

    // Hash table (array of list heads)
    LIST_ENTRY hashTable_[HASH_TABLE_SIZE];

    // Lock for thread safety
    PushLock tableLock_;

    // Statistics
    volatile LONGLONG totalProcesses_;
    volatile LONGLONG activeProcesses_;
    volatile LONGLONG cacheHits_;
    volatile LONGLONG cacheMisses_;

    ProcessCache()
        : totalProcesses_(0), activeProcesses_(0),
        cacheHits_(0), cacheMisses_(0) {

        // Initialize hash table
        for (ULONG i = 0; i < HASH_TABLE_SIZE; i++) {
            InitializeListHead(&hashTable_[i]);
        }

        // Initialize lock
        tableLock_.Init();
    }

public:
    static ProcessCache& GetInstance() {
        static ProcessCache instance;
        return instance;
    }

    ProcessCache(const ProcessCache&) = delete;
    ProcessCache& operator=(const ProcessCache&) = delete;
    ProcessCache(ProcessCache&& Other) = delete;
    ProcessCache& operator=(ProcessCache&& Other) = delete;

    NTSTATUS Initialize();
    void Cleanup();

    // Add process to cache
    NTSTATUS AddProcess(
        _In_ HANDLE processId,
        _In_ HANDLE parentProcessId,
        _In_ HANDLE creatorProcessId,
        _In_opt_ PCUNICODE_STRING imagePath);

    // Remove process from cache
    NTSTATUS RemoveProcess(_In_ HANDLE processId);

    // Get process context (increments reference count)
    NTSTATUS GetProcessContext(
        _In_ HANDLE processId,
        _Out_ ProcessEntry** context);

    // Lookup without adding reference (for quick checks)
    BOOLEAN IsProcessCached(_In_ HANDLE processId);

    // Release a reference obtained via GetProcessContext
    void ReleaseProcessContext(_In_ ProcessEntry* context) {
        if (!context) return;
        InterlockedDecrement(&context->referenceCount);
    }

    // Get process context, populating the cache on miss by querying the kernel.
    // Must be called at PASSIVE_LEVEL since it opens a process handle.
    _IRQL_requires_(PASSIVE_LEVEL)
    NTSTATUS GetOrPopulateProcessContext(
        _In_ HANDLE processId,
        _Out_ ProcessEntry** outContext)
    {
        // Fast path: already cached
        NTSTATUS status = GetProcessContext(processId, outContext);
        if (NT_SUCCESS(status))
            return status;

        // Slow path: query the kernel and populate

        PEPROCESS process = nullptr;
        status = PsLookupProcessByProcessId(processId, &process);
        if (!NT_SUCCESS(status))
            return status;

        // Get PPID via PROCESS_BASIC_INFORMATION
        HANDLE hProcess = nullptr;
        HANDLE parentPid = nullptr;

        status = ObOpenObjectByPointer(process, OBJ_KERNEL_HANDLE, nullptr, PROCESS_QUERY_LIMITED_INFORMATION, *PsProcessType, KernelMode, &hProcess);

        if (NT_SUCCESS(status))
        {
            PROCESS_BASIC_INFORMATION pbi = {};
            ULONG retLen = 0;
            status = ZwQueryInformationProcess(
                hProcess, ProcessBasicInformation,
                &pbi, sizeof(pbi), &retLen);
            if (NT_SUCCESS(status))
            {
                parentPid = reinterpret_cast<HANDLE>(
                    pbi.InheritedFromUniqueProcessId);
            }
            ZwClose(hProcess);
        }

        // Get image path
        PUNICODE_STRING imagePath = nullptr;
        SeLocateProcessImageName(process, &imagePath);

        // Insert into cache (creator == parent for retroactively discovered processes)
#pragma warning(suppress: 6387)
        NTSTATUS addStatus = AddProcess(processId, parentPid, parentPid, imagePath);

        if (imagePath)
            ExFreePool(imagePath);

        ObDereferenceObject(process);

        // If we just added it (or it was already added by a racing thread), fetch it
        if (NT_SUCCESS(addStatus) || addStatus == STATUS_OBJECT_NAME_COLLISION)
            return GetProcessContext(processId, outContext);

        return addStatus;
    }

    // Get statistics
    void GetStatistics(
        _Out_ PLONGLONG total,
        _Out_ PLONGLONG active,
        _Out_ PLONGLONG hits,
        _Out_ PLONGLONG misses);

private:
    // Hash function
    ULONG ComputeHash(_In_ HANDLE processId) const {
        return (HandleToULong(processId) * 2654435761UL) % HASH_TABLE_SIZE;
    }

    // Allocate process context
    ProcessEntry* AllocateProcessContext() {
        ProcessEntry* ctx = static_cast<ProcessEntry*>(
            ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(ProcessEntry), 'corP')
            );

        if (!ctx) {
            return nullptr;
        }

        RtlZeroMemory(ctx, sizeof(ProcessEntry));

        RtlInitEmptyUnicodeString(&ctx->imagePath,
            ctx->imagePathBuffer,
            sizeof(ctx->imagePathBuffer));

        return ctx;
    }

    // Free process context
    void FreeProcessContext(_In_ ProcessEntry* context) {
        if (!context) return;

        ExFreePoolWithTag(context, 'corP');
    }

    // Find in hash table (lock must be held)
    ProcessEntry* FindProcessContextLocked(_In_ HANDLE processId) {
        ULONG hash = ComputeHash(processId);

        PLIST_ENTRY head = &hashTable_[hash];
        PLIST_ENTRY current = head->Flink;

        while (current != head) {
            ProcessEntry* ctx = CONTAINING_RECORD(
                current,
                ProcessEntry,
                ListEntry
            );

            if (ctx->processId == processId) {
                return ctx;
            }

            current = current->Flink;
        }

        return nullptr;
    }
};
