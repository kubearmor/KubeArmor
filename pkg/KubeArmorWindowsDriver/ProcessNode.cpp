// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

#include "ProcessNode.h"

// Plain global — initialized before DriverEntry by the WDK CRT startup code.
// Using a global (not a function-local static) avoids the CRT thread-guard
// (_Init_thread_header) that MSVC emits for magic-statics, which is a
// user-mode-only mechanism and will crash in the kernel.
static ProcessCache g_ProcessCache;

ProcessCache& ProcessCache::GetInstance() {
    return g_ProcessCache;
}

NTSTATUS ProcessCache::Initialize() {
	for (ULONG i = 0; i < HASH_TABLE_SIZE; i++) {
		InitializeListHead(&hashTable_[i]);
	}
	tableLock_.Init();
	return STATUS_SUCCESS;
}

void ProcessCache::Cleanup() {
	Locker<PushLock> locker(tableLock_);

	for (ULONG i = 0; i < HASH_TABLE_SIZE; i++) {
		while (!IsListEmpty(&hashTable_[i])) {
			PLIST_ENTRY entry = RemoveHeadList(&hashTable_[i]);

			ProcessEntry* ctx = CONTAINING_RECORD(entry,ProcessEntry, ListEntry);

			FreeProcessContext(ctx);
		}
	}

	tableLock_.Cleanup();
}

NTSTATUS ProcessCache::AddProcess(
	_In_ HANDLE processID,
	_In_ HANDLE parentProcessID,
	_In_ HANDLE creatorProcessID,
	_In_opt_ PCUNICODE_STRING imagePath) {

	ProcessEntry* ctx = AllocateProcessContext();

	if (!ctx) {
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	ctx->processId = processID;
	ctx->parentProcessId = parentProcessID;
	ctx->creatorProcessId = creatorProcessID;
	ctx->referenceCount = 1;
	ctx->hasExited = FALSE;

	KeQuerySystemTime(&ctx->createTime);

	if (imagePath && imagePath->Length > 0) {
		RtlCopyUnicodeString(&ctx->imagePath, imagePath);
	}

	ULONG hash = ComputeHash(processID);

	{
		Locker<PushLock> locker(tableLock_);

		ProcessEntry* exist = FindProcessContextLocked(processID);

		if (exist) {
			FreeProcessContext(ctx);
			return STATUS_OBJECT_NAME_COLLISION;
		}

		InsertHeadList(&hashTable_[hash], &ctx->ListEntry);

		InterlockedIncrement64(&totalProcesses_);
		InterlockedIncrement64(&activeProcesses_);
	}

	return STATUS_SUCCESS;
}

NTSTATUS ProcessCache::RemoveProcess(_In_ HANDLE processID) {
	ProcessEntry* ctx = nullptr;
	bool shouldFree = false;

	{
		Locker<PushLock> locker(tableLock_);

		ctx = FindProcessContextLocked(processID);

		if (!ctx) {
			return STATUS_NOT_FOUND;
		}

		ctx->hasExited = TRUE;
		KeQuerySystemTime(&ctx->exitTime);

		RemoveEntryList(&ctx->ListEntry);

		InterlockedDecrement64(&activeProcesses_);

		// Drop the initial reference that AddProcess placed on the entry.
		// If another thread already acquired a reference via GetProcessContext
		// (incrementing referenceCount before we took the exclusive lock), the
		// count will not reach zero here and that thread becomes responsible for
		// freeing the entry when it calls ReleaseProcessContext.
		// This prevents the use-after-free where we used to release the lock
		// and then call FreeProcessContext, leaving a window for a concurrent
		// reader to dereference the entry after it had been freed.
		shouldFree = (InterlockedDecrement(&ctx->referenceCount) == 0);
	}

	if (shouldFree) {
		FreeProcessContext(ctx);
	}

	return STATUS_SUCCESS;
}

NTSTATUS ProcessCache::GetProcessContext(_In_ HANDLE processID, _Out_ ProcessEntry** outContext) {
	if (!outContext) {
		return STATUS_INVALID_PARAMETER;
	}

	*outContext = nullptr;

	SharedLocker<PushLock> lock(tableLock_);

	ProcessEntry* ctx = FindProcessContextLocked(processID);

	if (ctx) {
		InterlockedIncrement(&ctx->referenceCount);
		InterlockedIncrement64(&cacheHits_);
		*outContext = ctx;
	}
	else {
		InterlockedIncrement64(&cacheMisses_);
	}

	return ctx ? STATUS_SUCCESS : STATUS_NOT_FOUND;

}

void ProcessCache::GetStatistics(
	_Out_ PLONGLONG total,
	_Out_ PLONGLONG active,
	_Out_ PLONGLONG hits,
	_Out_ PLONGLONG misses) {

	if (total) *total = totalProcesses_;
	if (active) *active = activeProcesses_;
	if (hits) *hits = cacheHits_;
	if (misses) *misses = cacheMisses_;
}

BOOLEAN ProcessCache::IsProcessCached(_In_ HANDLE processID) {
	SharedLocker<PushLock> lock(tableLock_);
	ProcessEntry* ctx = FindProcessContextLocked(processID);
	return ctx ? TRUE : FALSE;
}