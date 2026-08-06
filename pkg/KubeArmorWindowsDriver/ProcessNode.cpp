#include "ProcessNode.h"

NTSTATUS ProcessCache::Initialize() {
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
	_In_ HANDLE createrProcessID,
	_In_opt_ PCUNICODE_STRING imagePath) {

	ProcessEntry* ctx = AllocateProcessContext();

	if (!ctx) {
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	ctx->processId = processID;
	ctx->parentProcessId = parentProcessID;
	ctx->createrProcessId = createrProcessID;
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

	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
		"[EDR] Cached process: PID=%lu, Parent=%lu, Creator=%lu, Image=%wZ\n",
		HandleToULong(processID),
		HandleToULong(parentProcessID),
		HandleToULong(createrProcessID),
		&ctx->imagePath);

	return STATUS_SUCCESS;
}

NTSTATUS ProcessCache::RemoveProcess(_In_ HANDLE processID) {
	ProcessEntry* ctx = nullptr;

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
	}

	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
		"[EDR] Removed process: PID=%lu, Image=%wZ\n",
		HandleToULong(processID),
		&ctx->imagePath);

	FreeProcessContext(ctx);

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