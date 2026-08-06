#include "FastMutex.h"

void FastMutex::Init() {
	ExInitializeFastMutex(&_mutex);
}

void FastMutex::Lock() {
	ExAcquireFastMutex(&_mutex);
}

void FastMutex::Unlock() {
	ExReleaseFastMutex(&_mutex);
}

void PushLock::Init() {
    FltInitializePushLock(&_lock);
}

void PushLock::Cleanup() {
    FltDeletePushLock(&_lock);
}

void PushLock::Lock() {
    FltAcquirePushLockExclusive(&_lock);
}

void PushLock::Unlock() {
    FltReleasePushLock(&_lock);
}

void PushLock::LockShared() {
    FltAcquirePushLockShared(&_lock);
}

void PushLock::UnlockShared() {
    FltReleasePushLock(&_lock);
}
