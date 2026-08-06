#pragma once
#include <fltKernel.h>
#include <ntstrsafe.h>

class FastMutex {
public:
	void Init();

	void Lock();
	void Unlock();

private:
	FAST_MUTEX _mutex;
};

template<typename TLock>
struct Locker {
	explicit Locker(TLock& lock) : _lock(lock) {
		lock.Lock();
	}
	~Locker() {
		_lock.Unlock();
	}
private:
	TLock& _lock;
};

class PushLock {
public:
	void Init();
	void Cleanup();
	void Lock();
	void Unlock();
	void LockShared();
	void UnlockShared();
private:
	EX_PUSH_LOCK _lock;
};

template<typename TLock>
struct SharedLocker {
	explicit SharedLocker(TLock& lock) : _lock(lock) {
		lock.LockShared();
	}
	~SharedLocker() {
		_lock.UnlockShared();
	}
private:
	TLock& _lock;
};