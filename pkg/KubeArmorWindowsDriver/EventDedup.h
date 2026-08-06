// EventDedup.h
// Kernel-mode event deduplication cache for KubeArmor minifilter.
//
// Purpose: Collapse repeated kernel callbacks for the same logical event
// (same PID + file path hash + event type) within a configurable time window.
// Without this, a single user action like creating a blocked file can produce
// dozens of IRP_MJ_CREATE callbacks, each becoming a separate alert and
// exhausting the userspace throttle budget.
//
// Design:
//   - Fixed-size open-addressing hash table (DEDUP_BUCKET_COUNT buckets).
//   - Key   = (PID, FilePathHash, EventType) packed into 64 bits.
//   - Value = QPC timestamp of last time this key was seen.
//   - Protected by a single KSPIN_LOCK (safe at DISPATCH_LEVEL).
//   - Entries are never explicitly evicted; they expire naturally when the
//     time window passes.  Collisions evict the existing entry (LRU-lite).
//
#pragma once

extern "C" {
#include <fltKernel.h>
}

// Number of dedup buckets. Must be a power of two.
#ifndef DEDUP_BUCKET_COUNT
#define DEDUP_BUCKET_COUNT  256UL
#endif
static_assert((DEDUP_BUCKET_COUNT & (DEDUP_BUCKET_COUNT - 1)) == 0,
    "DEDUP_BUCKET_COUNT must be a power of two");

// Suppress duplicate events seen within this many QPC milliseconds.
#ifndef DEDUP_WINDOW_MS
#define DEDUP_WINDOW_MS  500ULL
#endif

#define DEDUP_INVALID_KEY  0ULL

// ---------------------------------------------------------------------------
// DedupEntry
// ---------------------------------------------------------------------------

#pragma pack(push, 1)
struct DedupEntry
{
    UINT64 key;          // packed (PID:32 | EventType:16 | PathHash:16)
    UINT64 lastSeenTick; // QPC ticks when this key was last admitted
};
#pragma pack(pop)

// ---------------------------------------------------------------------------
// EventDedupCache
// ---------------------------------------------------------------------------

class EventDedupCache final
{
public:
    EventDedupCache()  = default;
    ~EventDedupCache() = default;

    EventDedupCache(const EventDedupCache&)            = delete;
    EventDedupCache& operator=(const EventDedupCache&) = delete;

    void Initialize()
    {
        KeInitializeSpinLock(&m_lock);
        RtlZeroMemory(m_buckets, sizeof(m_buckets));
    }

    // Returns TRUE if this event is a duplicate and should be suppressed.
    // qpcFreqMs  - ticks-per-millisecond (from KeQueryPerformanceCounter).
    // pid        - requestor process ID.
    // pathHash   - 16-bit hash of the file/resource path.
    // eventType  - protocol::EVENT_TYPE cast to UINT16.
    _IRQL_requires_max_(DISPATCH_LEVEL)
    BOOLEAN IsDuplicate(
        UINT64 qpcFreqMs,
        ULONG  pid,
        UINT32 pathHash,
        UINT16 eventType)
    {
        if (qpcFreqMs == 0) return FALSE; // safety: not initialized

        // Build a 64-bit key.
        // Layout: [ pid(32) | eventType(16) | pathHash(16) ]
        const UINT64 key =
            (static_cast<UINT64>(pid)       << 32) |
            (static_cast<UINT64>(eventType) << 16) |
            (static_cast<UINT64>(pathHash & 0xFFFF));

        if (key == DEDUP_INVALID_KEY) return FALSE;

        const UINT64 nowTick = static_cast<UINT64>(
            KeQueryPerformanceCounter(nullptr).QuadPart);

        const UINT32 slot = BucketFor(key);

        KIRQL irql;
        KeAcquireSpinLock(&m_lock, &irql);

        DedupEntry& entry = m_buckets[slot];

        if (entry.key == key)
        {
            // Same key — check if still within the window.
            const UINT64 elapsedMs = (nowTick - entry.lastSeenTick) / qpcFreqMs;
            if (elapsedMs < DEDUP_WINDOW_MS)
            {
                KeReleaseSpinLock(&m_lock, irql);
                return TRUE; // duplicate — suppress
            }
        }

        // Admit: update the bucket (evicts any previous occupant).
        entry.key          = key;
        entry.lastSeenTick = nowTick;

        KeReleaseSpinLock(&m_lock, irql);
        return FALSE; // new or expired — allow through
    }

private:
    static UINT32 BucketFor(UINT64 key)
    {
        // FNV-1a mix of the key to spread bits.
        UINT64 h = key ^ (key >> 33);
        h *= 0xff51afd7ed558ccdULL;
        h ^= (h >> 33);
        return static_cast<UINT32>(h) & (DEDUP_BUCKET_COUNT - 1u);
    }

    KSPIN_LOCK  m_lock{};
    DedupEntry  m_buckets[DEDUP_BUCKET_COUNT]{};
};
