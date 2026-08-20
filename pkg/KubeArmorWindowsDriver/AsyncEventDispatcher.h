// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor


#pragma once

extern "C" {
    #include <fltKernel.h>
}

#include "Buffer.h"
#include "FileEvent.h"
#include "Protocol.h"
#include "Context.h"
#include "EventDedup.h"

#ifndef ASYNC_RING_BYTES
#define ASYNC_RING_BYTES  (256UL * 1024UL)
#endif
static_assert((ASYNC_RING_BYTES& (ASYNC_RING_BYTES - 1)) == 0,
    "ASYNC_RING_BYTES must be a power of two");

#ifndef ASYNC_SEND_BUFFER_BYTES
#define ASYNC_SEND_BUFFER_BYTES  (64UL * 1024UL)
#endif
static_assert(ASYNC_SEND_BUFFER_BYTES <= ASYNC_RING_BYTES,
    "Send buffer cannot exceed the ring");

#ifndef ASYNC_IDLE_TIMEOUT_MS
#define ASYNC_IDLE_TIMEOUT_MS  50UL
#endif

// FltSendMessage per-call timeout.
#ifndef ASYNC_SEND_TIMEOUT_100NS
#define ASYNC_SEND_TIMEOUT_100NS  (-10LL * 1000LL * 1000LL)  // 1 second
#endif


#ifndef ASYNC_CLAIM_TIMEOUT_MS
#define ASYNC_CLAIM_TIMEOUT_MS  500UL
#endif

#ifndef ASYNC_MAX_SEND_TIMEOUTS
#define ASYNC_MAX_SEND_TIMEOUTS  3UL
#endif

#define ASYNC_RING_TAG   'rAsy'
#define ASYNC_SEND_TAG   'sAsy'
#define ASYNC_SLOT_ALIGN  8UL

// ---------------------------------------------------------------------------
// Slot state machine
// ---------------------------------------------------------------------------

enum class SlotState : LONG { Free = 0, Claimed = 1, Committed = 2 };
constexpr UINT16 PAD_FLAG = 0xFFFFu;

#pragma pack(push, 1)
struct SlotHeader
{
    volatile LONG   state;        //  0
    UINT16          flags;        //  4
    UINT16          reserved;     //  6
    volatile UINT32 payloadBytes; //  8
    UINT32          seqNum;       // 12
    UINT32          strideBytes;  // 16 -- total slot size (header + aligned payload)
    // Written by the producer, read by the consumer to detect stuck slots.
    UINT64          claimedTick;  // 20
};                                // 28 bytes -- padded to 32 by ASYNC_SLOT_ALIGN
#pragma pack(pop)
static_assert(sizeof(SlotHeader) == 28, "SlotHeader size changed");
static_assert(FIELD_OFFSET(SlotHeader, state) == 0, "state must be at offset 0");

// ---------------------------------------------------------------------------
// AsyncEventDispatcher
// ---------------------------------------------------------------------------

class AsyncEventDispatcher final
{
public:
    AsyncEventDispatcher() = default;
    ~AsyncEventDispatcher() = default;

    AsyncEventDispatcher(const AsyncEventDispatcher&) = delete;
    AsyncEventDispatcher& operator=(const AsyncEventDispatcher&) = delete;
    AsyncEventDispatcher(AsyncEventDispatcher&&) = delete;
    AsyncEventDispatcher& operator=(AsyncEventDispatcher&&) = delete;

    _IRQL_requires_(PASSIVE_LEVEL)
        _Must_inspect_result_
        NTSTATUS Initialize(_In_ PFLT_FILTER filter);

    _IRQL_requires_(PASSIVE_LEVEL)
        void Uninitialize();

    _IRQL_requires_(PASSIVE_LEVEL)
        void OnClientConnected(_In_ PFLT_PORT clientPort);

    _IRQL_requires_(PASSIVE_LEVEL)
        void OnClientDisconnected();

    _IRQL_requires_max_(DISPATCH_LEVEL)
        _Must_inspect_result_
        NTSTATUS Enqueue(
            _In_ protocol::EVENT_TYPE  eventType,
            _In_ StreamHandleContext* pStrHandleCtx,
            _In_ InstanceContext* pInstCtx);

    // Enqueue a blocked file event directly (no StreamHandleContext needed).
    // Used by PreCreateCallback when blocking access before PostCreate runs.
    _IRQL_requires_max_(DISPATCH_LEVEL)
        _Must_inspect_result_
        NTSTATUS EnqueueBlockedFileEvent(
            _In_ PUNICODE_STRING FilePath,
            _In_ ULONG ProcessId);

    LONG64 EnqueuedEvents()  const { return m_enqueued; }
    LONG64 DroppedEvents()   const { return m_dropped; }
    LONG64 PoisonedSlots()   const { return m_poisoned; }

private:

    static constexpr UINT32 RingMask()
    {
        return static_cast<UINT32>(ASYNC_RING_BYTES) - 1u;
    }
    static constexpr UINT32 AlignUp(UINT32 v)
    {
        return (v + static_cast<UINT32>(ASYNC_SLOT_ALIGN) - 1u)
            & ~(static_cast<UINT32>(ASYNC_SLOT_ALIGN) - 1u);
    }
    static UINT32 Stride(UINT32 payloadBytes)
    {
        return AlignUp(static_cast<UINT32>(sizeof(SlotHeader)) + payloadBytes);
    }
    SlotHeader* SlotAt(UINT32 byteOffset) const
    {
        return reinterpret_cast<SlotHeader*>(
            m_ring + (byteOffset & RingMask()));
    }
    static UINT8* PayloadOf(SlotHeader* h)
    {
        return reinterpret_cast<UINT8*>(h) + sizeof(SlotHeader);
    }

    // Convert QPC ticks to milliseconds.
    UINT64 TicksToMs(UINT64 ticks) const
    {
        // m_qpcFreq is queried once at Initialize() time.
        if (m_qpcFreqMs == 0) return 0;
        return ticks / m_qpcFreqMs;
    }

    _IRQL_requires_max_(DISPATCH_LEVEL)
        NTSTATUS ProduceSlot(
            _In_reads_bytes_(size) const UINT8* bytes,
            _In_ UINT32 size);

    _IRQL_requires_(PASSIVE_LEVEL)
        UINT32 ConsumeOne();

    _IRQL_requires_(PASSIVE_LEVEL)
        NTSTATUS SendOne(_In_ UINT32 bytes);

    static VOID WorkerEntry(_In_ PVOID ctx);
    void WorkerLoop();

    // ---- Members -------------------------------------------------------

    UINT8* m_ring = nullptr;
    volatile LONG   m_writeHead = 0;
    volatile LONG   m_readHead = 0;
    volatile LONG   m_seqCounter = 0;

    UINT8* m_sendBuf = nullptr;
    PFLT_FILTER     m_filter = nullptr;

    PFLT_PORT       m_clientPort = nullptr;
    KSPIN_LOCK      m_portLock{};

    PETHREAD        m_thread = nullptr;
    KEVENT          m_dataReady{};   // SynchronizationEvent (auto-reset)
    KEVENT          m_stopEvent{};   // NotificationEvent

    volatile LONG   m_active = 0;
    bool            m_initialized = false;


    UINT64          m_qpcFreqMs = 0;

    ULONG           m_sendTimeouts = 0;

    volatile LONG64 m_enqueued = 0;
    volatile LONG64 m_dropped = 0;
    volatile LONG64 m_poisoned = 0;  // slots skipped as stuck
    volatile LONG64 m_deduped = 0;   // events suppressed by dedup cache

    EventDedupCache m_dedupCache;
};

extern AsyncEventDispatcher g_AsyncDispatcher;
