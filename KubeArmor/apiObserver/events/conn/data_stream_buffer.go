// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package conn

import (
	kg "github.com/kubearmor/KubeArmor/KubeArmor/log"
	"sync"
	"sync/atomic"
	"time"
)

// lastOverflowLog tracks the last time an overflow warning was emitted
// to avoid flooding logs during high-throughput TLS capture.
var lastOverflowLog atomic.Int64

// defaultPreAllocBytes is the initial backing array size for pooled buffers.
// Set to 16KB — large enough to hold most HTTP headers + small API response
// bodies without reallocation, yet small enough that idle pool entries don't
// waste excessive memory.
//
// The pool naturally converges to the right size distribution: when a buffer
// grows to handle a 100KB response, it returns to the pool with that capacity
// intact, and the next connection that draws it starts with 100KB for free.
// The pre-alloc only affects the cold-start path (sync.Pool.New).
const defaultPreAllocBytes = 16 * 1024 // 16KB

// maxPoolableCapacity is the cap-gate for pool return. Buffers that grew
// beyond this threshold (e.g. from a single oversized HTTP response that
// hit the 192KB per-direction cap) are not returned to the pool — they
// are left for the GC to reclaim. This prevents a few outlier connections
// from permanently inflating the pool's memory footprint.
const maxPoolableCapacity = 256 * 1024 // 256KB

// dsbPool is the sync.Pool for DataStreamBuffer structs. The pool does NOT
// pre-allocate backing arrays in New — that would waste memory for short-lived
// connections. Instead, the pool's value comes from retaining the backing array
// from previous connections: when a buffer that grew to 100KB is released, the
// next connection that draws it starts with 100KB capacity for free.
var dsbPool = sync.Pool{
	New: func() any {
		return &DataStreamBuffer{}
	},
}

// DataStreamBuffer accumulates raw TCP payload chunks from BPF events and
// exposes them as a single contiguous byte window for the protocol parser.
//
// It tracks how many bytes the parser has consumed so that on overflow only
// already-processed bytes are discarded first. If the buffer is still over
// capacity after GC, it keeps the HEAD (which contains HTTP headers) and
// discards the tail.
//
// The skip counter allows the tracker to drain large body bytes off the wire
// without storing them in the buffer, preserving alignment for the next message.
type DataStreamBuffer struct {
	buf      []byte
	consumed int // index of first unconsumed byte
	capacity int
	skip     int // bytes to silently discard before buffering
	overflowCount int // number of times the buffer overflowed
}

// AcquireDataStreamBuffer returns a DataStreamBuffer from the pool,
// configured with the given per-direction capacity. If the buffer was
// previously used (warm pool hit), its backing array retains capacity
// from prior use — hot connections avoid reallocation entirely.
// Cold pool entries (sync.Pool.New) start with a nil backing array
// and grow on first Write(), identical to the non-pooled path.
func AcquireDataStreamBuffer(capacity int) *DataStreamBuffer {
	dsb := dsbPool.Get().(*DataStreamBuffer)
	dsb.capacity = capacity
	dsb.consumed = 0
	dsb.skip = 0
	dsb.overflowCount = 0
	if dsb.buf != nil {
		dsb.buf = dsb.buf[:0] // warm hit: keep backing array, reset length
	}
	return dsb
}

// ReleaseDataStreamBuffer returns a buffer to the pool for reuse.
// Buffers whose backing array grew beyond maxPoolableCapacity are not
// pooled — they are left for the GC to prevent outlier memory retention.
func ReleaseDataStreamBuffer(dsb *DataStreamBuffer) {
	if dsb == nil {
		return
	}
	if cap(dsb.buf) > maxPoolableCapacity {
		// Oversized buffer — let GC handle it. Don't pollute the pool
		// with memory that most connections won't need.
		return
	}
	dsb.buf = dsb.buf[:0]
	dsb.consumed = 0
	dsb.skip = 0
	dsb.overflowCount = 0
	dsbPool.Put(dsb)
}

// NewDataStreamBuffer allocates a fresh (non-pooled) buffer. Retained for
// backward compatibility and tests; production code should prefer
// AcquireDataStreamBuffer.
func NewDataStreamBuffer(capacity int) *DataStreamBuffer {
	return &DataStreamBuffer{
		capacity: capacity,
	}
}

// Write appends data to the buffer, with three behaviours in order:
//
//  1. If skip > 0, consume the skip counter first (drain leftover body bytes
//     from the wire without storing them). If the entire chunk is covered by
//     skip, return immediately without touching buf.
//
//  2. If the buffer is within capacity after appending, return normally.
//
//  3. If over capacity, first GC already-consumed bytes. If still over
//     capacity (a single un-parsed message is larger than the buffer),
//     keep the HEAD of the buffer so HTTP headers are never discarded,
//     and log a warning.
func (b *DataStreamBuffer) Write(data []byte) {
	// Phase 1: drain skip counter
	if b.skip > 0 {
		if len(data) <= b.skip {
			b.skip -= len(data)
			return // entire chunk is skipped
		}
		data = data[b.skip:] // partial skip — process the remainder
		b.skip = 0
	}

	b.buf = append(b.buf, data...)
	if len(b.buf) <= b.capacity {
		return
	}

	// Phase 2: GC consumed bytes
	if b.consumed > 0 {
		b.buf = b.buf[:copy(b.buf, b.buf[b.consumed:])]
		b.consumed = 0
	}

	// Phase 3: hard cap — keep HEAD so HTTP headers survive
	if len(b.buf) > b.capacity {
		b.overflowCount++
		now := time.Now().UnixMilli()
		last := lastOverflowLog.Load()
		if now-last > 10_000 { // log at most once per 10s
			if lastOverflowLog.CompareAndSwap(last, now) {
				kg.Warnf("DataStreamBuffer: overflow, truncating to preserve headers bufLen=%d capacity=%d",
					len(b.buf), b.capacity)
			}
		}
		b.buf = b.buf[:b.capacity] // keep head, discard tail
	}
}

// Bytes returns the unconsumed portion of the buffer for the parser.
func (b *DataStreamBuffer) Bytes() []byte {
	if b.consumed >= len(b.buf) {
		return nil
	}
	return b.buf[b.consumed:]
}

// Advance marks n bytes as consumed by the parser.
// Memory is reclaimed lazily on the next Write() call,
// or immediately if the buffer is fully consumed.
func (b *DataStreamBuffer) Advance(n int) {
	b.consumed += n
	if b.consumed >= len(b.buf) {
		b.buf = b.buf[:0]
		b.consumed = 0
	}
}

// HasRepeatedOverflow returns true if the buffer has overflowed multiple times.
func (b *DataStreamBuffer) HasRepeatedOverflow() bool {
	return b.overflowCount > 3
}

// SkipNextBytes instructs the buffer to silently discard the next n bytes
// written to it. Called by the tracker after body truncation to drain
// the remaining body bytes from the wire without storing them.
//
// Multiple calls accumulate: SkipNextBytes(a) then SkipNextBytes(b) → skip=a+b.
func (b *DataStreamBuffer) SkipNextBytes(n int) {
	b.skip += n
}

// SetRemaining replaces the unconsumed portion with the given bytes.
// Used by HTTP/2 and gRPC parsers that return a `remaining` slice.
func (b *DataStreamBuffer) SetRemaining(remaining []byte) {
	// Reuse existing backing array if it has sufficient capacity.
	if cap(b.buf) >= len(remaining) {
		b.buf = b.buf[:len(remaining)]
		copy(b.buf, remaining)
	} else {
		buf := make([]byte, len(remaining), b.capacity)
		copy(buf, remaining)
		b.buf = buf
	}
	b.consumed = 0
}

// Len returns the number of unconsumed bytes.
func (b *DataStreamBuffer) Len() int {
	return len(b.buf) - b.consumed
}

// Reset clears the buffer for reuse, preserving the backing array's capacity.
// This is critical for pool efficiency — the array is not freed, so the next
// connection that acquires this buffer starts with the same capacity.
func (b *DataStreamBuffer) Reset() {
	b.buf = b.buf[:0] // keep backing array
	b.consumed = 0
	b.skip = 0
	b.overflowCount = 0
}
