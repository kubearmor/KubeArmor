// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package conn

import "log/slog"

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
}

func NewDataStreamBuffer(capacity int) *DataStreamBuffer {
	return &DataStreamBuffer{capacity: capacity}
}

// Write appends data to the buffer, with three behaviours in order:
//
//   1. If skip > 0, consume the skip counter first (drain leftover body bytes
//      from the wire without storing them). If the entire chunk is covered by
//      skip, return immediately without touching buf.
//
//   2. If the buffer is within capacity after appending, return normally.
//
//   3. If over capacity, first GC already-consumed bytes. If still over
//      capacity (a single un-parsed message is larger than the buffer),
//      keep the HEAD of the buffer so HTTP headers are never discarded,
//      and log a warning.
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
		b.buf = append([]byte(nil), b.buf[b.consumed:]...)
		b.consumed = 0
	}

	// Phase 3: hard cap — keep HEAD so HTTP headers survive
	if len(b.buf) > b.capacity {
		slog.Warn("DataStreamBuffer: overflow, truncating to preserve headers",
			"bufLen", len(b.buf),
			"capacity", b.capacity,
		)
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
// Memory is reclaimed lazily on the next Write() call.
func (b *DataStreamBuffer) Advance(n int) {
	b.consumed += n
	if b.consumed > len(b.buf) {
		b.consumed = len(b.buf)
	}
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
	b.buf = append([]byte(nil), remaining...)
	b.consumed = 0
}

// Len returns the number of unconsumed bytes.
func (b *DataStreamBuffer) Len() int {
	return len(b.buf) - b.consumed
}

// Reset discards all buffered data and resets all counters.
func (b *DataStreamBuffer) Reset() {
	b.buf = nil
	b.consumed = 0
	b.skip = 0
}
