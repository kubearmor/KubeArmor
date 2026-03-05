// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package conn

import "log/slog"

// data_stream_buffer.h - tracks how many bytes the parser has consumed
// so that on overflow only already-processed bytes are discarded.

// Unlike a simple []byte with blind tail-trimming, this avoids destroying
// half-parsed messages.
type DataStreamBuffer struct {
	buf      []byte
	consumed int // index of first unconsumed byte
	capacity int
}

// NewDataStreamBuffer creates a buffer with the given capacity.
func NewDataStreamBuffer(capacity int) *DataStreamBuffer {
	return &DataStreamBuffer{
		capacity: capacity,
	}
}

// Write appends data to the buffer.  If the total size exceeds capacity,
// it first discards already-consumed bytes (GC).  If it's *still* over
// capacity after GC, it means a single unparseable message is larger than
// the buffer — discard everything and log a warning.
func (b *DataStreamBuffer) Write(data []byte) {
	b.buf = append(b.buf, data...)

	if len(b.buf) <= b.capacity {
		return
	}

	// Phase 1: GC consumed bytes.
	if b.consumed > 0 {
		b.buf = append([]byte(nil), b.buf[b.consumed:]...)
		b.consumed = 0
	}

	// Phase 2: if still over capacity, the unconsumed message itself is
	// too large.  Discard trailing bytes to stay within capacity.
	if len(b.buf) > b.capacity {
		slog.Warn("DataStreamBuffer: message exceeds capacity, discarding overflow",
			"bufLen", len(b.buf),
			"capacity", b.capacity,
		)
		b.buf = b.buf[len(b.buf)-b.capacity:]
	}
}

// Bytes returns the unconsumed portion of the buffer that the parser should
// work on.  This is the "window" the protocol parser sees.
func (b *DataStreamBuffer) Bytes() []byte {
	if b.consumed >= len(b.buf) {
		return nil
	}
	return b.buf[b.consumed:]
}

// Advance marks n bytes as consumed by the parser.  The next Bytes() call
// will skip these.  Actual memory reclaim happens lazily in Write() during GC.
func (b *DataStreamBuffer) Advance(n int) {
	b.consumed += n
	if b.consumed > len(b.buf) {
		b.consumed = len(b.buf)
	}
}

// SetRemaining replaces the unconsumed portion with the given remaining
// bytes.  This is a convenience for parsers that return a `remaining` slice.
func (b *DataStreamBuffer) SetRemaining(remaining []byte) {
	// Drop everything up to the consumed point, then replace with remaining.
	b.buf = append([]byte(nil), remaining...)
	b.consumed = 0
}

// Len returns the total number of unconsumed bytes.
func (b *DataStreamBuffer) Len() int {
	return len(b.buf) - b.consumed
}

// Reset discards all data and resets the consumed pointer.
func (b *DataStreamBuffer) Reset() {
	b.buf = nil
	b.consumed = 0
}
