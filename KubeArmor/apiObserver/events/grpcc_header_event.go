// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package events

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
)

// GRPCCHeaderEvent is the Go mirror of struct grpcc_header_event in
// KubeArmor/BPF/apiobserver/grpc_c_trace.h.
//
// Wire layout (little-endian, LP64, no padding holes):
//
//	offset  0 : u32  pid       (4 bytes)
//	offset  4 : u32  fd        (4 bytes)
//	offset  8 : u32  stream_id (4 bytes)
//	offset 12 : u8   _pad      (1 byte)
//	offset 13 : u8[64] method  (64 bytes)  — null-terminated, up to 63 chars
//
// Total: 77 bytes. The [64]byte array is the critical fix vs. a scalar byte:
// binary.Read requires a fixed-size array to match the BPF ring-buffer layout.
type GRPCCHeaderEvent struct {
	PID      uint32
	FD       uint32
	StreamID uint32
	Pad      uint8
	Method   [64]byte
}

// ParseGRPCCHeaderEvent decodes a raw BPF ring-buffer record into a
// GRPCCHeaderEvent. Returns an error if the slice is too short.
func ParseGRPCCHeaderEvent(data []byte) (GRPCCHeaderEvent, error) {
	var ev GRPCCHeaderEvent
	size := binary.Size(ev) // = 77 bytes
	if len(data) < size {
		return ev, fmt.Errorf("grpcc_header_event: short record: got %d bytes, want %d", len(data), size)
	}
	if err := binary.Read(bytes.NewReader(data[:size]), binary.LittleEndian, &ev); err != nil {
		return ev, fmt.Errorf("grpcc_header_event decode: %w", err)
	}
	return ev, nil
}

// MethodString returns the gRPC ":path" value as a Go string,
// stripping trailing null bytes written by the BPF probe.
func (e GRPCCHeaderEvent) MethodString() string {
	return strings.TrimRight(string(e.Method[:]), "\x00")
}
