// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package events

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// GoGRPCEventType matches enum go_grpc_event_type in go_http2_trace.h.
const (
	GoGRPCEventServerRequest uint8 = 1
	GoGRPCEventClientRequest uint8 = 2
)

// GoGRPCRequestEvent is the Go-side representation of struct go_grpc_request_event
// emitted by the BPF ring buffer. It contains the full gRPC path and latency info.
//
// BPF struct layout (must match go_http2_trace.h):
//
//	struct go_grpc_request_event {
//	  u64 start_ns;      // offset 0
//	  u64 end_ns;        // offset 8
//	  u32 pid;           // offset 16
//	  u16 status;        // offset 20
//	  u8  event_type;    // offset 22
//	  u8  _pad;          // offset 23
//	  char path[160];    // offset 24
//	};
const goGRPCRequestEventSize = 24 + 160 // 184 bytes

type GoGRPCRequestEvent struct {
	StartNs   uint64
	EndNs     uint64
	PID       uint32
	Status    uint16
	EventType uint8
	Path      string
}

// LatencyNs returns the end-to-end latency in nanoseconds.
func (e *GoGRPCRequestEvent) LatencyNs() uint64 {
	if e.EndNs > e.StartNs {
		return e.EndNs - e.StartNs
	}
	return 0
}

// IsServer returns true for server-side events.
func (e *GoGRPCRequestEvent) IsServer() bool {
	return e.EventType == GoGRPCEventServerRequest
}

// ParseGoGRPCRequestEvent decodes a raw ring buffer sample into a GoGRPCRequestEvent.
func ParseGoGRPCRequestEvent(data []byte) (*GoGRPCRequestEvent, error) {
	if len(data) < goGRPCRequestEventSize {
		return nil, fmt.Errorf(
			"go_grpc_request_event too short: got %d bytes, need >= %d",
			len(data), goGRPCRequestEventSize,
		)
	}

	e := &GoGRPCRequestEvent{}
	e.StartNs = binary.LittleEndian.Uint64(data[0:8])
	e.EndNs = binary.LittleEndian.Uint64(data[8:16])
	e.PID = binary.LittleEndian.Uint32(data[16:20])
	e.Status = binary.LittleEndian.Uint16(data[20:22])
	e.EventType = data[22]

	// Path is a null-terminated C string at offset 24.
	pathBytes := data[24:goGRPCRequestEventSize]
	if idx := bytes.IndexByte(pathBytes, 0); idx >= 0 {
		e.Path = string(pathBytes[:idx])
	} else {
		e.Path = string(pathBytes)
	}

	return e, nil
}
