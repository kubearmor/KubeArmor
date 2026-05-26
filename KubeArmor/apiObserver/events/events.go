// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package events

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

// Direction, Flag and Protocol constants must match constants defined in KubeArmor/BPF/apiobserver/common/macros.h
const (
	// DirEgress: data written by the local process (outgoing request).
	// BPF emits src=local, dst=remote.
	DirEgress uint8 = 0

	// DirIngress: data received by the local process (incoming response).
	// BPF swaps src/dst so src=remote sender in all events.
	DirIngress uint8 = 1
)

const (
	ProtoUnknown uint8 = 0
	ProtoHTTP1   uint8 = 1
	ProtoHTTP2   uint8 = 2
	ProtoGRPC    uint8 = 3
)

const (
	// FlagNoPayload is set when the event carries no application payload
	// (e.g. sendfile in Task 3). The reassembler should skip these events.
	FlagNoPayload uint8 = 1 << 0

	// FlagTruncated is set when the payload was capped to MAX_DATA_SIZE.
	FlagTruncated uint8 = 1 << 1
)

// dataEventHeaderSize is the fixed byte count before the payload.
const dataEventHeaderSize = 48

// ConnectionKey uniquely identifies a TCP connection for its lifetime.
// Uses {PID, FD} keying — each process has its own FD table, so
// PID+FD naturally separates multi-hop traffic captured at the same node.
// When FD is 0 (missed connect/accept), falls back to SockPtr.
type ConnectionKey struct {
	PID     uint32
	FD      uint32
	SockPtr uint64 // fallback when FD=0
}

const FlagIsSSL uint8 = 1 << 2 // matches BPF FLAG_IS_SSL

// DataEvent is the Go representation of struct data_event emitted by the
// BPF ring buffer defined in KubeArmor/BPF/apiobserver/common/structs.h
type DataEvent struct {
	Timestamp uint64
	PID       uint32
	TID       uint32
	SrcIP     uint32
	DstIP     uint32
	SrcPort   uint16
	DstPort   uint16
	DataLen   uint32
	Direction uint8
	Protocol  uint8
	Flags     uint8
	FD        uint32
	SockPtr   uint64

	Payload       []byte
	ConnectionKey ConnectionKey

	// HasConnRole is true when IsClientConn was populated from BPF
	// (TLS chunks from connect/accept tracepoints). When false, the
	// ConnectionTracker falls back to direction-based guessing.
	HasConnRole  bool
	IsClientConn bool // true = connect() side, false = accept() side

	// Cached IP strings (lazily computed, avoid repeated allocation).
	srcIPStr string
	dstIPStr string
}

func (e DataEvent) IsSSL() bool {
	return e.Flags&FlagIsSSL != 0
}

// ParseDataEvent parses a raw ring-buffer sample into a DataEvent.
func ParseDataEvent(data []byte) (*DataEvent, error) {
	if len(data) < dataEventHeaderSize {
		return nil, fmt.Errorf(
			"data_event too short: got %d bytes, need ≥ %d",
			len(data), dataEventHeaderSize,
		)
	}

	e := &DataEvent{}

	// Parse fixed header.
	e.Timestamp = binary.LittleEndian.Uint64(data[0:8])
	e.PID = binary.LittleEndian.Uint32(data[8:12])
	e.TID = binary.LittleEndian.Uint32(data[12:16])
	e.SrcIP = binary.LittleEndian.Uint32(data[16:20])
	e.DstIP = binary.LittleEndian.Uint32(data[20:24])
	e.SrcPort = binary.LittleEndian.Uint16(data[24:26])
	e.DstPort = binary.LittleEndian.Uint16(data[26:28])
	e.DataLen = binary.LittleEndian.Uint32(data[28:32])
	e.Direction = data[32]
	e.Protocol = data[33]
	e.Flags = data[34]
	// data[35] -> pad[1], skip
	e.FD = binary.LittleEndian.Uint32(data[36:40])
	e.SockPtr = binary.LittleEndian.Uint64(data[40:48])

	// Derive ConnectionKey.
	e.ConnectionKey = ConnectionKey{
		PID:     e.PID,
		FD:      e.FD,
		SockPtr: e.SockPtr,
	}

	// Parse variable-length payload.
	// BPF emits exactly (header + min(data_len, MAX_DATA_SIZE)) bytes.
	// Guard: payloadLen ≤ bytes actually present in the ring-buffer sample.
	available := len(data) - dataEventHeaderSize
	payloadLen := int(e.DataLen)
	if payloadLen > available {
		payloadLen = available
	}
	if payloadLen > 0 {
		e.Payload = make([]byte, payloadLen)
		copy(e.Payload, data[dataEventHeaderSize:dataEventHeaderSize+payloadLen])
	}

	return e, nil
}

// SrcIPString returns the source IP in dotted-decimal notation.
// The result is cached to avoid repeated allocation on the hot path.
func (e *DataEvent) SrcIPString() string {
	if e.srcIPStr == "" {
		e.srcIPStr = uint32ToIP(e.SrcIP).String()
	}
	return e.srcIPStr
}

// DstIPString returns the destination IP in dotted-decimal notation.
// The result is cached to avoid repeated allocation on the hot path.
func (e *DataEvent) DstIPString() string {
	if e.dstIPStr == "" {
		e.dstIPStr = uint32ToIP(e.DstIP).String()
	}
	return e.dstIPStr
}

// Time converts the BPF ktime_get_ns() nanosecond timestamp to time.Time.
func (e *DataEvent) Time() time.Time {
	return time.Unix(0, int64(e.Timestamp))
}

// ProtocolString returns a human-readable protocol label.
func (e *DataEvent) ProtocolString() string {
	switch e.Protocol {
	case ProtoHTTP1:
		return "HTTP1.1"
	case ProtoHTTP2:
		return "HTTP2"
	case ProtoGRPC:
		return "gRPC"
	default:
		return "unknown"
	}
}

// IsRequest returns true when this event carries egress data (a request
// written by the local process).
func (e *DataEvent) IsRequest() bool {
	return e.Direction == DirEgress
}

// HasPayload returns false for metadata-only events (FlagNoPayload set),
// such as sendfile events added in Task 3.
func (e *DataEvent) HasPayload() bool {
	return e.Flags&FlagNoPayload == 0
}

// uint32ToIP converts a host-byte-order uint32 IPv4 address (as stored
// by BPF on little-endian x86/arm64) into a net.IP.
func uint32ToIP(ip uint32) net.IP {
	return net.IPv4(
		byte(ip),
		byte(ip>>8),
		byte(ip>>16),
		byte(ip>>24),
	)
}
