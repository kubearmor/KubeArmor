// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package events

import (
	"encoding/binary"
	"fmt"
	"net"
)

// TLS chunk flag bits — must match BPF TLS_FLAGS_* in structs.h.
const (
	TlsFlagIsClient = 1 << 0
	TlsFlagIsRead   = 1 << 1
)

// tlsChunkHeaderSize is the fixed-size header before data[].
// Layout from struct ks_tls_chunk in structs.h:
//
//	 0:  u64  timestamp
//	 8:  u32  cgroup_id
//	12:  u32  pid
//	16:  u32  tgid
//	20:  u32  len
//	24:  u32  start
//	28:  u32  recorded
//	32:  u32  fd
//	36:  u32  flags
//	40:  struct ks_address_info (48 bytes):
//	     40:  __be32 family
//	     44:  __be32 saddr4
//	     48:  __be32 daddr4
//	     52:  __u8   saddr6[16]
//	     68:  __u8   daddr6[16]
//	     84:  __be16 sport
//	     86:  __be16 dport
//	88:  u8   data[TLS_CHUNK_SIZE=4096]
const tlsChunkHeaderSize = 88

// TlsChunkEvent is the Go representation of struct ks_tls_chunk emitted
// by the kubeshark-style BPF perf buffer (ks_chunks_buffer).
type TlsChunkEvent struct {
	Timestamp uint64
	CgroupID  uint32
	PID       uint32
	TGID      uint32
	Len       uint32 // total plaintext length
	Start     uint32 // byte offset within total data
	Recorded  uint32 // bytes actually in Data[]
	FD        uint32
	Flags     uint32

	// Address info
	Family uint32
	SrcIP4 uint32
	DstIP4 uint32
	SrcIP6 [16]byte
	DstIP6 [16]byte
	SrcPort uint16
	DstPort uint16

	// Payload data (up to 4096 bytes per chunk)
	Data []byte
}

// IsRead returns true if this chunk is from a TLS read (ingress).
func (e *TlsChunkEvent) IsRead() bool {
	return e.Flags&TlsFlagIsRead != 0
}

// IsClient returns true if the connection was initiated by connect() (client-side).
func (e *TlsChunkEvent) IsClient() bool {
	return e.Flags&TlsFlagIsClient != 0
}

// SrcIPString returns the source IP as a string.
func (e *TlsChunkEvent) SrcIPString() string {
	if e.Family == 2 { // AF_INET
		return uint32ToIP(e.SrcIP4).String()
	}
	if e.Family == 10 { // AF_INET6
		return net.IP(e.SrcIP6[:]).String()
	}
	return ""
}

// DstIPString returns the destination IP as a string.
func (e *TlsChunkEvent) DstIPString() string {
	if e.Family == 2 { // AF_INET
		return uint32ToIP(e.DstIP4).String()
	}
	if e.Family == 10 { // AF_INET6
		return net.IP(e.DstIP6[:]).String()
	}
	return ""
}

// ParseTlsChunkEvent parses a raw perf buffer sample into a TlsChunkEvent.
func ParseTlsChunkEvent(data []byte) (*TlsChunkEvent, error) {
	if len(data) < tlsChunkHeaderSize {
		return nil, fmt.Errorf(
			"tls_chunk too short: got %d bytes, need >= %d",
			len(data), tlsChunkHeaderSize,
		)
	}

	e := &TlsChunkEvent{}

	e.Timestamp = binary.LittleEndian.Uint64(data[0:8])
	e.CgroupID = binary.LittleEndian.Uint32(data[8:12])
	e.PID = binary.LittleEndian.Uint32(data[12:16])
	e.TGID = binary.LittleEndian.Uint32(data[16:20])
	e.Len = binary.LittleEndian.Uint32(data[20:24])
	e.Start = binary.LittleEndian.Uint32(data[24:28])
	e.Recorded = binary.LittleEndian.Uint32(data[28:32])
	e.FD = binary.LittleEndian.Uint32(data[32:36])
	e.Flags = binary.LittleEndian.Uint32(data[36:40])

	// address_info starts at offset 40
	e.Family = binary.LittleEndian.Uint32(data[40:44])
	e.SrcIP4 = binary.LittleEndian.Uint32(data[44:48])
	e.DstIP4 = binary.LittleEndian.Uint32(data[48:52])
	copy(e.SrcIP6[:], data[52:68])
	copy(e.DstIP6[:], data[68:84])
	e.SrcPort = binary.BigEndian.Uint16(data[84:86]) // network byte order
	e.DstPort = binary.BigEndian.Uint16(data[86:88]) // network byte order

	// Parse variable-length data.
	recorded := int(e.Recorded)
	available := len(data) - tlsChunkHeaderSize
	if recorded > available {
		recorded = available
	}
	if recorded > 0 {
		e.Data = make([]byte, recorded)
		copy(e.Data, data[tlsChunkHeaderSize:tlsChunkHeaderSize+recorded])
	}

	return e, nil
}

// ToDataEvent converts a TlsChunkEvent into the existing DataEvent format
// used by the correlator pipeline. This bridges the kubeshark perf path
// with our existing event processing infrastructure.
func (e *TlsChunkEvent) ToDataEvent() *DataEvent {
	// Determine direction: read = ingress, write = egress
	direction := DirEgress
	if e.IsRead() {
		direction = DirIngress
	}

	srcIP := e.SrcIP4
	dstIP := e.DstIP4

	// For client-side connections:
	//   write (egress): src=local, dst=remote — addresses are already correct
	//   read (ingress): swap so src=remote sender
	// For server-side connections:
	//   read (ingress): src=remote client — addresses are already correct
	//   write (egress): swap so src=local
	// The BPF code stores addresses from struct sock which has:
	//   saddr = local, daddr = remote
	// Our DataEvent convention: egress → src=local, dst=remote
	//                           ingress → src=remote, dst=local (swap)
	if direction == DirIngress {
		srcIP, dstIP = dstIP, srcIP
	}

	ev := &DataEvent{
		Timestamp: e.Timestamp,
		PID:       e.PID,
		TID:       e.TGID,
		SrcIP:     srcIP,
		DstIP:     dstIP,
		SrcPort:   e.SrcPort,
		DstPort:   e.DstPort,
		DataLen:   e.Recorded,
		Direction: direction,
		Protocol:  ProtoUnknown, // Will be inferred by protocol_inference
		Flags:     FlagIsSSL,    // Mark as SSL traffic
		FD:        e.FD,
		SockPtr:   0, // Not available from perf path
		Payload:   e.Data,
	}

	if direction == DirIngress {
		ev.SrcPort, ev.DstPort = ev.DstPort, ev.SrcPort
	}

	ev.ConnectionKey = ConnectionKey{
		PID: e.PID,
		FD:  e.FD,
	}

	return ev
}
