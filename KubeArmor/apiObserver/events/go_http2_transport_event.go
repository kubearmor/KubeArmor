// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package events

import (
    "bytes"
    "encoding/binary"
    "fmt"
)

// Must match struct go_h2_transport_event in commonstructs.h.
const (
    GoH2MaxFields = 20
    GoH2NameSize  = 128
    GoH2ValSize   = 128
)

// GoH2HdrField mirrors struct go_h2_hdr_field.
type GoH2HdrField struct {
    Name  [GoH2NameSize]byte
    Value [GoH2ValSize]byte
}

// GoH2TransportEvent mirrors struct go_h2_transport_event.
// Total size: 4+4+1+1+2 + 8*(32+128) = 8 + 1280 = 1288 bytes.
type GoH2TransportEvent struct {
    PID        uint32
    StreamID   uint32
    IsServer   uint8
    FieldCount uint8
    Pad        uint16
    Fields     [GoH2MaxFields]GoH2HdrField
}

const goH2TransportEventSize = 4 + 4 + 1 + 1 + 2 + GoH2MaxFields*(GoH2NameSize+GoH2ValSize)

// ParseGoH2TransportEvent decodes a raw ring-buffer sample into a GoH2TransportEvent.
func ParseGoH2TransportEvent(raw []byte) (*GoH2TransportEvent, error) {
    if len(raw) < goH2TransportEventSize {
        return nil, fmt.Errorf("go_h2_transport_event: short read %d < %d", len(raw), goH2TransportEventSize)
    }
    ev := &GoH2TransportEvent{}
    if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, ev); err != nil {
        return nil, fmt.Errorf("go_h2_transport_event decode: %w", err)
    }
    return ev, nil
}

// Headers returns a map[string]string of the decoded header fields, trimming NUL bytes.
func (e *GoH2TransportEvent) Headers() map[string]string {
    out := make(map[string]string, int(e.FieldCount))
    // Iterate all slots — BPF writes at index i (loop variable),
    // so there may be gaps from skipped fields. FieldCount is only
    // a hint for the map pre-allocation.
    for i := range GoH2MaxFields {
        name := cString(e.Fields[i].Name[:])
        if name == "" {
            continue // skipped slot
        }
        out[name] = cString(e.Fields[i].Value[:])
    }
    return out
}

// cString converts a NUL-terminated byte slice to a Go string.
func cString(b []byte) string {
    if before, _, ok := bytes.Cut(b, []byte{0}); ok {
        return string(before)
    }
    return string(b)
}

// Must match HEADER_FIELD_STR_SIZE in structs.h.
const HeaderFieldStrSize = 128

// GoH2SingleHeaderEvent mirrors struct go_h2_single_header_event.
// Emitted by hpack.WriteField and loopyWriter.writeHeader probes.
type GoH2SingleHeaderEvent struct {
	PID       uint32
	StreamID  uint32
	IsServer  uint8
	EventType uint8 // 1=read, 2=write
	NameLen   uint16
	ValueLen  uint16
	Pad       uint16
	Name      [HeaderFieldStrSize]byte
	Value     [HeaderFieldStrSize]byte
}

const goH2SingleHeaderEventSize = 4 + 4 + 1 + 1 + 2 + 2 + 2 + HeaderFieldStrSize + HeaderFieldStrSize

// ParseGoH2SingleHeaderEvent decodes a raw ring-buffer sample into a GoH2SingleHeaderEvent.
func ParseGoH2SingleHeaderEvent(raw []byte) (*GoH2SingleHeaderEvent, error) {
	if len(raw) < goH2SingleHeaderEventSize {
		return nil, fmt.Errorf("go_h2_single_header_event: short read %d < %d", len(raw), goH2SingleHeaderEventSize)
	}
	ev := &GoH2SingleHeaderEvent{}
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, ev); err != nil {
		return nil, fmt.Errorf("go_h2_single_header_event decode: %w", err)
	}
	return ev, nil
}

// HeaderName returns the decoded header name.
func (e *GoH2SingleHeaderEvent) HeaderName() string {
	return cString(e.Name[:])
}

// HeaderValue returns the decoded header value.
func (e *GoH2SingleHeaderEvent) HeaderValue() string {
	return cString(e.Value[:])
}
