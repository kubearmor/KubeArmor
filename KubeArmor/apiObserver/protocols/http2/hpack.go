// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor
package http2

import (
	"github.com/kubearmor/KubeArmor/KubeArmor/apiObserver/protocols/http2/bhpack"
)

// HPACKDecoder wraps bhpack.Decoder which is a mid-stream-tolerant HPACK
// decoder. Unlike the standard hpack.Decoder, bhpack emits a <BAD INDEX>
// sentinel for references to dynamic-table entries that were inserted before
// we started observing the connection, instead of returning a fatal error.
// This is essential because BPF-based tracing often begins mid-connection
// after the HPACK dynamic table has already been populated.
type HPACKDecoder struct {
	decoder *bhpack.Decoder
}

// NewHPACKDecoder creates a new HPACK decoder with the specified max table size.
func NewHPACKDecoder(maxDynamicTableSize uint32) *HPACKDecoder {
	dec := bhpack.NewDecoder(maxDynamicTableSize, nil)
	return &HPACKDecoder{
		decoder: dec,
	}
}

// DecodeHeaders decodes an HPACK encoded block into a slice of bhpack.HeaderField.
// Invalid dynamic-table references produce HeaderField{Name: "<BAD INDEX>"}
// instead of errors, allowing partial header recovery on mid-stream connections.
func (d *HPACKDecoder) DecodeHeaders(b []byte) ([]bhpack.HeaderField, error) {
	fields, err := d.decoder.DecodeFull(b)
	if err != nil {
		return nil, err
	}
	return fields, nil
}

// SetMaxDynamicTableSize updates the decoder's max dynamic table size.
func (d *HPACKDecoder) SetMaxDynamicTableSize(v uint32) {
	d.decoder.SetMaxDynamicTableSize(v)
}

// ExtractPseudoHeaders extracts the HTTP/2 pseudo-headers (like :method, :path)
// from the decoded fields, skipping any <BAD INDEX> sentinel entries.
func ExtractPseudoHeaders(fields []bhpack.HeaderField) (method, path, scheme, authority, status string) {
	for _, f := range fields {
		if f.Name == "<BAD INDEX>" {
			continue
		}
		if !f.IsPseudo() {
			continue
		}
		switch f.Name {
		case ":method":
			method = f.Value
		case ":path":
			path = f.Value
		case ":scheme":
			scheme = f.Value
		case ":authority":
			authority = f.Value
		case ":status":
			status = f.Value
		}
	}
	return
}

// HeadersToMap converts non-pseudo headers into a simple map representation,
// skipping any <BAD INDEX> sentinel entries.
func HeadersToMap(fields []bhpack.HeaderField) map[string]string {
	m := make(map[string]string)
	for _, f := range fields {
		if f.Name == "<BAD INDEX>" {
			continue
		}
		if !f.IsPseudo() {
			m[f.Name] = f.Value
		}
	}
	return m
}
