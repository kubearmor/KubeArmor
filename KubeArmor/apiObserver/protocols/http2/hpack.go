// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor
package http2

import (
	"golang.org/x/net/http2/hpack"
)

// HPACKDecoder wraps hpack.Decoder to easily parse and extract HTTP/2 headers.
type HPACKDecoder struct {
	decoder *hpack.Decoder
}

// NewHPACKDecoder creates a new HPACK decoder with the specified max table size.
func NewHPACKDecoder(maxDynamicTableSize uint32) *HPACKDecoder {
	var dec *hpack.Decoder
	dec = hpack.NewDecoder(maxDynamicTableSize, nil)
	return &HPACKDecoder{
		decoder: dec,
	}
}

// DecodeHeaders decodes an HPACK encoded block into a slice of HeaderFields.
func (d *HPACKDecoder) DecodeHeaders(b []byte) ([]hpack.HeaderField, error) {
	var fields []hpack.HeaderField
	d.decoder.SetEmitFunc(func(f hpack.HeaderField) {
		fields = append(fields, f)
	})
	defer d.decoder.SetEmitFunc(nil)

	// hpack.Decoder.Write keeps state and decodes the stream of bytes.
	_, err := d.decoder.Write(b)
	if err != nil {
		return nil, err
	}
	return fields, nil
}

// ExtractPseudoHeaders extracts the HTTP/2 pseudo-headers (like :method, :path)
// from the decoded fields.
func ExtractPseudoHeaders(fields []hpack.HeaderField) (method, path, scheme, authority, status string) {
	for _, f := range fields {
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

// HeadersToMap converts non-pseudo headers into a simple map representation.
func HeadersToMap(fields []hpack.HeaderField) map[string]string {
	m := make(map[string]string)
	for _, f := range fields {
		if !f.IsPseudo() {
			m[f.Name] = f.Value
		}
	}
	return m
}
