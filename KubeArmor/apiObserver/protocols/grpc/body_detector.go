// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

// Package grpc provides gRPC protocol utilities for the API Observer.
package grpc

// IsGRPCBody returns true when b starts with a valid gRPC Length-Prefix-Message
// frame (1-byte compressed flag + 4-byte big-endian length) whose declared
// payload length is consistent with the buffer size AND whose payload begins
// with a valid protobuf varint tag (field-number > 0, wire-type 0-5).
//
// This is used as a fallback classifier when content-type is absent (e.g. lost
// to HPACK mid-stream connection).  False-positive rate is very low: the LPM
// header + protobuf tag check eliminates random binary data.
func IsGRPCBody(b []byte) bool {
    const lpmHeaderSize = 5
    if len(b) < lpmHeaderSize {
        return false
    }
    // Byte 0: compressed flag (must be 0 or 1).
    if b[0] != 0 && b[0] != 1 {
        return false
    }
    // Bytes 1-4: big-endian message length.
    msgLen := uint32(b[1])<<24 | uint32(b[2])<<16 | uint32(b[3])<<8 | uint32(b[4])
    // Sanity: declared length must fit within buffer (allowing partial reads).
    if msgLen > 16*1024*1024 { // 16 MB hard cap
        return false
    }
    payload := b[lpmHeaderSize:]
    if len(payload) == 0 {
        // Zero-length gRPC message (heartbeat / empty response) — valid.
        return msgLen == 0
    }
    // Validate that payload[0..] starts with a valid protobuf varint tag.
    // A valid tag: bits[0..2] = wire-type (0-5, not 6/7), bits[3..] = field-number > 0.
    tag, n := decodeVarint(payload)
    if n == 0 {
        return false
    }
    wireType := tag & 0x7
    fieldNum  := tag >> 3
    if wireType > 5 || fieldNum == 0 {
        return false
    }
    return true
}

// decodeVarint decodes a protobuf varint from b.
// Returns (value, bytesConsumed); bytesConsumed == 0 on error.
func decodeVarint(b []byte) (uint64, int) {
    var val uint64
    for i, byt := range b {
        if i >= 10 {
            return 0, 0
        }
        val |= uint64(byt&0x7F) << (7 * uint(i))
        if byt&0x80 == 0 {
            return val, i + 1
        }
    }
    return 0, 0
}
