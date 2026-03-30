// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor
// Package http2 implements HTTP/2 frame parsing for the API Observer.
//
//
// The Parser maintains per-connection HPACK dynamic table state, so exactly
// ONE Parser instance must exist per TCP connection.
package http2

import (
	"encoding/binary"
	"fmt"
	"log/slog"
	"strings"
	"sync"
)

const (
	FrameTypeData         = 0x0
	FrameTypeHeaders      = 0x1
	FrameTypePriority     = 0x2
	FrameTypeRSTStream    = 0x3
	FrameTypeSettings     = 0x4
	FrameTypePushPromise  = 0x5
	FrameTypePing         = 0x6
	FrameTypeGoAway       = 0x7
	FrameTypeWindowUpdate = 0x8
	FrameTypeContinuation = 0x9
	// Frame flags
	FlagDataEndStream     = 0x01
	FlagDataPadded        = 0x08
	FlagHeadersEndStream  = 0x01
	FlagHeadersEndHeaders = 0x04
	FlagHeadersPadded     = 0x08
	FlagHeadersPriority   = 0x20
	FlagSettingsAck       = 0x01
	// Frame header size is always 9 bytes (RFC 7540 §4.1).
	FrameHeaderSize = 9
	// ClientPreface is the HTTP/2 client connection preface (RFC 7540 §3.5).
	ClientPreface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
)

// FrameHeader represents the 9-byte header of every HTTP/2 frame.
type FrameHeader struct {
	Length   uint32
	Type     uint8
	Flags    uint8
	StreamID uint32
}

func (fh *FrameHeader) IsEndStream() bool {
	return fh.Flags&FlagDataEndStream != 0
}
func (fh *FrameHeader) IsEndHeaders() bool {
	return fh.Flags&FlagHeadersEndHeaders != 0
}

// Message is one complete HTTP/2 stream message (request or response).
// Aggregated from HEADERS + DATA + optional TRAILERS frames.
type Message struct {
	StreamID    uint32
	IsEndStream bool
	IsRequest   bool
	// Pseudo-headers (decoded from HPACK).
	Method    string // :method
	Path      string // :path
	Scheme    string // :scheme
	Authority string // :authority
	Status    string // :status

	Headers     map[string]string
	ContentType string

	// Aggregated DATA frame payload.
	Body []byte
}

// StreamState tracks one HTTP/2 stream's accumulated headers and body.
type StreamState struct {
	StreamID      uint32
	Message       *Message
	HeadersBuffer []byte // For multi-frame CONTINUATION sequences
	IsComplete    bool
	mu            sync.Mutex
}

// Parser handles HTTP/2 frame parsing with connection-level state.
// It is NOT safe for concurrent use — callers must serialise access
// (ConnectionTracker already does this per-connection).
type Parser struct {
	// Connection-level HPACK decoder (shared across all streams).
	hpackDecoder *HPACKDecoder
	// Active streams on this connection.
	streams map[uint32]*StreamState
	mu      sync.RWMutex
	// Connection settings.
	maxFrameSize      uint32
	maxHeaderListSize uint32
	initialWindowSize uint32
	// Preface tracking.
	prefaceReceived bool
}

func NewParser() *Parser {
	return &Parser{
		hpackDecoder:      NewHPACKDecoder(4096),
		streams:           make(map[uint32]*StreamState),
		maxFrameSize:      16384, // Default (RFC 7540 §6.5.2)
		maxHeaderListSize: 0,     // Unlimited
		initialWindowSize: 65535, // Default
	}
}

// ParseFrames parses HTTP/2 frames from buf, returning complete messages
// and any unconsumed bytes.
func (p *Parser) ParseFrames(data []byte) ([]*Message, []byte, error) {
	var messages []*Message
	offset := 0
	if !p.prefaceReceived {
		prefaceLen := len(ClientPreface)
		if len(data) < prefaceLen {
			if strings.HasPrefix(ClientPreface, string(data)) {
				return nil, data, nil // Wait for more data
			}
			p.prefaceReceived = true
		} else if string(data[:prefaceLen]) == ClientPreface {
			p.prefaceReceived = true
			offset = prefaceLen
			slog.Debug("HTTP/2 connection preface received")
		} else {
			// No preface — treat as server-side connection.
			p.prefaceReceived = true
		}
	}

	prefaceBytes := []byte(ClientPreface)
	for offset+FrameHeaderSize <= len(data) {
		if offset+len(prefaceBytes) <= len(data) &&
			string(data[offset:offset+len(prefaceBytes)]) == ClientPreface {
			offset += len(prefaceBytes)
			continue
		}

		fh := &FrameHeader{
			Length:   (uint32(data[offset]) << 16) | (uint32(data[offset+1]) << 8) | uint32(data[offset+2]),
			Type:     data[offset+3],
			Flags:    data[offset+4],
			StreamID: binary.BigEndian.Uint32(data[offset+5:offset+9]) & 0x7FFFFFFF,
		}

		if fh.Length > p.maxFrameSize {
			offset++
			continue
		}
		frameEnd := offset + FrameHeaderSize + int(fh.Length)
		if frameEnd > len(data) {
			return messages, data[offset:], nil
		}
		payload := data[offset+FrameHeaderSize : frameEnd]
		msg, err := p.handleFrame(fh, payload)
		if err != nil {
			slog.Debug("Error handling HTTP/2 frame",
				"type", fh.Type,
				"stream_id", fh.StreamID,
				"error", err)
			// Continue processing other frames.
		} else if msg != nil {
			messages = append(messages, msg)
		}
		offset = frameEnd
	}
	// Return any remaining incomplete data.
	if offset < len(data) {
		return messages, data[offset:], nil
	}
	return messages, nil, nil
}

func (p *Parser) handleFrame(fh *FrameHeader, payload []byte) (*Message, error) {
	switch fh.Type {
	case FrameTypeData:
		return p.handleData(fh, payload)
	case FrameTypeHeaders:
		return p.handleHeaders(fh, payload)
	case FrameTypeContinuation:
		return p.handleContinuation(fh, payload)
	case FrameTypeSettings:
		return p.handleSettings(fh, payload)
	case FrameTypeRSTStream:
		return p.handleRSTStream(fh)
	case FrameTypePing, FrameTypePriority, FrameTypeGoAway,
		FrameTypeWindowUpdate, FrameTypePushPromise:
		// Control frames — skip.
		return nil, nil
	default:
		return nil, nil
	}
}

func (p *Parser) handleHeaders(fh *FrameHeader, payload []byte) (*Message, error) {
	headerData := payload

	slog.Debug("HTTP/2 HEADERS frame",
		"stream_id", fh.StreamID,
		"flags", fmt.Sprintf("0x%02x", fh.Flags),
		"end_stream", fh.IsEndStream(),
		"end_headers", fh.IsEndHeaders(),
		"payload_len", len(payload),
	)

	if fh.Flags&FlagHeadersPadded != 0 {
		if len(payload) == 0 {
			return nil, fmt.Errorf("HEADERS with PADDED flag but empty payload")
		}
		padLen := int(payload[0])
		headerData = payload[1:]
		if padLen >= len(headerData) {
			return nil, fmt.Errorf("padding %d exceeds payload %d", padLen, len(headerData))
		}
		if padLen > 0 {
			headerData = headerData[:len(headerData)-padLen]
		}
	}

	if fh.Flags&FlagHeadersPriority != 0 {
		if len(headerData) < 5 {
			return nil, fmt.Errorf("HEADERS with PRIORITY flag but insufficient data")
		}
		headerData = headerData[5:]
	}

	stream := p.getOrCreateStream(fh.StreamID)
	stream.mu.Lock()
	defer stream.mu.Unlock()
	if fh.IsEndHeaders() {
		return p.decodeAndFinishHeaders(stream, headerData, fh.IsEndStream())
	}
	// Headers span multiple frames — buffer for CONTINUATION.
	stream.HeadersBuffer = append(stream.HeadersBuffer, headerData...)
	return nil, nil
}

func (p *Parser) handleContinuation(fh *FrameHeader, payload []byte) (*Message, error) {
	p.mu.RLock()
	stream, ok := p.streams[fh.StreamID]
	p.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("CONTINUATION for unknown stream %d", fh.StreamID)
	}
	stream.mu.Lock()
	defer stream.mu.Unlock()
	stream.HeadersBuffer = append(stream.HeadersBuffer, payload...)
	if fh.IsEndHeaders() {
		// All header fragments received — decode the accumulated block.
		data := stream.HeadersBuffer
		stream.HeadersBuffer = nil
		return p.decodeAndFinishHeaders(stream, data, fh.IsEndStream())
	}
	return nil, nil
}

func (p *Parser) handleData(fh *FrameHeader, payload []byte) (*Message, error) {
	bodyData := payload
	// Strip padding.
	if fh.Flags&FlagDataPadded != 0 {
		if len(payload) == 0 {
			return nil, fmt.Errorf("DATA with PADDED flag but empty payload")
		}
		padLen := int(payload[0])
		bodyData = payload[1:]
		if padLen >= len(bodyData) {
			return nil, fmt.Errorf("DATA padding %d exceeds payload %d", padLen, len(bodyData))
		}
		if padLen > 0 {
			bodyData = bodyData[:len(bodyData)-padLen]
		}
	}
	p.mu.RLock()
	stream, ok := p.streams[fh.StreamID]
	p.mu.RUnlock()
	if !ok {
		// DATA before HEADERS — shouldn't happen per spec, but handle gracefully.
		stream = p.getOrCreateStream(fh.StreamID)
	}
	stream.mu.Lock()
	defer stream.mu.Unlock()
	stream.Message.Body = append(stream.Message.Body, bodyData...)
	if fh.IsEndStream() {
		stream.Message.IsEndStream = true
		stream.IsComplete = true
		p.deleteStream(fh.StreamID)
		return stream.Message, nil
	}
	return nil, nil
}

func (p *Parser) handleSettings(fh *FrameHeader, payload []byte) (*Message, error) {
	if fh.Flags&FlagSettingsAck != 0 {
		return nil, nil // ACK — nothing to update.
	}
	// Parse 6-byte setting entries: 2-byte ID + 4-byte value.
	for i := 0; i+6 <= len(payload); i += 6 {
		id := binary.BigEndian.Uint16(payload[i : i+2])
		val := binary.BigEndian.Uint32(payload[i+2 : i+6])
		switch id {
		case 3: // SETTINGS_MAX_CONCURRENT_STREAMS (ignored, informational)
		case 4: // SETTINGS_INITIAL_WINDOW_SIZE
			p.initialWindowSize = val
		case 5: // SETTINGS_MAX_FRAME_SIZE
			p.maxFrameSize = val
		case 6: // SETTINGS_MAX_HEADER_LIST_SIZE
			p.maxHeaderListSize = val
		case 1: // SETTINGS_HEADER_TABLE_SIZE
			// Update HPACK decoder table size.
			p.hpackDecoder.SetMaxDynamicTableSize(val)
		}
	}
	return nil, nil
}

func (p *Parser) handleRSTStream(fh *FrameHeader) (*Message, error) {
	// Stream was reset — clean up any buffered state.
	p.deleteStream(fh.StreamID)
	return nil, nil
}

func (p *Parser) getOrCreateStream(streamID uint32) *StreamState {
	p.mu.Lock()
	defer p.mu.Unlock()
	if s, ok := p.streams[streamID]; ok {
		return s
	}
	s := &StreamState{
		StreamID: streamID,
		Message: &Message{
			StreamID: streamID,
			Headers:  make(map[string]string),
		},
	}
	p.streams[streamID] = s
	return s
}
func (p *Parser) deleteStream(streamID uint32) {
	p.mu.Lock()
	delete(p.streams, streamID)
	p.mu.Unlock()
}

// decodeAndFinishHeaders decodes HPACK data, populates the stream's Message,
// and returns the Message if END_STREAM is set (headers-only message).
func (p *Parser) decodeAndFinishHeaders(stream *StreamState, hpackData []byte, endStream bool) (*Message, error) {
	fields, err := p.hpackDecoder.DecodeHeaders(hpackData)
	if err != nil {
		slog.Debug("HPACK decode error",
			"stream_id", stream.StreamID,
			"hpack_len", len(hpackData),
			"error", err,
		)
		p.deleteStream(stream.StreamID)
		return nil, fmt.Errorf("HPACK decode: %w", err)
	}
	method, path, scheme, authority, status := ExtractPseudoHeaders(fields)

	slog.Debug("HTTP/2 HEADERS decoded",
		"stream_id", stream.StreamID,
		"method", method,
		"path", path,
		"status", status,
		"scheme", scheme,
		"authority", authority,
		"num_fields", len(fields),
		"end_stream", endStream,
	)

	if method != "" {
		stream.Message.Method = method
		stream.Message.IsRequest = true
	}
	if path != "" {
		stream.Message.Path = path
	}
	if scheme != "" {
		stream.Message.Scheme = scheme
	}
	if authority != "" {
		stream.Message.Authority = authority
	}
	if status != "" {
		stream.Message.Status = status
	}

	if stream.Message.Headers == nil {
		stream.Message.Headers = make(map[string]string)
	}
	for k, v := range HeadersToMap(fields) {
		stream.Message.Headers[k] = v
	}

	if ct, ok := stream.Message.Headers["content-type"]; ok {
		stream.Message.ContentType = ct
	}
	if endStream {
		stream.Message.IsEndStream = true
		stream.IsComplete = true
		p.deleteStream(stream.StreamID)
		return stream.Message, nil
	}
	return nil, nil
}

// IsHTTP2Preface returns true if data starts with the HTTP/2 connection preface.
func IsHTTP2Preface(data []byte) bool {
	if len(data) < len(ClientPreface) {
		return strings.HasPrefix(ClientPreface, string(data))
	}
	return string(data[:len(ClientPreface)]) == ClientPreface
}

// StreamCount returns the number of active streams (for diagnostics).
func (p *Parser) StreamCount() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.streams)
}
