// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

// Package grpc implements gRPC message parsing for the API Observer.
//
// gRPC uses HTTP/2 as its transport. This parser handles:
//   - Length-Prefixed Message (LPM) framing within DATA frames
//   - Protobuf-to-text decoding (Pixie's approach: unknown-field format)
//   - Trailer extraction (grpc-status, grpc-message)
//   - Compression (gzip) support
//   - Service/method name extraction from :path header
//
// Reference: Pixie grpc.cc — ParsePB / GRPCPBWireToText
package grpc

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// gRPC Length-Prefixed Message header: 1 byte compressed flag + 4 bytes message length
const lpmHeaderSize = 5

// maxBodyBytes caps the amount of body data we keep per message to prevent
// unbounded memory growth (same limit as Pixie's HalfStream::kMaxBodyBytes).
const maxBodyBytes = 512

// Message is one complete gRPC message (request or response).
type Message struct {
	IsRequest   bool
	ServiceName string // e.g. "helloworld.Greeter"
	MethodName  string // e.g. "SayHello"
	Headers     map[string]string
	Body        string // decoded protobuf text or raw body
	RawBody     []byte // raw protobuf bytes

	// gRPC-specific status (from trailers)
	GRPCStatus  int32  // grpc-status code (0=OK)
	GRPCMessage string // grpc-message (human-readable error)
}

// LPMFrame is one Length-Prefixed Message extracted from a gRPC DATA frame body.
type LPMFrame struct {
	Compressed bool
	Data       []byte // raw protobuf bytes
}

// Parser handles gRPC Length-Prefixed Message framing.
type Parser struct {
	// Partial frame buffer for incomplete LPM messages.
	partialBuf []byte
}

// NewParser creates a new gRPC parser.
func NewParser() *Parser {
	return &Parser{}
}

// ParseLPM extracts one or more Length-Prefixed Messages from a gRPC DATA body.
// Returns the parsed frames, any remaining (incomplete) bytes, and an error.
//
// Reference: gRPC wire format — https://grpc.io/docs/what-is-grpc/core-concepts/#grpc-protocol
//
//	Each message is preceded by:
//	  [1-byte compressed flag][4-byte big-endian message length][N-byte payload]
func ParseLPM(body []byte) ([]LPMFrame, []byte, error) {
	var frames []LPMFrame
	offset := 0

	for offset+lpmHeaderSize <= len(body) {
		compressedFlag := body[offset]
		msgLen := binary.BigEndian.Uint32(body[offset+1 : offset+5])

		// Sanity check: reject unreasonably large messages
		if msgLen > 16*1024*1024 { // 16MB
			return frames, body[offset:], fmt.Errorf("gRPC LPM message too large: %d bytes", msgLen)
		}

		frameEnd := offset + lpmHeaderSize + int(msgLen)
		if frameEnd > len(body) {
			// Incomplete frame — return remaining bytes
			return frames, body[offset:], nil
		}

		payload := body[offset+lpmHeaderSize : frameEnd]

		frames = append(frames, LPMFrame{
			Compressed: compressedFlag == 1,
			Data:       payload,
		})

		offset = frameEnd
	}

	if offset < len(body) {
		return frames, body[offset:], nil
	}
	return frames, nil, nil
}

// DecodePBToText converts raw protobuf bytes to a human-readable text format
// using unknown-field wire format decoding (field_number: value).
//
// This is the Go equivalent of Pixie's grpc.cc:ParsePB approach:
// ParsePartialFromArray into an empty message, then TextFormat::PrintToString.
// Since we don't have the .proto schema, we decode using wire format directly.
//
// The output looks like: `1: "hello world" 2: 42`
func DecodePBToText(data []byte, isGzipped bool) string {
	if len(data) == 0 {
		return ""
	}

	// Handle gzip decompression
	if isGzipped {
		reader, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return "<Failed to gunzip data>"
		}
		defer reader.Close()
		decompressed, err := io.ReadAll(io.LimitReader(reader, int64(maxBodyBytes)))
		if err != nil {
			return "<Failed to gunzip data>"
		}
		data = decompressed
	}

	// Decode protobuf wire format into text representation
	text, err := decodeProtoWireToText(data)
	if err != nil {
		return "<Failed to parse protobuf>"
	}
	if text == "" {
		return "<empty>"
	}
	return text
}

// decodeProtoWireToText parses raw protobuf wire format bytes into a human-readable
// text format with field numbers. This mirrors Pixie's approach of using
// Empty.ParsePartialFromArray + TextFormat::PrintToString.
//
// Wire types:
//
//	0: Varint  — field_num: value
//	1: 64-bit  — field_num: 0xhexvalue
//	2: Length-delimited — field_num: "string" or field_num: { nested }
//	5: 32-bit  — field_num: 0xhexvalue
func decodeProtoWireToText(data []byte) (string, error) {
	var parts []string
	offset := 0

	for offset < len(data) {
		if offset >= len(data) {
			break
		}

		// Read the tag (varint)
		tag, n := decodeVarint(data[offset:])
		if n == 0 {
			break // Malformed
		}
		offset += n

		fieldNum := tag >> 3
		wireType := tag & 0x7

		switch wireType {
		case 0: // Varint
			val, n := decodeVarint(data[offset:])
			if n == 0 {
				return strings.Join(parts, " "), nil
			}
			offset += n
			parts = append(parts, fmt.Sprintf("%d: %d", fieldNum, val))

		case 1: // 64-bit
			if offset+8 > len(data) {
				return strings.Join(parts, " "), nil
			}
			val := binary.LittleEndian.Uint64(data[offset : offset+8])
			offset += 8
			parts = append(parts, fmt.Sprintf("%d: 0x%x", fieldNum, val))

		case 2: // Length-delimited (string, bytes, nested message)
			length, n := decodeVarint(data[offset:])
			if n == 0 {
				return strings.Join(parts, " "), nil
			}
			offset += n

			if offset+int(length) > len(data) {
				return strings.Join(parts, " "), nil
			}

			fieldData := data[offset : offset+int(length)]
			offset += int(length)

			// Try to decode as nested message first
			if nested, err := decodeProtoWireToText(fieldData); err == nil && isLikelyProto(fieldData) {
				parts = append(parts, fmt.Sprintf("%d: { %s }", fieldNum, nested))
			} else {
				// Treat as string/bytes — truncate for readability
				s := string(fieldData)
				if len(s) > 128 {
					s = s[:128] + "..."
				}
				parts = append(parts, fmt.Sprintf("%d: \"%s\"", fieldNum, sanitizeString(s)))
			}

		case 5: // 32-bit
			if offset+4 > len(data) {
				return strings.Join(parts, " "), nil
			}
			val := binary.LittleEndian.Uint32(data[offset : offset+4])
			offset += 4
			parts = append(parts, fmt.Sprintf("%d: 0x%x", fieldNum, val))

		default:
			// Unknown wire type — stop parsing
			return strings.Join(parts, " "), nil
		}
	}

	return strings.Join(parts, " "), nil
}

// isLikelyProto performs a heuristic to determine if bytes look like
// a valid protobuf message rather than a string/bytes field.
// We prefer string interpretation when the data is mostly printable ASCII,
// since protobuf field tags can coincidentally look like ASCII chars.
func isLikelyProto(data []byte) bool {
	if len(data) == 0 {
		return false
	}

	// If data is mostly printable ASCII, treat it as a string, not a nested message.
	// This prevents "hello" (0x68='h' → field 13, varint) from being misinterpreted.
	if isPrintableText(data) {
		return false
	}

	// Validate that the ENTIRE buffer parses as valid protobuf wire format.
	// Just checking the first tag is insufficient — "hello" starts with a valid tag.
	offset := 0
	fieldCount := 0
	for offset < len(data) {
		tag, n := decodeVarint(data[offset:])
		if n == 0 {
			return false
		}
		offset += n
		fieldNum := tag >> 3
		wireType := tag & 0x7
		if fieldNum == 0 || fieldNum > 10000 {
			return false
		}

		switch wireType {
		case 0: // varint
			_, vn := decodeVarint(data[offset:])
			if vn == 0 {
				return false
			}
			offset += vn
		case 1: // 64-bit
			if offset+8 > len(data) {
				return false
			}
			offset += 8
		case 2: // length-delimited
			length, vn := decodeVarint(data[offset:])
			if vn == 0 {
				return false
			}
			offset += vn
			if offset+int(length) > len(data) {
				return false
			}
			offset += int(length)
		case 5: // 32-bit
			if offset+4 > len(data) {
				return false
			}
			offset += 4
		default:
			return false
		}
		fieldCount++
	}

	// Must have consumed all bytes exactly AND have at least one field.
	return offset == len(data) && fieldCount > 0
}

// isPrintableText returns true if the majority (>75%) of bytes are printable
// ASCII characters (space through tilde, plus tab/newline/carriage-return).
func isPrintableText(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	printable := 0
	for _, b := range data {
		if (b >= 0x20 && b <= 0x7e) || b == '\t' || b == '\n' || b == '\r' {
			printable++
		}
	}
	return float64(printable)/float64(len(data)) > 0.75
}

// decodeVarint decodes a protobuf varint from the beginning of buf.
// Returns the value and the number of bytes consumed. Returns 0,0 on error.
func decodeVarint(buf []byte) (uint64, int) {
	var val uint64
	for i, b := range buf {
		if i >= 10 { // Varint too long
			return 0, 0
		}
		val |= uint64(b&0x7F) << (7 * uint(i))
		if b&0x80 == 0 {
			return val, i + 1
		}
	}
	return 0, 0
}

// sanitizeString replaces non-printable characters for safe text output.
func sanitizeString(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 32 && r < 127 && r != '"' && r != '\\' {
			b.WriteRune(r)
		} else {
			fmt.Fprintf(&b, "\\x%02x", r)
		}
	}
	return b.String()
}

// ParseMessage extracts a gRPC message from an HTTP/2 DATA frame body.
// It performs LPM framing, decompression, and protobuf decoding.
//
// Reference: Pixie grpc.cc:ParseReqRespBody
func (p *Parser) ParseMessage(body []byte, headers map[string]string) (*Message, []byte, error) {
	// Combine any partial data from previous calls
	if len(p.partialBuf) > 0 {
		body = append(p.partialBuf, body...)
		p.partialBuf = nil
	}

	msg := &Message{
		Headers: headers,
	}

	// Extract service/method from :path header (format: /package.Service/Method)
	if path, ok := headers[":path"]; ok && len(path) > 1 {
		msg.IsRequest = true
		trimmed := path[1:] // Remove leading slash
		for i := len(trimmed) - 1; i >= 0; i-- {
			if trimmed[i] == '/' {
				msg.ServiceName = trimmed[:i]
				msg.MethodName = trimmed[i+1:]
				break
			}
		}
	}

	// Check for gzip encoding
	isGzipped := false
	if enc, ok := headers["grpc-encoding"]; ok {
		isGzipped = strings.Contains(enc, "gzip")
	}

	// Parse LPM frames
	frames, remaining, err := ParseLPM(body)
	if err != nil {
		p.partialBuf = remaining
		return nil, nil, err
	}

	// Save remaining for next call
	if len(remaining) > 0 {
		p.partialBuf = make([]byte, len(remaining))
		copy(p.partialBuf, remaining)
	}

	// Decode all frames into text
	var bodyParts []string
	for _, frame := range frames {
		isCompressed := frame.Compressed && isGzipped
		text := DecodePBToText(frame.Data, isCompressed)
		bodyParts = append(bodyParts, text)
		msg.RawBody = append(msg.RawBody, frame.Data...)
	}

	if len(bodyParts) > 0 {
		msg.Body = strings.Join(bodyParts, "\n")
	}

	return msg, remaining, nil
}

// ParseTrailers extracts gRPC trailer values from HTTP/2 HEADERS frames
// sent with END_STREAM.
//
// Reference: gRPC protocol — trailers carry grpc-status and grpc-message
func (p *Parser) ParseTrailers(headers map[string]string) (grpcStatus int32, grpcMessage string, trailers map[string]string) {
	trailers = headers

	if s, ok := headers["grpc-status"]; ok {
		if code, err := strconv.ParseInt(s, 10, 32); err == nil {
			grpcStatus = int32(code)
		}
	}

	if m, ok := headers["grpc-message"]; ok {
		grpcMessage = m
	}

	return grpcStatus, grpcMessage, trailers
}

// IsGRPCContentType returns true if the content-type indicates gRPC traffic.
// Reference: Pixie types.h — HasGRPCContentType()
func IsGRPCContentType(contentType string) bool {
	return strings.HasPrefix(contentType, "application/grpc")
}

// ExtractServiceMethod parses a gRPC :path value like "/package.Service/Method"
// into service and method names.
func ExtractServiceMethod(path string) (service, method string) {
	if len(path) < 2 || path[0] != '/' {
		return "", ""
	}
	trimmed := path[1:]
	for i := len(trimmed) - 1; i >= 0; i-- {
		if trimmed[i] == '/' {
			return trimmed[:i], trimmed[i+1:]
		}
	}
	return trimmed, ""
}
