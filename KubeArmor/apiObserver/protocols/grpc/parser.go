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

  "google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/types/known/emptypb"
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

// renderProtoUnknown is the Go implementation of Pixie's ParsePartialFromArray +
// TextFormat::PrintToString pipeline.
//
// It parses data into emptypb.Empty so that all bytes land in the unknown-field
// set (the library validates the wire framing), then walks the raw unknown bytes
// with protowire to produce field_number: value text.
//
// Returns "" if data is not valid protobuf (replaces the old isLikelyProto heuristic).
func renderProtoUnknown(data []byte, indent string) string {
	msg := &emptypb.Empty{}

	// Step 1 — equivalent to C++ ParsePartialFromArray.
	// AllowPartial tolerates missing required fields (Empty has none, but kept for
	// semantic parity with the C++ "Partial" qualifier).
	// DiscardUnknown must be false (the default) so unknown fields are preserved.
	if err := (proto.UnmarshalOptions{
		AllowPartial:   true,
		DiscardUnknown: false,
	}).Unmarshal(data, msg); err != nil {
		// Invalid protobuf wire format — treat as opaque bytes, not a proto message.
		return ""
	}

	// Retrieve the raw unknown-field bytes the library preserved.
	raw := msg.ProtoReflect().GetUnknown()
	if len(raw) == 0 {
		// Valid protobuf but no fields (e.g. an actual google.protobuf.Empty payload).
		return ""
	}

	// Step 2 — equivalent to C++ TextFormat::PrintToString on the UnknownFieldSet.
	return renderUnknownBytes(raw, indent)
}

// renderUnknownBytes walks raw protobuf unknown-field bytes using protowire and
// renders them as text. This mirrors C++ TextFormat::PrintUnknownFields.
//
// For LEN (wire type 2) fields it attempts a recursive parse as a nested message,
// rendering as "N {\n  ...\n}" on success — exactly what C++ TextFormat does when
// UnknownField::TYPE_LENGTH_DELIMITED bytes parse as a valid UnknownFieldSet.
// On failure the bytes are rendered as a Go quoted string (%q ≈ C's CEscape).
func renderUnknownBytes(raw []byte, indent string) string {
	var sb strings.Builder

	for len(raw) > 0 {
		num, typ, n := protowire.ConsumeTag(raw)
		if n < 0 {
			break // malformed tag — stop here rather than produce garbage
		}
		raw = raw[n:]

		switch typ {

		// Wire type 0: Varint — int32, int64, uint32, uint64, sint32, sint64, bool, enum.
		case protowire.VarintType:
			v, n := protowire.ConsumeVarint(raw)
			if n < 0 {
				break
			}
			raw = raw[n:]
			fmt.Fprintf(&sb, "%s%d: %d\n", indent, num, v)

		// Wire type 1: 64-bit — fixed64, sfixed64, double.
		case protowire.Fixed64Type:
			v, n := protowire.ConsumeFixed64(raw)
			if n < 0 {
				break
			}
			raw = raw[n:]
			fmt.Fprintf(&sb, "%s%d: 0x%016x\n", indent, num, v)

		// Wire type 2: LEN — string, bytes, embedded message, packed repeated fields.
		// This is the only ambiguous case. We mirror C++ TextFormat: attempt a
		// recursive Empty parse; success → nested message block, failure → quoted string.
		case protowire.BytesType:
			b, n := protowire.ConsumeBytes(raw)
			if n < 0 {
				break
			}
			raw = raw[n:]

			// Truncate very long fields for readability (same cap as old code).
			display := b
			truncated := false
			if len(display) > 128 {
				display = display[:128]
				truncated = true
			}

			if nested := renderProtoUnknown(b, indent+"  "); nested != "" {
				// C++ TextFormat: TYPE_LENGTH_DELIMITED parsed as nested UnknownFieldSet.
				fmt.Fprintf(&sb, "%s%d {\n%s%s}\n", indent, num, nested, indent)
			} else {
				// C++ TextFormat: TYPE_LENGTH_DELIMITED rendered as quoted bytes (CEscape).
				if truncated {
					fmt.Fprintf(&sb, "%s%d: %q...\n", indent, num, display)
				} else {
					fmt.Fprintf(&sb, "%s%d: %q\n", indent, num, display)
				}
			}

		// Wire type 5: 32-bit — fixed32, sfixed32, float.
		case protowire.Fixed32Type:
			v, n := protowire.ConsumeFixed32(raw)
			if n < 0 {
				break
			}
			raw = raw[n:]
			fmt.Fprintf(&sb, "%s%d: 0x%08x\n", indent, num, v)

		default:
			// Unknown wire type — stop; remaining bytes are likely corrupt.
			break
		}
	}

	return sb.String()
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
	text := renderProtoUnknown(data, "")
	if text == "" {
		return "<empty>"
	}

	return text
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
