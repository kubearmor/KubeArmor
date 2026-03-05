package grpc

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor
// Package grpc implements gRPC message parsing for the API Observer.
//
// gRPC uses HTTP/2 as its transport, so this parser sits on top of the
// http2.Parser.  It handles:
//   - Length-Prefixed Message (LPM) framing within DATA frames
//   - Trailer extraction (grpc-status, grpc-message)
//   - Service/method name extraction from :path header
//
// NOTE: WIP - some parts not implemented fully yet. 
// TODO: implement full gRPC LPM parsing.
// This is currently a stub that compiles but returns no messages.
// Message is one complete gRPC message (request or response).

type Message struct {
	IsRequest   bool
	ServiceName string
	MethodName  string
	Headers map[string]string
	RawMessage []byte
}

// Parser handles gRPC Length-Prefixed Message framing.
type Parser struct {
	// TODO: internal buffering for partial LPM frames.
}

// NewParser creates a new gRPC parser.
func NewParser() *Parser {
	return &Parser{}
}

// ParseMessage extracts a gRPC message from an HTTP/2 DATA frame body.
//
// Returns:
//   - msg:       the parsed gRPC message, or nil if incomplete
//   - remaining: unconsumed bytes from body
//   - err:       non-nil on framing errors
//
// TODO: implement full LPM parsing.
func (p *Parser) ParseMessage(body []byte, headers map[string]string) (*Message, []byte, error) {
	// Stub: return a minimal message with the raw body.
	msg := &Message{
		Headers:    headers,
		RawMessage: body,
	}
	// Extract service/method from :path header (format: /package.Service/Method).
	if path, ok := headers[":path"]; ok && len(path) > 1 {
		msg.IsRequest = true
		// Remove leading slash.
		trimmed := path[1:]
		// Split into service and method.
		for i := len(trimmed) - 1; i >= 0; i-- {
			if trimmed[i] == '/' {
				msg.ServiceName = trimmed[:i]
				msg.MethodName = trimmed[i+1:]
				break
			}
		}
	}
	return msg, nil, nil
}

// ParseTrailers extracts gRPC trailer values from HTTP/2 HEADERS frames
// sent with END_STREAM.
//
// Returns:
//   - grpcStatus:  the value of "grpc-status" header ("0" = OK)
//   - trailers:    all trailer key-value pairs
//   - err:         non-nil if critical trailers are malformed
func (p *Parser) ParseTrailers(headers map[string]string) (string, map[string]string, error) {
	status := ""
	if s, ok := headers["grpc-status"]; ok {
		status = s
	}
	return status, headers, nil
}
