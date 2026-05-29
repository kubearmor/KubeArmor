// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package http1

import (
	"fmt"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// findChunkedEnd tests — the core bug fix
// ---------------------------------------------------------------------------

func TestFindChunkedEnd_NoTrailers(t *testing.T) {
	// The most common case: terminal chunk "0\r\n\r\n" with no trailers.
	// Before the fix, this returned (0, false, false) — "incomplete".
	body := "5\r\nhello\r\n0\r\n\r\n"
	buf := []byte(body)
	offset := 0

	totalLen, complete, truncated := findChunkedEnd(buf, offset)
	if !complete {
		t.Fatalf("findChunkedEnd returned complete=false for a valid chunked body without trailers")
	}
	if truncated {
		t.Fatalf("findChunkedEnd returned truncated=true unexpectedly")
	}
	if totalLen != len(buf) {
		t.Fatalf("findChunkedEnd totalLen=%d, want %d", totalLen, len(buf))
	}
}

func TestFindChunkedEnd_NoTrailers_LenientLF(t *testing.T) {
	// Lenient case: bare LF for the terminal chunk terminator.
	// Chunk data still uses CRLF (as all HTTP servers do), but the
	// final empty-trailer line is just "\n".
	body := "5\r\nhello\r\n0\r\n\n"
	buf := []byte(body)

	totalLen, complete, truncated := findChunkedEnd(buf, 0)
	if !complete {
		t.Fatalf("findChunkedEnd returned complete=false for LF-only terminal")
	}
	if truncated {
		t.Fatalf("unexpected truncation")
	}
	if totalLen != len(buf) {
		t.Fatalf("totalLen=%d, want %d", totalLen, len(buf))
	}
}

func TestFindChunkedEnd_WithTrailers(t *testing.T) {
	// Terminal chunk followed by one trailer header and blank line.
	body := "5\r\nhello\r\n0\r\nTrailer: value\r\n\r\n"
	buf := []byte(body)

	totalLen, complete, truncated := findChunkedEnd(buf, 0)
	if !complete {
		t.Fatalf("findChunkedEnd returned complete=false for chunked body with trailers")
	}
	if truncated {
		t.Fatalf("unexpected truncation")
	}
	if totalLen != len(buf) {
		t.Fatalf("totalLen=%d, want %d", totalLen, len(buf))
	}
}

func TestFindChunkedEnd_MultipleChunks(t *testing.T) {
	// Two data chunks followed by terminal.
	body := "5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"
	buf := []byte(body)

	totalLen, complete, truncated := findChunkedEnd(buf, 0)
	if !complete {
		t.Fatalf("findChunkedEnd returned complete=false for multi-chunk body")
	}
	if truncated {
		t.Fatalf("unexpected truncation")
	}
	if totalLen != len(buf) {
		t.Fatalf("totalLen=%d, want %d", totalLen, len(buf))
	}
}

func TestFindChunkedEnd_Incomplete(t *testing.T) {
	// Only one chunk, no terminal yet — should return incomplete.
	body := "5\r\nhello\r\n"
	buf := []byte(body)

	_, complete, _ := findChunkedEnd(buf, 0)
	if complete {
		t.Fatalf("findChunkedEnd returned complete=true for an incomplete chunked body")
	}
}

func TestFindChunkedEnd_WithHeaderOffset(t *testing.T) {
	// Simulates a full HTTP response where bodyStart is after headers.
	headers := "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
	body := "5\r\nhello\r\n0\r\n\r\n"
	buf := []byte(headers + body)
	offset := len(headers)

	totalLen, complete, truncated := findChunkedEnd(buf, offset)
	if !complete {
		t.Fatalf("findChunkedEnd returned complete=false")
	}
	if truncated {
		t.Fatalf("unexpected truncation")
	}
	if totalLen != len(buf) {
		t.Fatalf("totalLen=%d, want %d", totalLen, len(buf))
	}
}

// ---------------------------------------------------------------------------
// decodeChunked tests
// ---------------------------------------------------------------------------

func TestDecodeChunked_Simple(t *testing.T) {
	wire := []byte("5\r\nhello\r\n0\r\n\r\n")
	decoded, err := decodeChunked(wire)
	if err != nil {
		t.Fatalf("decodeChunked error: %v", err)
	}
	if string(decoded) != "hello" {
		t.Fatalf("decoded=%q, want %q", string(decoded), "hello")
	}
}

func TestDecodeChunked_MultiChunk(t *testing.T) {
	wire := []byte("5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n")
	decoded, err := decodeChunked(wire)
	if err != nil {
		t.Fatalf("decodeChunked error: %v", err)
	}
	if string(decoded) != "hello world" {
		t.Fatalf("decoded=%q, want %q", string(decoded), "hello world")
	}
}

// ---------------------------------------------------------------------------
// SSE body extraction tests
// ---------------------------------------------------------------------------

func TestExtractSSEData_SingleEvent(t *testing.T) {
	body := []byte("data: {\"jsonrpc\":\"2.0\",\"id\":3,\"result\":{}}\n\n")
	got := extractSSEData(body)
	want := `{"jsonrpc":"2.0","id":3,"result":{}}`
	if string(got) != want {
		t.Fatalf("extractSSEData=%q, want %q", string(got), want)
	}
}

func TestExtractSSEData_MultipleEvents(t *testing.T) {
	body := []byte("data: {\"type\":\"progress\"}\n\ndata: {\"type\":\"result\"}\n\n")
	got := extractSSEData(body)
	want := "{\"type\":\"progress\"}\n{\"type\":\"result\"}"
	if string(got) != want {
		t.Fatalf("extractSSEData=%q, want %q", string(got), want)
	}
}

func TestExtractSSEData_WithCRLF(t *testing.T) {
	body := []byte("data: hello\r\n\r\n")
	got := extractSSEData(body)
	if string(got) != "hello" {
		t.Fatalf("extractSSEData=%q, want %q", string(got), "hello")
	}
}

func TestExtractSSEData_NonSSEBody(t *testing.T) {
	// Non-SSE body should be returned as-is.
	body := []byte("{\"jsonrpc\":\"2.0\"}")
	got := extractSSEData(body)
	if string(got) != string(body) {
		t.Fatalf("extractSSEData should return body as-is for non-SSE, got=%q", string(got))
	}
}

func TestExtractSSEData_EventAndIdFields(t *testing.T) {
	// SSE can have event:, id:, retry: fields — only data: should be extracted.
	body := []byte("event: message\ndata: {\"result\":true}\nid: 42\n\n")
	got := extractSSEData(body)
	want := `{"result":true}`
	if string(got) != want {
		t.Fatalf("extractSSEData=%q, want %q", string(got), want)
	}
}

// ---------------------------------------------------------------------------
// Full HTTP/1 parser integration tests — MCP wire formats
// ---------------------------------------------------------------------------

func TestParse_MCPInitializeResponse(t *testing.T) {
	// MCP initialize response: Content-Type: application/json with Content-Length.
	// This path worked before the fix — verify it still works.
	body := `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2024-11-05","capabilities":{},"serverInfo":{"name":"everything","version":"1.0"}}}`
	resp := fmt.Sprintf(
		"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s",
		len(body), body,
	)

	parser := NewParser(false) // response parser
	msgs, consumed, _, _, err := parser.Parse([]byte(resp))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message, got %d", len(msgs))
	}
	if consumed != len(resp) {
		t.Fatalf("consumed=%d, want %d", consumed, len(resp))
	}
	if msgs[0].StatusCode != 200 {
		t.Fatalf("status=%d, want 200", msgs[0].StatusCode)
	}
	if string(msgs[0].Body) != body {
		t.Fatalf("body=%q, want %q", string(msgs[0].Body), body)
	}
}

func TestParse_MCPToolsCallSSEResponse(t *testing.T) {
	// MCP tools/call response: text/event-stream with chunked encoding.
	// This is the exact scenario that failed before the fix.
	ssePayload := "data: {\"jsonrpc\":\"2.0\",\"id\":3,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"Echo: hello\"}]}}\n\n"
	chunkHex := fmt.Sprintf("%x", len(ssePayload))
	chunkedBody := chunkHex + "\r\n" + ssePayload + "\r\n0\r\n\r\n"

	resp := "HTTP/1.1 200 OK\r\n" +
		"Content-Type: text/event-stream\r\n" +
		"Transfer-Encoding: chunked\r\n" +
		"\r\n" +
		chunkedBody

	parser := NewParser(false) // response parser
	msgs, consumed, _, _, err := parser.Parse([]byte(resp))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message, got %d (consumed=%d/%d)", len(msgs), consumed, len(resp))
	}
	if msgs[0].StatusCode != 200 {
		t.Fatalf("status=%d, want 200", msgs[0].StatusCode)
	}

	// The body should be the clean JSON (SSE framing stripped).
	expectedBody := `{"jsonrpc":"2.0","id":3,"result":{"content":[{"type":"text","text":"Echo: hello"}]}}`
	if string(msgs[0].Body) != expectedBody {
		t.Fatalf("body=%q, want %q", string(msgs[0].Body), expectedBody)
	}
}

func TestParse_MCPToolsCallJSONResponse(t *testing.T) {
	// Some MCP servers respond to tools/call with application/json (non-streaming).
	body := `{"jsonrpc":"2.0","id":3,"result":{"content":[{"type":"text","text":"Echo: hello"}]}}`
	resp := fmt.Sprintf(
		"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s",
		len(body), body,
	)

	parser := NewParser(false)
	msgs, _, _, _, err := parser.Parse([]byte(resp))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message, got %d", len(msgs))
	}
	if string(msgs[0].Body) != body {
		t.Fatalf("body=%q, want %q", string(msgs[0].Body), body)
	}
}

func TestParse_ChunkedResponseNoSSE(t *testing.T) {
	// Regular chunked JSON response (not SSE) — body should pass through as-is.
	body := `{"status":"ok"}`
	chunkHex := fmt.Sprintf("%x", len(body))
	chunkedBody := chunkHex + "\r\n" + body + "\r\n0\r\n\r\n"

	resp := "HTTP/1.1 200 OK\r\n" +
		"Content-Type: application/json\r\n" +
		"Transfer-Encoding: chunked\r\n" +
		"\r\n" +
		chunkedBody

	parser := NewParser(false)
	msgs, _, _, _, err := parser.Parse([]byte(resp))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message, got %d", len(msgs))
	}
	// No SSE extraction for application/json — body should be raw JSON.
	if string(msgs[0].Body) != body {
		t.Fatalf("body=%q, want %q", string(msgs[0].Body), body)
	}
}

func TestParse_MCPRequest(t *testing.T) {
	// MCP POST request — verify request parsing works.
	body := `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo","arguments":{"message":"hello"}}}`
	req := fmt.Sprintf(
		"POST /mcp HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: %d\r\nMcp-Session-Id: test-session\r\n\r\n%s",
		len(body), body,
	)

	parser := NewParser(true) // request parser
	msgs, consumed, _, _, err := parser.Parse([]byte(req))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message, got %d", len(msgs))
	}
	if consumed != len(req) {
		t.Fatalf("consumed=%d, want %d", consumed, len(req))
	}
	if msgs[0].Method != "POST" {
		t.Fatalf("method=%q, want POST", msgs[0].Method)
	}
	if msgs[0].Path != "/mcp" {
		t.Fatalf("path=%q, want /mcp", msgs[0].Path)
	}
	if string(msgs[0].Body) != body {
		t.Fatalf("body=%q, want %q", string(msgs[0].Body), body)
	}
}

func TestParse_SSEMultiEventChunked(t *testing.T) {
	// MCP streaming tools/call with multiple SSE events (progress + result).
	ssePayload := "data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{\"progress\":50}}\n\n" +
		"data: {\"jsonrpc\":\"2.0\",\"id\":3,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"Done\"}]}}\n\n"
	chunkHex := fmt.Sprintf("%x", len(ssePayload))
	chunkedBody := chunkHex + "\r\n" + ssePayload + "\r\n0\r\n\r\n"

	resp := "HTTP/1.1 200 OK\r\n" +
		"Content-Type: text/event-stream\r\n" +
		"Transfer-Encoding: chunked\r\n" +
		"\r\n" +
		chunkedBody

	parser := NewParser(false)
	msgs, _, _, _, err := parser.Parse([]byte(resp))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message, got %d", len(msgs))
	}

	// Both data lines should be extracted, separated by newline.
	got := string(msgs[0].Body)
	if !strings.Contains(got, "notifications/progress") {
		t.Fatalf("body missing progress notification: %q", got)
	}
	if !strings.Contains(got, "\"result\"") {
		t.Fatalf("body missing result: %q", got)
	}
}

func TestParse_202AcceptedNoBody(t *testing.T) {
	// MCP notifications/initialized response: 202 Accepted with no body.
	// This validates the parser handles body-less responses correctly.
	resp := "HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\n\r\n"

	parser := NewParser(false)
	msgs, consumed, _, _, err := parser.Parse([]byte(resp))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message, got %d", len(msgs))
	}
	if consumed != len(resp) {
		t.Fatalf("consumed=%d, want %d", consumed, len(resp))
	}
	if msgs[0].StatusCode != 202 {
		t.Fatalf("status=%d, want 202", msgs[0].StatusCode)
	}
	if len(msgs[0].Body) != 0 {
		t.Fatalf("body should be empty, got %q", string(msgs[0].Body))
	}
}
