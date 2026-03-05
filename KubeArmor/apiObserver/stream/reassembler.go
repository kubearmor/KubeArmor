// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

// Package stream reassembles TCP byte streams into complete HTTP/1.x,
package stream

import (
	"bytes"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kubearmor/KubeArmor/KubeArmor/apiObserver/events"
	"github.com/kubearmor/KubeArmor/KubeArmor/apiObserver/protocols/grpc"
	"github.com/kubearmor/KubeArmor/KubeArmor/apiObserver/protocols/http2"
)

// StreamKey identifies a TCP stream direction.
// Two streams share one ConnectionKey (via SockPtr) but can have opposite
// StreamKeys (client→server, server→client).
type StreamKey struct {
	SrcIP   string
	SrcPort uint16
	DstIP   string
	DstPort uint16
}

// MessageMetadata carries structured fields extracted by the protocol parser.
type MessageMetadata struct {
	StreamID    uint32 // HTTP/2 stream ID; 0 for HTTP/1
	IsEndStream bool   // HTTP/2 END_STREAM flag
	IsRequest   bool
	Method      string // HTTP method or gRPC method name
	Service     string // gRPC service name (package.Service)
	GRPCStatus  string // gRPC trailer grpc-status value ("0" = OK)
}

// Message is one fully reassembled message (request or response).
// Data contains the serialised representation used by the
// parsers in apiObserver.go.
type Message struct {
	Data        []byte
	Protocol    uint8
	Metadata    MessageMetadata
	IsEncrypted bool
}

// CleanupReason records why a connection was removed from the table.
type CleanupReason int

const (
	ReasonTimeout CleanupReason = iota
	ReasonError
	ReasonCompleted
	ReasonBufferFull
	ReasonClosed
)

type connection struct {
	Key       events.ConnectionKey
	StreamKey StreamKey
	Protocol  uint8
	EstAt     time.Time
	LastSeen  time.Time
	Closed    bool
	IsSSL     bool

	// HTTP/1.x reassembly buffer
	http1Buf *bytes.Buffer

	// HTTP/2 reassembly buffer (incomplete frame data carried over)
	http2Buf *bytes.Buffer

	// HTTP/2 frame parser — one per connection, HPACK state is here
	http2Parser *http2.Parser

	// gRPC message parser — shares http2Parser for frame parsing
	grpcParser *grpc.Parser

	// Per-connection statistics
	MessageCount  int
	BytesReceived uint64
	BytesDropped  uint64

	// Fine-grained lock; held only during per-connection work, NOT during
	// global map lookups. Prevents the global RWMutex from being held
	// while parsing (which is the slow part).
	mu sync.Mutex
}

// ReassemblerStats are exported for monitoring (TODO).
type ReassemblerStats struct {
	TotalConnections  uint64
	ActiveConnections uint64
	CompletedMessages uint64
	DroppedMessages   uint64
	BytesProcessed    uint64
	ParseErrors       uint64
	CleanupByReason   map[CleanupReason]uint64
}

// DataStream classes merged into one. It is safe for concurrent use.
type Reassembler struct {
	conns      map[events.ConnectionKey]*connection
	mu         sync.RWMutex // guards conns map
	timeout    time.Duration
	maxBufSize int // per-connection buffer cap (bytes)
	stats      ReassemblerStats
	statsMu    sync.RWMutex
}

// NewReassembler creates a Reassembler and starts its background goroutines.
func NewReassembler(timeout time.Duration) *Reassembler {
	r := &Reassembler{
		conns:   make(map[events.ConnectionKey]*connection),
		timeout: timeout,
		stats: ReassemblerStats{
			CleanupByReason: make(map[CleanupReason]uint64),
		},
	}
	go r.cleanupLoop()
	go r.statsLoop()
	return r
}

// AddChunk feeds a BPF payload chunk into the reassembler for the given
// connection. Returns all complete messages extracted from the combined
// buffer.
func (r *Reassembler) AddChunk(
	streamKey StreamKey,
	connKey events.ConnectionKey,
	data []byte,
	direction uint8,
	proto uint8,
	isEncrypted bool,
) []Message {
	if len(data) == 0 {
		return nil
	}

	r.mu.RLock()
	conn, exists := r.conns[connKey]
	r.mu.RUnlock()

	if !exists {
		conn = r.createConn(streamKey, connKey, proto)
	}

	conn.mu.Lock()
	defer conn.mu.Unlock()

	if isEncrypted && !conn.IsSSL {
		conn.IsSSL = true
	}

	if conn.Protocol == events.ProtoUnknown && proto != events.ProtoUnknown {
		conn.Protocol = proto
		r.initParsers(conn)
	}

	currentBuf := r.bufferSize(conn)
	if currentBuf+len(data) > r.maxBufSize {
		slog.Warn("Connection buffer full, dropping data",
			"sock_ptr", connKey.SockPtr,
			"buf_size", currentBuf,
			"new_data", len(data),
		)
		conn.BytesDropped += uint64(len(data))
		r.statsMu.Lock()
		r.stats.DroppedMessages++
		r.stats.CleanupByReason[ReasonBufferFull]++
		r.statsMu.Unlock()
		r.resetBuffers(conn)
		return nil
	}

	conn.LastSeen = time.Now()
	conn.BytesReceived += uint64(len(data))
	r.statsMu.Lock()
	r.stats.BytesProcessed += uint64(len(data))
	r.statsMu.Unlock()

	// protocol dispatch
	var messages []Message
	var err error

	switch conn.Protocol {
	case events.ProtoHTTP1:
		if conn.http1Buf == nil {
			conn.http1Buf = &bytes.Buffer{}
		}
		conn.http1Buf.Write(data)
		messages = r.extractHTTP1(conn, direction)

	case events.ProtoHTTP2:
		if conn.http2Buf == nil {
			conn.http2Buf = &bytes.Buffer{}
		}
		conn.http2Buf.Write(data)
		messages, err = r.extractHTTP2(conn)

	case events.ProtoGRPC:
		if conn.http2Buf == nil {
			conn.http2Buf = &bytes.Buffer{}
		}
		conn.http2Buf.Write(data)
		messages, err = r.extractGRPC(conn)

	default:
		// Protocol not yet known — try to detect from payload
		if r.detectProtocol(conn, data) {
			// Recurse once with detected protocol; conn.Protocol is now set
			conn.mu.Unlock()
			msgs := r.AddChunk(streamKey, connKey, data, direction, conn.Protocol, false)
			conn.mu.Lock()
			return msgs
		}
		// Still unknown — buffer in HTTP/1 buf as fallback and try later
		if conn.http1Buf == nil {
			conn.http1Buf = &bytes.Buffer{}
		}
		conn.http1Buf.Write(data)
	}

	if err != nil {
		slog.Debug("Error extracting messages",
			"sock_ptr", connKey.SockPtr,
			"protocol", conn.Protocol,
			"error", err,
		)
		r.statsMu.Lock()
		r.stats.ParseErrors++
		r.statsMu.Unlock()
		r.recoverFromError(conn, err)
	}

	r.statsMu.Lock()
	r.stats.CompletedMessages += uint64(len(messages))
	r.statsMu.Unlock()
	conn.MessageCount += len(messages)

	// conn.IsSSL is true for the lifetime of the connection once any SSL
	// uprobe event arrives. This propagates IsEncrypted into PendingRequest
	// -> CorrelatedTrace -> pb.APIEvent.Metadata.Protocol ("HTTPS"/"HTTP2+TLS").
	if conn.IsSSL {
		for i := range messages {
			messages[i].IsEncrypted = true
		}
	}

	return messages
}

// CloseConnection removes all state for a connection.
// Called when a BPF close event arrives (Task 2).
func (r *Reassembler) CloseConnection(connKey events.ConnectionKey) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.conns[connKey]; exists {
		delete(r.conns, connKey)
		r.statsMu.Lock()
		r.stats.ActiveConnections--
		r.stats.CleanupByReason[ReasonClosed]++
		r.statsMu.Unlock()
	}
}

// GetStats returns a snapshot of reassembler statistics.
func (r *Reassembler) GetStats() ReassemblerStats {
	r.statsMu.RLock()
	defer r.statsMu.RUnlock()
	return r.stats
}

// Connection management

func (r *Reassembler) createConn(sk StreamKey, ck events.ConnectionKey, proto uint8) *connection {
	r.mu.Lock()
	defer r.mu.Unlock()

	if conn, exists := r.conns[ck]; exists {
		return conn
	}

	conn := &connection{
		Key:       ck,
		StreamKey: sk,
		Protocol:  proto,
		EstAt:     time.Now(),
		LastSeen:  time.Now(),
	}
	r.initParsers(conn)
	r.conns[ck] = conn

	r.statsMu.Lock()
	r.stats.TotalConnections++
	r.stats.ActiveConnections++
	r.statsMu.Unlock()

	return conn
}

// initParsers allocates protocol-specific parsers on first protocol detection.
// http2Parser is intentionally ONE instance per connection (HPACK bug fix).
func (r *Reassembler) initParsers(conn *connection) {
	switch conn.Protocol {
	case events.ProtoHTTP1:
		if conn.http1Buf == nil {
			conn.http1Buf = &bytes.Buffer{}
		}
	case events.ProtoHTTP2:
		if conn.http2Parser == nil {
			conn.http2Parser = http2.NewParser()
			conn.http2Buf = &bytes.Buffer{}
		}
	case events.ProtoGRPC:
		if conn.http2Parser == nil {
			conn.http2Parser = http2.NewParser() 
		}
		if conn.grpcParser == nil {
			conn.grpcParser = grpc.NewParser()
		}
		if conn.http2Buf == nil {
			conn.http2Buf = &bytes.Buffer{}
		}
	}
}

func (r *Reassembler) bufferSize(conn *connection) int {
	n := 0
	if conn.http1Buf != nil {
		n += conn.http1Buf.Len()
	}
	if conn.http2Buf != nil {
		n += conn.http2Buf.Len()
	}
	return n
}

func (r *Reassembler) resetBuffers(conn *connection) {
	if conn.http1Buf != nil {
		conn.http1Buf.Reset()
	}
	if conn.http2Buf != nil {
		conn.http2Buf.Reset()
	}
}

// detectProtocol checks payload bytes to infer the protocol.
func (r *Reassembler) detectProtocol(conn *connection, data []byte) bool {
	if len(data) < 4 {
		return false
	}
	// HTTP/2 client connection preface
	if http2.IsHTTP2Preface(data) {
		conn.Protocol = events.ProtoHTTP2
		conn.http2Parser = http2.NewParser()
		conn.http2Buf = &bytes.Buffer{}
		slog.Debug("Detected HTTP/2 protocol", "sock_ptr", conn.Key.SockPtr)
		return true
	}
	// HTTP/1.x request or response
	for _, prefix := range [][]byte{
		[]byte("GET "), []byte("POST "), []byte("PUT "), []byte("DELETE "),
		[]byte("PATCH "), []byte("HEAD "), []byte("OPTIONS "), []byte("HTTP/"),
	} {
		if bytes.HasPrefix(data, prefix) {
			conn.Protocol = events.ProtoHTTP1
			conn.http1Buf = &bytes.Buffer{}
			slog.Debug("Detected HTTP/1.x protocol", "sock_ptr", conn.Key.SockPtr)
			return true
		}
	}
	return false
}

// extractHTTP1 drains conn.http1Buf, yielding complete HTTP/1.x messages.
// Handles both Content-Length and chunked Transfer-Encoding.
func (r *Reassembler) extractHTTP1(conn *connection, direction uint8) []Message {
	var messages []Message

	for {
		buf := conn.http1Buf.Bytes()
		if len(buf) == 0 {
			break
		}

		method, isRequest := detectHTTP1Method(buf)
		isResponse := bytes.HasPrefix(buf, []byte("HTTP/"))

		if !isRequest && !isResponse {
			if skip := findNextHTTP1Boundary(buf); skip > 0 {
				conn.http1Buf.Next(skip)
				continue
			}
			slog.Debug("HTTP/1 buffer unrecognised, resetting",
				"sock_ptr", conn.Key.SockPtr,
				"first_bytes", string(buf[:min(20, len(buf))]),
			)
			conn.http1Buf.Reset()
			break
		}

		// locate end of headers
		sepIdx := bytes.Index(buf, []byte("\r\n\r\n"))
		if sepIdx < 0 {
			break // incomplete headers — wait for more data
		}
		headerEnd := sepIdx + 4 // first byte after \r\n\r\n
		headerSection := buf[:headerEnd]

		// getting body len
		if isResponse && isChunkedEncoding(headerSection) {
			completeLen := findChunkedEnd(buf)
			if completeLen < 0 {
				break // incomplete chunked body
			}
			msg := make([]byte, completeLen)
			copy(msg, buf[:completeLen])
			messages = append(messages, Message{
				Data:     msg,
				Protocol: events.ProtoHTTP1,
				Metadata: MessageMetadata{
					IsRequest: isRequest,
					Method:    method,
				},
			})
			conn.http1Buf.Next(completeLen)
			conn.MessageCount++
			continue
		}

		bodyLen := getContentLength(headerSection)
		if bodyLen > 0 {
			totalLen := headerEnd + bodyLen
			if len(buf) < totalLen {
				break 
			}
			msg := make([]byte, totalLen)
			copy(msg, buf[:totalLen])
			messages = append(messages, Message{
				Data:     msg,
				Protocol: events.ProtoHTTP1,
				Metadata: MessageMetadata{
					IsRequest: isRequest,
					Method:    method,
				},
			})
			conn.http1Buf.Next(totalLen)
			conn.MessageCount++
			continue
		}

		msg := make([]byte, headerEnd)
		copy(msg, buf[:headerEnd])
		messages = append(messages, Message{
			Data:     msg,
			Protocol: events.ProtoHTTP1,
			Metadata: MessageMetadata{
				IsRequest: isRequest,
				Method:    method,
			},
		})
		conn.http1Buf.Next(headerEnd)
		conn.MessageCount++
	}

	return messages
}

// extractHTTP2 feeds conn.http2Buf into the connection-level HTTP/2 parser
// and returns all complete stream messages.
// The parser returns (messages, remaining_bytes, error).  Any unparsed bytes
// are put back into http2Buf for the next call.
func (r *Reassembler) extractHTTP2(conn *connection) ([]Message, error) {
	if conn.http2Parser == nil {
		return nil, fmt.Errorf("HTTP/2 parser not initialised for sock_ptr=%d", conn.Key.SockPtr)
	}

	data := conn.http2Buf.Bytes()
	if len(data) == 0 {
		return nil, nil
	}

	h2msgs, remaining, err := conn.http2Parser.ParseFrames(data)
	if err != nil {
		return nil, fmt.Errorf("HTTP/2 parse error: %w", err)
	}

	// Replace buffer contents with only the unparsed remainder
	conn.http2Buf.Reset()
	if len(remaining) > 0 {
		conn.http2Buf.Write(remaining)
	}

	var messages []Message
	for _, h2msg := range h2msgs {
		serialised := serializeHTTP2Message(h2msg)
		messages = append(messages, Message{
			Data:     serialised,
			Protocol: events.ProtoHTTP2,
			Metadata: MessageMetadata{
				StreamID:    h2msg.StreamID,
				IsEndStream: h2msg.IsEndStream,
				IsRequest:   h2msg.IsRequest,
				Method:      h2msg.Method,
			},
		})
		conn.MessageCount++
	}
	return messages, nil
}

// extractGRPC feeds the HTTP/2 frame parser, then passes each DATA frame
// body through the gRPC length-prefixed message parser.
// gRPC trailers (END_STREAM HEADERS with grpc-status) yield a final message
// with GRPCStatus populated.
func (r *Reassembler) extractGRPC(conn *connection) ([]Message, error) {
	if conn.http2Parser == nil || conn.grpcParser == nil {
		return nil, fmt.Errorf("gRPC parsers not initialised for sock_ptr=%d", conn.Key.SockPtr)
	}

	data := conn.http2Buf.Bytes()
	if len(data) == 0 {
		return nil, nil
	}

	h2msgs, remaining, err := conn.http2Parser.ParseFrames(data)
	if err != nil {
		return nil, fmt.Errorf("gRPC HTTP/2 parse error: %w", err)
	}

	conn.http2Buf.Reset()
	if len(remaining) > 0 {
		conn.http2Buf.Write(remaining)
	}

	var messages []Message
	for _, h2msg := range h2msgs {
		// gRPC trailers have END_STREAM headers and no body
		if h2msg.IsEndStream && len(h2msg.Body) == 0 {
			grpcStatus, _, _ := conn.grpcParser.ParseTrailers(h2msg.Headers)
			messages = append(messages, Message{
				Data:     serializeGRPCTrailer(h2msg),
				Protocol: events.ProtoGRPC,
				Metadata: MessageMetadata{
					StreamID:    h2msg.StreamID,
					IsEndStream: true,
					IsRequest:   false, // trailers are always server-side
					GRPCStatus:  grpcStatus,
				},
			})
			conn.MessageCount++
			continue
		}

		if len(h2msg.Body) == 0 {
			continue 
		}

		grpcMsg, _, err := conn.grpcParser.ParseMessage(h2msg.Body, h2msg.Headers)
		if err != nil {
			slog.Debug("gRPC message parse error",
				"sock_ptr", conn.Key.SockPtr,
				"stream_id", h2msg.StreamID,
				"error", err,
			)
			continue
		}

		// Extract trailer status even when END_STREAM is on a DATA frame
		grpcStatus := ""
		if h2msg.IsEndStream {
			grpcStatus, _, _ = conn.grpcParser.ParseTrailers(h2msg.Headers)
		}

		messages = append(messages, Message{
			Data:     serializeGRPCMessage(grpcMsg),
			Protocol: events.ProtoGRPC,
			Metadata: MessageMetadata{
				StreamID:    h2msg.StreamID,
				IsEndStream: h2msg.IsEndStream,
				IsRequest:   grpcMsg.IsRequest,
				Service:     grpcMsg.ServiceName,
				Method:      grpcMsg.MethodName,
				GRPCStatus:  grpcStatus,
			},
		})
		conn.MessageCount++
	}
	return messages, nil
}

// recoverFromError tries to re-sync the HTTP/1 buffer to the next message
// boundary. For HTTP/2 and gRPC, we reset the http2Buf and the parser - HPACK state is lost 
func (r *Reassembler) recoverFromError(conn *connection, _ error) {
	switch conn.Protocol {
	case events.ProtoHTTP1:
		if conn.http1Buf == nil {
			return
		}
		skip := findNextHTTP1Boundary(conn.http1Buf.Bytes())
		if skip > 0 {
			conn.http1Buf.Next(skip)
			slog.Debug("HTTP/1 parse recovery: skipped bytes",
				"sock_ptr", conn.Key.SockPtr,
				"bytes_skipped", skip,
			)
		} else {
			conn.http1Buf.Reset()
			slog.Debug("HTTP/1 parse recovery: buffer reset",
				"sock_ptr", conn.Key.SockPtr,
			)
		}
	case events.ProtoHTTP2, events.ProtoGRPC:
		if conn.http2Buf != nil {
			conn.http2Buf.Reset()
		}
		// Re-initialise parser — HPACK state is lost but avoids stuck state
		conn.http2Parser = http2.NewParser()
		slog.Debug("HTTP/2 parser reset after error",
			"sock_ptr", conn.Key.SockPtr,
		)
	}
}

func (r *Reassembler) cleanupLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		r.cleanup()
	}
}

func (r *Reassembler) cleanup() {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	cleaned := 0

	for key, conn := range r.conns {
		conn.mu.Lock()
		var shouldDelete bool
		var reason CleanupReason

		if conn.Closed {
			shouldDelete = true
			reason = ReasonClosed
		} else if now.Sub(conn.LastSeen) > r.timeout {
			shouldDelete = true
			reason = ReasonTimeout
		}
		conn.mu.Unlock()

		if shouldDelete {
			delete(r.conns, key)
			cleaned++
			r.statsMu.Lock()
			r.stats.ActiveConnections--
			r.stats.CleanupByReason[reason]++
			r.statsMu.Unlock()
		}
	}

	if cleaned > 0 {
		slog.Debug("Reassembler cleanup", "removed_connections", cleaned)
	}
}

func (r *Reassembler) statsLoop() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		r.statsMu.RLock()
		s := r.stats
		r.statsMu.RUnlock()
		slog.Info("Reassembler statistics",
			"active_connections", s.ActiveConnections,
			"total_connections", s.TotalConnections,
			"completed_messages", s.CompletedMessages,
			"dropped_messages", s.DroppedMessages,
			"parse_errors", s.ParseErrors,
			"bytes_processed", s.BytesProcessed,
		)
	}
}


// http1Methods is the ordered list used for request-line detection.
// "HTTP/" detects responses.
var http1RequestPrefixes = [][]byte{
	[]byte("GET "), []byte("POST "), []byte("PUT "), []byte("DELETE "),
	[]byte("PATCH "), []byte("HEAD "), []byte("OPTIONS "), []byte("CONNECT "),
	[]byte("TRACE "),
}

// detectHTTP1Method returns the HTTP method and true if buf starts with a
// request line, or ("", false) if not a request.
func detectHTTP1Method(buf []byte) (string, bool) {
	for _, prefix := range http1RequestPrefixes {
		if bytes.HasPrefix(bytes.ToUpper(buf), prefix) {
			// Extract method from first token (strip the trailing space)
			return strings.TrimSpace(string(prefix)), true
		}
	}
	return "", false
}

func findNextHTTP1Boundary(buf []byte) int {
	patterns := [][]byte{
		[]byte("GET "), []byte("POST "), []byte("PUT "), []byte("DELETE "),
		[]byte("PATCH "), []byte("HEAD "), []byte("OPTIONS "), []byte("HTTP/"),
	}
	best := -1
	for _, p := range patterns {
		// Start search at offset 1 to skip the current broken message head
		if idx := bytes.Index(buf[1:], p); idx >= 0 {
			actual := idx + 1
			if best < 0 || actual < best {
				best = actual
			}
		}
	}
	if best > 0 {
		return best
	}
	return 0
}

// getContentLength parses the Content-Length header value from raw headers.
func getContentLength(headers []byte) int {
	for line := range bytes.SplitSeq(headers, []byte("\r\n")) {
		if bytes.HasPrefix(bytes.ToLower(line), []byte("content-length:")) {
			parts := bytes.SplitN(line, []byte(":"), 2)
			if len(parts) == 2 {
				n, err := strconv.Atoi(strings.TrimSpace(string(parts[1])))
				if err == nil {
					return n
				}
			}
		}
	}
	return 0
}

// isChunkedEncoding returns true when Transfer-Encoding: chunked is present.
func isChunkedEncoding(headers []byte) bool {
	for line := range bytes.SplitSeq(headers, []byte("\r\n")) {
		if bytes.HasPrefix(bytes.ToLower(line), []byte("transfer-encoding:")) {
			return bytes.Contains(bytes.ToLower(line), []byte("chunked"))
		}
	}
	return false
}

// findChunkedEnd locates the end of a complete chunked HTTP/1.1 body.
// Returns the total byte count (headers + all chunks + trailing CRLF) or -1
// if the body is incomplete.
func findChunkedEnd(buf []byte) int {
	// Find where the body starts (after \r\n\r\n)
	sepIdx := bytes.Index(buf, []byte("\r\n\r\n"))
	if sepIdx < 0 {
		return -1
	}
	idx := sepIdx + 4 // start of chunked body

	for {
		end := bytes.Index(buf[idx:], []byte("\r\n"))
		if end < 0 {
			return -1
		}
		sizeStr := string(buf[idx : idx+end])
		if semi := strings.IndexByte(sizeStr, ';'); semi >= 0 {
			sizeStr = sizeStr[:semi]
		}
		sizeStr = strings.TrimSpace(sizeStr)
		size, err := strconv.ParseInt(sizeStr, 16, 64)
		if err != nil {
			return -1
		}
		idx += end + 2 // skip size line + CRLF

		if size == 0 {
			trailerEnd := bytes.Index(buf[idx:], []byte("\r\n"))
			if trailerEnd < 0 {
				if bytes.HasPrefix(buf[idx:], []byte("\r\n")) {
					return idx + 2
				}
				return -1
			}
			return idx + trailerEnd + 4 // account for the final CRLF
		}

		idx += int(size) + 2
		if idx > len(buf) {
			return -1
		}
	}
}
