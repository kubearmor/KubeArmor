// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package dissector

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/kubearmor/KubeArmor/KubeArmor/apiObserver/events"
	"github.com/kubearmor/KubeArmor/KubeArmor/apiObserver/protocols/grpc"
)

// ============================================================================
// TlsStreamAssembler — timestamp-sorted TLS chunk reassembly
// ============================================================================

// TlsStreamAssembler receives TLS plaintext chunks from the TlsPoller and
// delivers them as ordered byte streams to per-connection HTTP/2 parser
// goroutines. It solves the HPACK corruption problem by:
//
//  1. Sorting chunks by BPF timestamp (bpf_ktime_get_ns — globally monotonic
//     across CPUs) before delivery, restoring cross-CPU ordering.
//  2. Using io.Pipe to provide a blocking io.Reader to http2.Framer, which
//     naturally handles partial frames without manual buffer management.
//  3. Maintaining one HPACK decoder per direction per connection, never reset
//     except on connection preface or pipe close.
type TlsStreamAssembler struct {
	mu        sync.Mutex
	conns     map[string]*asmConn // key = connKey()
	dissector *Dissector
	log       Logger

	// flushInterval controls how long chunks are buffered before being
	// sorted and delivered. Shorter = lower latency, longer = better ordering.
	flushInterval time.Duration
}

// asmConn is the per-TCP-connection state for the assembler.
type asmConn struct {
	key  string
	info streamInfo // connection metadata from first chunk

	// Per-direction pipes. Writer side is fed by sorted chunks;
	// reader side is consumed by the parser goroutine's http2.Framer.
	reqWriter  *io.PipeWriter
	reqReader  *io.PipeReader
	respWriter *io.PipeWriter
	respReader *io.PipeReader

	// HTTP/2 stream tracking — shared between both parser goroutines.
	// Protected by mu.
	streams map[uint32]*h2AsmStream

	// Pending chunks awaiting timestamp-sorted flush.
	mu      sync.Mutex
	pending []*asmChunk

	// lastSeen tracks activity for GC.
	lastSeen time.Time

	// closed is set when the connection's pipes are closed.
	closed bool
}

// asmChunk is a chunk waiting to be sorted and flushed.
type asmChunk struct {
	timestamp uint64 // BPF ktime_get_ns
	start     uint32 // byte offset within the syscall
	data      []byte
	isRequest bool
	info      streamInfo
	wallClock time.Time // When this chunk arrived in the assembler
}

// newTlsStreamAssembler creates and starts a TlsStreamAssembler.
func newTlsStreamAssembler(d *Dissector) *TlsStreamAssembler {
	asm := &TlsStreamAssembler{
		conns:         make(map[string]*asmConn),
		dissector:     d,
		log:           d.log,
		flushInterval: 5 * time.Millisecond,
	}
	// Background flusher: periodically sorts and delivers buffered chunks.
	go asm.flushLoop()
	// Background GC: evict connections idle for >5 minutes.
	go asm.gcLoop()
	return asm
}

// Deliver accepts a TLS chunk and buffers it for timestamp-sorted delivery.
func (asm *TlsStreamAssembler) Deliver(chunk *events.TlsChunkEvent, info streamInfo) {
	if len(chunk.Data) == 0 {
		return
	}

	key := asm.connKey(chunk)
	isRequest := (chunk.IsClient() && !chunk.IsRead()) || (!chunk.IsClient() && chunk.IsRead())

	const h2Preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
	hasPreface := bytes.HasPrefix(chunk.Data, []byte(h2Preface))

	asm.mu.Lock()
	conn, exists := asm.conns[key]

	if exists && hasPreface {
		asm.log.Printf("[TLS-ASM] HTTP/2 preface detected on key=%s — resetting connection", key)
		// Close old connection pipes to stop its parsers
		conn.mu.Lock()
		conn.closed = true
		conn.mu.Unlock()
		conn.reqWriter.Close()
		conn.respWriter.Close()
		
		exists = false
	}

	if !exists {
		conn = asm.newConn(key, info)
		asm.conns[key] = conn
	}
	asm.mu.Unlock()

	now := time.Now()

	if hasPreface {
		// Strip preface, deliver remaining data if any
		remaining := chunk.Data[len(h2Preface):]
		if len(remaining) > 0 {
			conn.mu.Lock()
			conn.pending = append(conn.pending, &asmChunk{
				timestamp: chunk.Timestamp,
				start:     chunk.Start,
				data:      remaining,
				isRequest: isRequest,
				info:      info,
				wallClock: now,
			})
			conn.lastSeen = now
			conn.mu.Unlock()
		}
		return
	}

	conn.mu.Lock()
	conn.pending = append(conn.pending, &asmChunk{
		timestamp: chunk.Timestamp,
		start:     chunk.Start,
		data:      chunk.Data,
		isRequest: isRequest,
		info:      info,
		wallClock: now,
	})
	conn.lastSeen = now
	conn.mu.Unlock()
}

// connKey builds a stable connection key from chunk addresses.
// Uses the same convention as streamInfo.connKey() but for TLS chunks
// where direction is always 0 (addresses come from struct sock: src=local, dst=remote).
func (asm *TlsStreamAssembler) connKey(chunk *events.TlsChunkEvent) string {
	return fmt.Sprintf("%s:%d>%s:%d",
		chunk.SrcIPString(), chunk.SrcPort,
		chunk.DstIPString(), chunk.DstPort)
}

// newConn creates a new assembled connection with pipe pairs and starts
// parser goroutines for both directions.
func (asm *TlsStreamAssembler) newConn(key string, info streamInfo) *asmConn {
	reqReader, reqWriter := io.Pipe()
	respReader, respWriter := io.Pipe()

	conn := &asmConn{
		key:        key,
		info:       info,
		reqWriter:  reqWriter,
		reqReader:  reqReader,
		respWriter: respWriter,
		respReader: respReader,
		streams:    make(map[uint32]*h2AsmStream),
		lastSeen:   time.Now(),
	}

	asm.log.Printf("[TLS-ASM] new connection key=%s src=%s:%d dst=%s:%d",
		key, info.srcIP, info.srcPort, info.dstIP, info.dstPort)

	// Start parser goroutines — one per direction.
	go asm.parseH2Stream(conn, reqReader, true)  // client→server (requests)
	go asm.parseH2Stream(conn, respReader, false) // server→client (responses)

	return conn
}

// resetConn closes and removes an existing connection.
func (asm *TlsStreamAssembler) resetConn(key string) {
	asm.mu.Lock()
	conn, exists := asm.conns[key]
	if exists {
		delete(asm.conns, key)
	}
	asm.mu.Unlock()

	if exists && conn != nil {
		conn.mu.Lock()
		conn.closed = true
		conn.mu.Unlock()
		conn.reqWriter.Close()
		conn.respWriter.Close()
	}
}

// flushLoop periodically sorts and delivers buffered chunks to pipes.
func (asm *TlsStreamAssembler) flushLoop() {
	ticker := time.NewTicker(asm.flushInterval)
	defer ticker.Stop()
	for range ticker.C {
		asm.flushAll()
	}
}

// flushAll sorts and delivers pending chunks for all connections.
func (asm *TlsStreamAssembler) flushAll() {
	asm.mu.Lock()
	keys := make([]string, 0, len(asm.conns))
	for k := range asm.conns {
		keys = append(keys, k)
	}
	asm.mu.Unlock()

	for _, key := range keys {
		asm.mu.Lock()
		conn, exists := asm.conns[key]
		asm.mu.Unlock()
		if !exists {
			continue
		}
		asm.flushConn(conn)
	}
}

// flushConn sorts pending chunks by BPF timestamp and writes them to pipes.
func (asm *TlsStreamAssembler) flushConn(conn *asmConn) {
	conn.mu.Lock()
	if len(conn.pending) == 0 || conn.closed {
		conn.mu.Unlock()
		return
	}

	now := time.Now()
	// Wait 50ms before flushing to ensure chunks from all CPUs have arrived.
	flushAge := 50 * time.Millisecond

	// 1. Sort ALL pending chunks by BPF timestamp, then by Start offset.
	// We use SliceStable to preserve arrival order for chunks with identical timestamps.
	chunks := conn.pending
	sort.SliceStable(chunks, func(i, j int) bool {
		if chunks[i].timestamp == chunks[j].timestamp {
			return chunks[i].start < chunks[j].start
		}
		return chunks[i].timestamp < chunks[j].timestamp
	})

	// 2. Iterate from the front. We can only flush a chunk if it has waited >= 50ms.
	// If we encounter a chunk that hasn't waited 50ms, we MUST STOP, because
	// flushing anything after it would violate BPF timestamp order.
	var toFlush []*asmChunk
	var remaining []*asmChunk

	for i, c := range chunks {
		if now.Sub(c.wallClock) >= flushAge {
			toFlush = append(toFlush, c)
		} else {
			// This chunk (and all chunks after it, which have newer timestamps)
			// must wait.
			remaining = chunks[i:]
			break
		}
	}

	if len(toFlush) == 0 {
		conn.mu.Unlock()
		return
	}

	conn.pending = remaining
	conn.mu.Unlock()

	// Deliver to the appropriate pipe in strictly sorted order.
	for _, c := range toFlush {
		var w *io.PipeWriter
		if c.isRequest {
			w = conn.reqWriter
		} else {
			w = conn.respWriter
		}

		_, err := w.Write(c.data)
		if err != nil {
			// Pipe closed — connection was reset or GC'd.
			asm.log.Printf("[TLS-ASM] write error on key=%s isRequest=%v: %v", conn.key, c.isRequest, err)
			return
		}
	}
}

// gcLoop evicts connections idle for >5 minutes.
func (asm *TlsStreamAssembler) gcLoop() {
	ticker := time.NewTicker(2 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		cutoff := time.Now().Add(-5 * time.Minute)
		asm.mu.Lock()
		var stale []string
		for key, conn := range asm.conns {
			conn.mu.Lock()
			if conn.lastSeen.Before(cutoff) {
				stale = append(stale, key)
			}
			conn.mu.Unlock()
		}
		asm.mu.Unlock()

		for _, key := range stale {
			asm.log.Printf("[TLS-ASM] GC: evicting stale connection key=%s", key)
			asm.resetConn(key)
		}
	}
}

// ============================================================================
// HTTP/2 parser goroutine — reads from io.PipeReader using http2.Framer
// ============================================================================

// parseH2Stream is the per-direction parser goroutine. It reads from the pipe
// using an http2.Framer with ReadMetaHeaders set to an hpack.Decoder.
// Because the pipe delivers bytes in timestamp-sorted order, the HPACK decoder
// stays perfectly in sync with the encoder's state.
func (asm *TlsStreamAssembler) parseH2Stream(conn *asmConn, reader *io.PipeReader, isRequest bool) {
	dirStr := "response"
	if isRequest {
		dirStr = "request"
	}
	asm.log.Printf("[TLS-ASM] parser goroutine started for key=%s dir=%s", conn.key, dirStr)

	dec := hpack.NewDecoder(4096, nil)

	// Use a bufio.Reader to allow peeking without consuming.
	bufReader := newFrameReader(reader)

	for {
		// Read the 9-byte frame header first to determine frame length.
		headerBuf, err := bufReader.Peek(h2FrameHeaderSize)
		if err != nil {
			if err == io.EOF || err == io.ErrClosedPipe {
				asm.log.Printf("[TLS-ASM] parser goroutine exiting for key=%s dir=%s: %v", conn.key, dirStr, err)
			} else {
				asm.log.Printf("[TLS-ASM] parser read error for key=%s dir=%s: %v", conn.key, dirStr, err)
			}
			return
		}

		// Parse frame payload length from the 3-byte big-endian field.
		framePayloadLen := int(uint32(headerBuf[0])<<16 | uint32(headerBuf[1])<<8 | uint32(headerBuf[2]))

		// Sanity check: reject obviously corrupt frame lengths.
		const maxAllowedFramePayload = 1 << 20 // 1 MB
		if framePayloadLen > maxAllowedFramePayload {
			asm.log.Printf("[TLS-ASM] oversized frame payload (%d bytes) on key=%s dir=%s — resetting decoder",
				framePayloadLen, conn.key, dirStr)
			// Discard all buffered data and reset decoder.
			dec = hpack.NewDecoder(4096, nil)
			bufReader.Discard(bufReader.Buffered())
			continue
		}

		totalFrameLen := h2FrameHeaderSize + framePayloadLen

		// Read the complete frame.
		frameBytes := make([]byte, totalFrameLen)
		_, err = io.ReadFull(bufReader, frameBytes)
		if err != nil {
			if err == io.EOF || err == io.ErrClosedPipe || err == io.ErrUnexpectedEOF {
				asm.log.Printf("[TLS-ASM] parser goroutine exiting for key=%s dir=%s: %v", conn.key, dirStr, err)
			} else {
				asm.log.Printf("[TLS-ASM] parser frame read error for key=%s dir=%s: %v", conn.key, dirStr, err)
			}
			return
		}

		// Create a one-shot Framer to parse this complete frame.
		framer := http2.NewFramer(io.Discard, bytes.NewReader(frameBytes))
		framer.ReadMetaHeaders = dec

		frame, err := framer.ReadFrame()
		if err != nil {
			asm.log.Printf("[TLS-ASM] frame parse error on key=%s dir=%s: %v — resetting HPACK",
				conn.key, dirStr, err)
			dec = hpack.NewDecoder(4096, nil)
			continue
		}

		asm.processFrame(conn, frame, isRequest)
	}
}

// processFrame dispatches a parsed HTTP/2 frame to the appropriate handler,
// accumulating state in the shared h2AsmConn.
func (asm *TlsStreamAssembler) processFrame(conn *asmConn, frame http2.Frame, isRequest bool) {
	switch f := frame.(type) {
	case *http2.MetaHeadersFrame:
		asm.processHeaders(conn, f, isRequest)
	case *http2.DataFrame:
		asm.processData(conn, f, isRequest)
	case *http2.RSTStreamFrame:
		conn.mu.Lock()
		if s, ok := conn.streams[f.StreamID]; ok {
			asm.emitEvent(s, conn)
			delete(conn.streams, f.StreamID)
		}
		conn.mu.Unlock()
	case *http2.SettingsFrame:
		// SETTINGS frames are connection-level control; log but don't process.
		asm.log.Printf("[TLS-ASM] SETTINGS frame on key=%s isRequest=%v ack=%v",
			conn.key, isRequest, f.IsAck())
	}
}

// ============================================================================
// H2 stream state (per HTTP/2 stream ID within a connection)
// ============================================================================

// h2AsmStream tracks a single HTTP/2 stream within an assembled connection.
type h2AsmStream struct {
	ts               time.Time
	srcIP, dstIP     string
	srcPort, dstPort uint16
	cgroupID         uint64
	isSSL            bool

	reqMethod    string
	reqPath      string
	reqAuthority string
	reqHdrs      map[string]string
	respStatus   string
	respHdrs     map[string]string
	contentType  string
	grpcService  string
	grpcMethod   string
	grpcStatus   int32
	grpcMessage  string

	reqBodyBuf  bytes.Buffer
	respBodyBuf bytes.Buffer
}

// getOrCreateStream returns the h2AsmStream for the given stream ID, creating one if needed.
// Must be called with conn.mu held.
func (conn *asmConn) getOrCreateStream(sid uint32, info streamInfo) *h2AsmStream {
	if conn.streams == nil {
		conn.streams = make(map[uint32]*h2AsmStream)
	}
	s, ok := conn.streams[sid]
	if !ok {
		s = &h2AsmStream{
			ts:       info.timestamp,
			srcIP:    info.srcIP, dstIP: info.dstIP,
			srcPort:  info.srcPort, dstPort: info.dstPort,
			cgroupID: info.cgroupID,
			isSSL:    info.isSSL,
			reqHdrs:  make(map[string]string),
			respHdrs: make(map[string]string),
		}
		conn.streams[sid] = s
	}
	return s
}

func (asm *TlsStreamAssembler) processHeaders(conn *asmConn, f *http2.MetaHeadersFrame, isRequest bool) {
	sid := f.StreamID

	conn.mu.Lock()
	defer conn.mu.Unlock()

	s := conn.getOrCreateStream(sid, conn.info)

	// Determine if request or response from frame content.
	isReqFrame := false
	for _, hf := range f.Fields {
		if hf.Name == ":method" {
			isReqFrame = true
			break
		}
		if hf.Name == ":status" {
			isReqFrame = false
			break
		}
	}

	asm.log.Printf("[TLS-ASM] HEADERS key=%s streamID=%d isReqFrame=%v endStream=%v fields=%d",
		conn.key, sid, isReqFrame, f.StreamEnded(), len(f.Fields))

	if isReqFrame {
		for _, hf := range f.Fields {
			switch hf.Name {
			case ":method":
				s.reqMethod = hf.Value
			case ":path":
				s.reqPath = hf.Value
			case ":authority":
				s.reqAuthority = hf.Value
			case "content-type":
				s.contentType = hf.Value
				if strings.HasPrefix(hf.Value, "application/grpc") {
					parts := strings.SplitN(s.reqPath, "/", 3)
					if len(parts) == 3 {
						s.grpcService = parts[1]
						s.grpcMethod = parts[2]
					}
				}
			default:
				s.reqHdrs[hf.Name] = hf.Value
			}
		}
	} else {
		for _, hf := range f.Fields {
			switch hf.Name {
			case ":status":
				s.respStatus = hf.Value
			case "grpc-status":
				if code, err := strconv.ParseInt(hf.Value, 10, 32); err == nil {
					s.grpcStatus = int32(code)
				}
			case "grpc-message":
				s.grpcMessage = hf.Value
			default:
				s.respHdrs[hf.Name] = hf.Value
			}
		}
		if f.StreamEnded() {
			asm.emitEvent(s, conn)
			delete(conn.streams, sid)
		}
	}
}

func (asm *TlsStreamAssembler) processData(conn *asmConn, f *http2.DataFrame, isRequest bool) {
	conn.mu.Lock()
	defer conn.mu.Unlock()

	s, ok := conn.streams[f.StreamID]
	if !ok {
		return
	}

	data := f.Data()
	maxBody := asm.dissector.cfg.MaxBodySize

	asm.log.Printf("[TLS-ASM] DATA key=%s streamID=%d isRequest=%v len=%d endStream=%v",
		conn.key, f.StreamID, isRequest, len(data), f.StreamEnded())

	if isRequest {
		if s.reqBodyBuf.Len() < maxBody {
			s.reqBodyBuf.Write(data)
		}
	} else {
		if s.respBodyBuf.Len() < maxBody {
			s.respBodyBuf.Write(data)
		}
		if f.StreamEnded() {
			asm.emitEvent(s, conn)
			delete(conn.streams, f.StreamID)
		}
	}
}

// emitEvent builds and delivers a pb.APIEvent for a completed HTTP/2 stream.
// Must be called with conn.mu held.
func (asm *TlsStreamAssembler) emitEvent(s *h2AsmStream, conn *asmConn) {
	if s.reqMethod == "" && s.reqPath == "" {
		asm.log.Printf("[TLS-ASM] DROP incomplete stream key=%s (no method or path)", conn.key)
		return
	}

	d := asm.dissector
	dstLabel := s.dstIP
	if fqdn := d.svcFn(dstLabel); fqdn != "" {
		dstLabel = fqdn
	}
	proto := "HTTP/2"
	if strings.HasPrefix(s.contentType, "application/grpc") {
		proto = "gRPC"
	}

	statusCode := int32(0)
	if s.respStatus != "" {
		if code, err := strconv.ParseInt(s.respStatus, 10, 32); err == nil {
			statusCode = int32(code)
		}
	}

	reqHdrs := s.reqHdrs
	if reqHdrs == nil {
		reqHdrs = make(map[string]string)
	}
	if s.reqMethod != "" {
		reqHdrs[":method"] = s.reqMethod
	}
	if s.reqPath != "" {
		reqHdrs[":path"] = s.reqPath
	}
	if s.reqAuthority != "" {
		reqHdrs[":authority"] = s.reqAuthority
	}
	reqHdrs[":scheme"] = "https" // always TLS in this path

	respHdrs := s.respHdrs
	if respHdrs == nil {
		respHdrs = make(map[string]string)
	}
	if s.respStatus != "" {
		respHdrs[":status"] = s.respStatus
	}

	grpcMsg := s.grpcMessage
	if grpcMsg == "" && s.grpcStatus == 0 && strings.HasPrefix(s.contentType, "application/grpc") {
		grpcMsg = "OK"
	}

	reqBodyStr := s.reqBodyBuf.String()
	respBodyStr := s.respBodyBuf.String()

	isGrpc := strings.HasPrefix(s.contentType, "application/grpc")
	if isGrpc {
		reqBody := s.reqBodyBuf.Bytes()
		if len(reqBody) > 0 {
			parser := grpc.NewParser()
			msg, _, err := parser.ParseMessage(reqBody, reqHdrs)
			if err == nil && msg != nil && msg.Body != "" {
				reqBodyStr = msg.Body
			} else {
				reqBodyStr = base64.StdEncoding.EncodeToString(reqBody)
			}
		}
		respBody := s.respBodyBuf.Bytes()
		if len(respBody) > 0 {
			parser := grpc.NewParser()
			msg, _, err := parser.ParseMessage(respBody, respHdrs)
			if err == nil && msg != nil && msg.Body != "" {
				respBodyStr = msg.Body
			} else {
				respBodyStr = base64.StdEncoding.EncodeToString(respBody)
			}
		}
	} else {
		if s.reqBodyBuf.Len() > 0 {
			reqBodyStr = base64.StdEncoding.EncodeToString(s.reqBodyBuf.Bytes())
		}
		if s.respBodyBuf.Len() > 0 {
			respBodyStr = base64.StdEncoding.EncodeToString(s.respBodyBuf.Bytes())
		}
	}

	evt := d.buildH2APIEvent(s.ts, s.srcIP, s.dstIP, dstLabel, s.srcPort, s.dstPort,
		s.cgroupID, true, /* isSSL */
		s.reqMethod, s.reqPath, s.contentType,
		reqHdrs, respHdrs,
		reqBodyStr, respBodyStr,
		statusCode, proto,
		s.grpcService, s.grpcMethod, s.grpcStatus, grpcMsg)

	if d.handler != nil {
		asm.log.Printf("[TLS-ASM] EMIT proto=%s method=%s path=%s status=%s src=%s:%d dst=%s:%d",
			proto, s.reqMethod, s.reqPath, s.respStatus,
			s.srcIP, s.srcPort, s.dstIP, s.dstPort)
		d.handler(evt)
	}
}

// ============================================================================
// frameReader — bufio.Reader wrapper for h2 frame parsing
// ============================================================================

// frameReader wraps an io.Reader with buffered peeking capability needed
// to inspect the 9-byte HTTP/2 frame header before reading the full frame.
type frameReader struct {
	buf    []byte
	pos    int
	end    int
	reader io.Reader
}

func newFrameReader(r io.Reader) *frameReader {
	return &frameReader{
		buf:    make([]byte, 64*1024), // 64KB buffer
		reader: r,
	}
}

// Peek returns the next n bytes without advancing the reader.
// Blocks until n bytes are available or an error occurs.
func (fr *frameReader) Peek(n int) ([]byte, error) {
	for fr.end-fr.pos < n {
		if fr.pos > 0 {
			copy(fr.buf, fr.buf[fr.pos:fr.end])
			fr.end -= fr.pos
			fr.pos = 0
		}
		if fr.end+4096 > len(fr.buf) {
			newBuf := make([]byte, len(fr.buf)*2)
			copy(newBuf, fr.buf[:fr.end])
			fr.buf = newBuf
		}
		nr, err := fr.reader.Read(fr.buf[fr.end:])
		fr.end += nr
		if err != nil {
			if fr.end-fr.pos >= n {
				break
			}
			return nil, err
		}
	}
	return fr.buf[fr.pos : fr.pos+n], nil
}

// Read implements io.Reader.
func (fr *frameReader) Read(p []byte) (int, error) {
	if fr.pos >= fr.end {
		// Buffer empty — read directly.
		return fr.reader.Read(p)
	}
	n := copy(p, fr.buf[fr.pos:fr.end])
	fr.pos += n
	return n, nil
}

// Buffered returns the number of buffered bytes available.
func (fr *frameReader) Buffered() int {
	return fr.end - fr.pos
}

// Discard skips up to n buffered bytes.
func (fr *frameReader) Discard(n int) {
	avail := fr.end - fr.pos
	if n > avail {
		n = avail
	}
	fr.pos += n
}
