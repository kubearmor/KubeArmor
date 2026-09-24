// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package dissector

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	pb "github.com/accuknox/SentryFlow/protobuf/golang"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/kubearmor/KubeArmor/KubeArmor/apiObserver/events"
	"github.com/kubearmor/KubeArmor/KubeArmor/apiObserver/poller"
	"github.com/kubearmor/KubeArmor/KubeArmor/apiObserver/protocols/grpc"
	fd "github.com/kubearmor/KubeArmor/KubeArmor/feeder"
)

// bufioReaderPool reuses *bufio.Reader instances across HTTP/1 parse calls
// to reduce allocations on the hot path.
var bufioReaderPool = sync.Pool{
	New: func() any { return bufio.NewReader(nil) },
}

// Handler is called with every correlated API event produced by the dissector.
type Handler func(evt *pb.APIEvent)

// Logger is the logging interface used by the Dissector for debug output.
type Logger interface {
	Printf(format string, args ...interface{})
}

// Config holds configuration for the Dissector.
type Config struct {
	// MaxBodySize caps the payload captured in pb.APIEvent request/response bodies.
	MaxBodySize int
	// NodeName is embedded in pb.Metadata.
	NodeName string
}

// DefaultConfig returns sensible defaults.
func DefaultConfig() Config {
	return Config{
		MaxBodySize: 4096,
	}
}

// Dissector is the core packet dissection component.
// It accepts raw packets and TLS chunks, performs TCP stream reassembly,
// and produces correlated HTTP/gRPC API events.
type Dissector struct {
	handler Handler
	cfg     Config
	svcFn   func(string) string // ClusterIP → FQDN resolver
	log     *fd.Feeder
	stop    chan struct{} // closed by Close() to stop background goroutines

	// HTTP/1 streams: key = "srcIP:srcPort>dstIP:dstPort"
	h1mu      sync.Mutex
	h1streams map[string]*h1Stream

	// HTTP/2 connections: key = connection ID → per-stream-ID state
	// Used by the raw-packet (non-TLS) path only.
	h2mu    sync.Mutex
	h2conns map[string]*h2Conn

	// TLS stream assembler: handles TLS HTTP/2 traffic with
	// timestamp-sorted chunk delivery and per-direction HPACK decoders.
	tlsAsm *TlsStreamAssembler
}

// New creates a Dissector.
// handler is called with every pb.APIEvent produced. svcResolver maps a
// destination ClusterIP to its K8s FQDN (may be nil).
func New(handler Handler, svcResolver func(string) string, logger *fd.Feeder, cfg Config) *Dissector {
	if svcResolver == nil {
		svcResolver = func(ip string) string { return "" }
	}

	d := &Dissector{
		handler:   handler,
		cfg:       cfg,
		svcFn:     svcResolver,
		log:       logger,
		h1streams: make(map[string]*h1Stream),
		h2conns:   make(map[string]*h2Conn),
		stop:      make(chan struct{}),
	}
	// TLS stream assembler for HTTP/2 over TLS with ordered chunk delivery.
	d.tlsAsm = newTlsStreamAssembler(d)
	// Background GC: evict h2Conn entries whose reassembly buffers have been
	// idle for more than 5 minutes. This prevents unbounded memory growth from
	// connections closed without a TCP FIN (e.g. pod restarts).
	go func() {
		ticker := time.NewTicker(2 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				d.gcStaleH2Conns(5 * time.Minute)
			case <-d.stop:
				return
			}
		}
	}()
	return d
}

// Close stops background goroutines. Must be called when the Dissector is
// no longer needed to prevent goroutine leaks.
func (d *Dissector) Close() {
	select {
	case <-d.stop:
		// Already closed.
	default:
		close(d.stop)
	}
}

// HandleRawPacket processes a packet from the PacketsPoller (plain traffic).
// It extracts TCP payload bytes and routes them to the appropriate stream
// reassembler based on detected protocol.
func (d *Dissector) HandleRawPacket(pkt *poller.RawPacket) {
	info, payload, err := extractTransportPayload(pkt)
	if err != nil {
		return // non-TCP/UDP or unsupported — expected and normal
	}

	// TCP SYN or SYN+ACK means a new connection is being established.
	// Reset any stale HTTP/2 or HTTP/1 state for this connKey to prevent
	// old HPACK dynamic table entries from corrupting the new connection.
	// (TCP port reuse causes old h2Conn objects to persist with stale state.)
	if pkt.IsTCPSyn() {
		key := info.connKey()
		d.h2mu.Lock()
		delete(d.h2conns, key)
		d.h2mu.Unlock()
		d.h1mu.Lock()
		delete(d.h1streams, key)
		d.h1mu.Unlock()
		return // SYN has no payload; nothing more to do
	}

	if len(payload) == 0 {
		return // TCP ACK — no payload
	}

	// Skip loopback traffic (127.0.0.0/8) on the plain-packet path.
	// Loopback HTTPS (e.g. kubelet :10250) produces raw encrypted TLS records
	// that cannot be HTTP-parsed and flood the log with noise. The TLS uprobe
	// path handles decrypted plaintext for these connections if needed.
	if isLoopbackIP(info.srcIP) || isLoopbackIP(info.dstIP) {
		return
	}

	// Drop raw TLS wire records. The cgroup_skb BPF program captures ALL TCP
	// payload, including HTTPS connections where the payload is ciphertext.
	// TLS records start with a ContentType byte:
	//   0x14 = ChangeCipherSpec
	//   0x15 = Alert
	//   0x16 = Handshake
	//   0x17 = Application Data (the most common — encrypted HTTP payload)
	// followed by version bytes 0x03 0x01–0x04 (TLS 1.0–1.3).
	// These are NOT plaintext HTTP and will never parse correctly.
	// The SSL uprobe path (HandleTlsChunk) provides the decrypted plaintext.
	if isTLSRecord(payload) {
		return
	}

	if info.srcPort == 53 || info.dstPort == 53 {
		d.processDNS(info, payload)
		return
	}

	if info.proto == 17 { // UDP
		return // non-DNS UDP is ignored
	}

	d.processPayload(info, payload, false)
}

// isLoopbackIP returns true for 127.0.0.0/8 (IPv4) and ::1 (IPv6) addresses.
func isLoopbackIP(ip string) bool {
	// IPv4: 127.x.x.x
	if len(ip) >= 4 && ip[:4] == "127." {
		return true
	}
	// IPv6 loopback: ::1
	if ip == "::1" || ip == "0:0:0:0:0:0:0:1" {
		return true
	}
	return false
}

// isTLSRecord returns true if the payload looks like a raw TLS record header.
// TLS record format: [ContentType 1B][Version 2B][Length 2B][...ciphertext...]
// ContentTypes 0x14–0x17 are standard; version 0x0301–0x0304 = TLS 1.0–1.3.
func isTLSRecord(payload []byte) bool {
	if len(payload) < 3 {
		return false
	}
	ct := payload[0]
	major := payload[1]
	minor := payload[2]
	return (ct >= 0x14 && ct <= 0x17) && major == 0x03 && (minor >= 0x01 && minor <= 0x04)
}

// truncate returns up to n printable bytes from b as a string.
func truncate(b []byte, n int) string {
	if len(b) > n {
		b = b[:n]
	}
	out := make([]byte, 0, len(b))
	for _, c := range b {
		if c >= 0x20 && c < 0x7f {
			out = append(out, c)
		} else {
			out = append(out, '.')
		}
	}
	return string(out)
}

// HandleTlsChunk processes a TLS plaintext chunk from the TlsPoller.
// The chunk is already decrypted plaintext; we apply protocol dissection
// directly.
//
// For HTTP/2 traffic: delegates to the TlsStreamAssembler which sorts
// chunks by BPF timestamp and delivers them as ordered byte streams to
// per-connection HTTP/2 parser goroutines. This prevents HPACK decoder
// corruption caused by cross-CPU perf buffer reordering.
//
// For HTTP/1 traffic: uses the existing processPayload path directly
// (HTTP/1 is stateless and doesn't suffer from HPACK issues).
func (d *Dissector) HandleTlsChunk(chunk *events.TlsChunkEvent) {
	if len(chunk.Data) == 0 {
		d.log.Debugf("[TLS] DROP pid=%d fd=%d cgroupID=%d: empty data",
			chunk.PID, chunk.FD, chunk.CgroupID)
		return
	}

	// Log every TLS chunk with full metadata for diagnosis.
	dataPreview := chunk.Data
	if len(dataPreview) > 64 {
		dataPreview = dataPreview[:64]
	}
	readStr := "write(egress)"
	if chunk.IsRead() {
		readStr = "read(ingress)"
	}
	d.log.Debugf("[TLS] CHUNK pid=%d fd=%d cgroupID=%d family=%d src=%s:%d dst=%s:%d op=%s len=%d recorded=%d data=%q",
		chunk.PID, chunk.FD, chunk.CgroupID, chunk.Family,
		chunk.SrcIPString(), chunk.SrcPort,
		chunk.DstIPString(), chunk.DstPort,
		readStr, chunk.Len, chunk.Recorded, dataPreview)

	info := streamInfo{
		srcIP:     chunk.SrcIPString(),
		dstIP:     chunk.DstIPString(),
		srcPort:   chunk.SrcPort,
		dstPort:   chunk.DstPort,
		isSSL:     true,
		isRequest: (chunk.IsClient() && !chunk.IsRead()) || (!chunk.IsClient() && chunk.IsRead()),
		cgroupID:  uint64(chunk.CgroupID),
		timestamp: time.Unix(0, int64(chunk.Timestamp)),
	}

	if info.srcIP == "" && info.dstIP == "" {
		d.log.Debugf("[TLS] DROP pid=%d fd=%d: no address info (family=%d — tcp_kprobe missed this connection)",
			chunk.PID, chunk.FD, chunk.Family)
		return
	}

	// Detect protocol from the first bytes.
	proto := detectProtocol(chunk.Data)

	// Route HTTP/2 and gRPC TLS traffic through the assembler for
	// timestamp-sorted delivery that keeps HPACK decoders in sync.
	switch proto {
	case protoHTTP2, protoGRPC:
		d.log.Debugf("[TLS] PROTO detected=HTTP/2 → assembler key=%s", d.tlsAsm.connKey(chunk))
		d.tlsAsm.Deliver(chunk, info)
		return
	case protoHTTP1:
		// HTTP/1 is stateless (no HPACK) — use existing direct path.
		d.log.Debugf("[TLS] PROTO detected=HTTP/1 key=%s", info.connKey())
		d.handleHTTP1(info, chunk.Data)
		return
	}

	// protoUnknown — check if this connection is already tracked by the
	// assembler (subsequent HTTP/2 frames that don't start with PRI preface).
	asmKey := d.tlsAsm.connKey(chunk)
	d.tlsAsm.mu.Lock()
	_, isKnownAsm := d.tlsAsm.conns[asmKey]
	d.tlsAsm.mu.Unlock()

	if isKnownAsm {
		d.log.Debugf("[TLS] PROTO fragment → existing assembler conn key=%s", asmKey)
		d.tlsAsm.Deliver(chunk, info)
		return
	}

	// Fall back to HTTP/1 for unknown protocol.
	d.log.Debugf("[TLS] PROTO unknown key=%s — falling back to HTTP/1", info.connKey())
	d.handleHTTP1(info, chunk.Data)
}

// ============================================================================
// Internal stream info
// ============================================================================

// streamInfo carries connection metadata extracted from a raw packet or TLS chunk.
type streamInfo struct {
	srcIP, dstIP     string
	srcPort, dstPort uint16
	proto            uint8 // IP Protocol (e.g. 6=TCP, 17=UDP)
	isSSL            bool
	isRequest        bool  // true if payload is HTTP/1 request text (method sniff)
	direction        uint8 // pkt.Direction: 1=egress (pod→peer), 0=ingress (peer→pod)
	cgroupID         uint64
	timestamp        time.Time
}

// connKey returns a stable connection key (always pod-side-first order).
// Uses packet direction to ensure egress + ingress of the same TCP connection
// produce the same key regardless of isRequest (which is unreliable for HTTP/2
// binary frames where isHTTPRequest always returns false).
func (s streamInfo) connKey() string {
	if s.direction == 1 {
		// Egress: pod is src, peer is dst → stable key: src>dst
		return fmt.Sprintf("%s:%d>%s:%d", s.srcIP, s.srcPort, s.dstIP, s.dstPort)
	}
	// Ingress: peer is src, pod is dst → stable key: dst>src (pod-side first)
	return fmt.Sprintf("%s:%d>%s:%d", s.dstIP, s.dstPort, s.srcIP, s.srcPort)
}

// ============================================================================
// Protocol dispatch
// ============================================================================

// processPayload detects the protocol in payload and routes to the appropriate
// HTTP/1 or HTTP/2 stream handler.
func (d *Dissector) processPayload(info streamInfo, payload []byte, fromTLS bool) {
	key := info.connKey()
	proto := detectProtocol(payload)
	switch proto {
	case protoHTTP1:
		d.log.Debugf("[TLS] PROTO detected=HTTP/1 key=%s isRequest=%v fromTLS=%v payloadLen=%d",
			key, info.isRequest, fromTLS, len(payload))
		d.handleHTTP1(info, payload)
	case protoHTTP2, protoGRPC:
		d.log.Debugf("[TLS] PROTO detected=HTTP/2 key=%s isRequest=%v fromTLS=%v payloadLen=%d",
			key, info.isRequest, fromTLS, len(payload))

		if !fromTLS && len(payload) >= 24 && string(payload[:24]) == "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" {
			d.h2mu.Lock()
			conn := d.getH2Conn_locked(key)
			conn.mu.Lock()
			conn.plaintextClientDir = int(info.direction)
			conn.plaintextClientDirSet = true
			conn.mu.Unlock()
			d.h2mu.Unlock()
		}

		// gRPC is HTTP/2 + protobuf DATA frames; the HTTP/2 handler extracts
		// content-type: application/grpc and sets IsGrpc on the event.
		d.handleHTTP2(info, payload)
	default:
		// protoUnknown — this happens when:
		// (a) The payload is a binary HTTP/2 frame fragment too small (<9 bytes)
		//     to pass the frame-header heuristic, OR
		// (b) The payload is a mid-stream HTTP/2 DATA/WINDOW_UPDATE/PING/etc
		//     frame that starts with non-ASCII bytes on a connection whose PRI
		//     preface was seen in a previous chunk.
		// In both cases, if we already have an h2Conn for this key, route to
		// HTTP/2 directly — re-running detectProtocol is wrong here.
		d.h2mu.Lock()
		_, isKnownH2 := d.h2conns[key]
		d.h2mu.Unlock()

		if isKnownH2 {
			d.log.Debugf("[TLS] PROTO fragment key=%s payloadLen=%d fromTLS=%v prefix=%q → existing HTTP/2 conn",
				key, len(payload), fromTLS,
				func() string {
					if len(payload) > 8 {
						return fmt.Sprintf("%x", payload[:8])
					}
					return fmt.Sprintf("%x", payload)
				}())
			d.handleHTTP2(info, payload)
			return
		}

		// No known state — fall back to HTTP/1 parsing.
		// This handles TLS traffic where the protocol isn't in the plaintext
		// prefix, and also catches HTTP/1 on non-standard ports.
		d.log.Debugf("[TLS] PROTO unknown key=%s isRequest=%v fromTLS=%v payloadLen=%d prefix=%q — falling back to HTTP/1",
			key, info.isRequest, fromTLS, len(payload),
			func() string {
				if len(payload) > 12 {
					return string(payload[:12])
				}
				return string(payload)
			}())
		d.handleHTTP1(info, payload)
	}
}

type protocol int

const (
	protoUnknown protocol = iota
	protoHTTP1
	protoHTTP2
	protoGRPC
)

// detectProtocol uses the first bytes of payload to identify the application
// protocol
//
// HTTP/2 detection covers TWO cases:
//  1. Connection preface: starts with "PRI " — sent once per connection.
//  2. Binary frames: all subsequent HTTP/2 data is binary frames. We detect
//     these by inspecting the 9-byte frame header structure:
//     [3B length][1B type][1B flags][4B stream_id]
//     Valid HTTP/2 frame types: DATA(0), HEADERS(1), PRIORITY(2), RST_STREAM(3),
//     SETTINGS(4), PUSH_PROMISE(5), PING(6), GOAWAY(7), WINDOW_UPDATE(8), CONTINUATION(9).
//     This is critical for gRPC traffic (always HTTP/2) captured mid-connection.
func detectProtocol(data []byte) protocol {
	if len(data) < 4 {
		return protoUnknown
	}

	// HTTP/2 connection preface — "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
	if bytes.HasPrefix(data, []byte("PRI ")) {
		return protoHTTP2
	}

	// HTTP/1 request methods
	switch {
	case bytes.HasPrefix(data, []byte("GET ")),
		bytes.HasPrefix(data, []byte("POST")),
		bytes.HasPrefix(data, []byte("PUT ")),
		bytes.HasPrefix(data, []byte("PATC")),
		bytes.HasPrefix(data, []byte("DELE")),
		bytes.HasPrefix(data, []byte("HEAD")),
		bytes.HasPrefix(data, []byte("OPTI")):
		return protoHTTP1
	case bytes.HasPrefix(data, []byte("HTTP")):
		return protoHTTP1
	}

	// HTTP/2 binary frame heuristic.
	// A valid HTTP/2 frame starts with a 9-byte header:
	//   bytes 0-2: payload length (big-endian uint24, must be ≤ 16384 for default settings)
	//   byte  3:   frame type (0–9 are standard)
	//   byte  4:   flags
	//   bytes 5-8: stream ID (31-bit, MSB is reserved=0)
	// We require at least 9 bytes and check frame type + length sanity.
	if len(data) >= 9 {
		frameLen := uint32(data[0])<<16 | uint32(data[1])<<8 | uint32(data[2])
		frameType := data[3]
		streamIDMSB := data[5] & 0x80 // reserved bit — always 0 in valid frames

		// Standard HTTP/2 frame types are 0x00–0x09.
		// Frame length must be ≤ 16384 (default max frame size; negotiated via SETTINGS).
		// The reserved bit in stream ID must be 0.
		if frameType <= 9 && frameLen <= 16384 && streamIDMSB == 0 {
			// Extra confidence: if we have enough bytes, verify the frame payload
			// length is consistent with the data we have (partial frames are OK).
			return protoHTTP2
		}
	}

	return protoUnknown
}

// ============================================================================
// HTTP/1.x stream handling
// ============================================================================

type h1Stream struct {
	mu      sync.Mutex
	connKey string
	pending []h1Pending // FIFO queue (pipelining)
}

type h1Pending struct {
	ts               time.Time
	srcIP, dstIP     string
	srcPort, dstPort uint16
	cgroupID         uint64
	isSSL            bool

	method  string
	url     string
	reqHdrs map[string]string
	reqBody string
}

func (d *Dissector) getH1Stream(key string) *h1Stream {
	d.h1mu.Lock()
	defer d.h1mu.Unlock()
	s, ok := d.h1streams[key]
	if !ok {
		s = &h1Stream{connKey: key}
		d.h1streams[key] = s
	}
	return s
}

func (d *Dissector) handleHTTP1(info streamInfo, payload []byte) {
	key := info.connKey()
	stream := d.getH1Stream(key)
	stream.mu.Lock()
	defer stream.mu.Unlock()

	if info.isRequest {
		br := bufioReaderPool.Get().(*bufio.Reader)
		br.Reset(bytes.NewReader(payload))
		req, err := http.ReadRequest(br)
		defer bufioReaderPool.Put(br)
		if err != nil {
			d.log.Debugf("[TLS][HTTP1] DROP key=%s: ReadRequest failed: %v (payloadLen=%d prefix=%q)",
				key, err, len(payload),
				func() string {
					if len(payload) > 24 {
						return string(payload[:24])
					}
					return string(payload)
				}())
			return
		}
		reqBody := d.readBody(req.Body)
		hdrs := headersToMap(req.Header)
		// Go's http.ReadRequest strips "Host" from req.Header into req.Host.
		// Re-insert it so buildHTTP1Event can map it to :authority.
		if req.Host != "" {
			hdrs["Host"] = req.Host
		}
		d.log.Debugf("[TLS][HTTP1] ENQUEUE REQUEST key=%s method=%s url=%s ssl=%v pending_before=%d",
			key, req.Method, req.URL.String(), info.isSSL, len(stream.pending))
		stream.pending = append(stream.pending, h1Pending{
			ts:    info.timestamp,
			srcIP: info.srcIP, dstIP: info.dstIP,
			srcPort: info.srcPort, dstPort: info.dstPort,
			cgroupID: info.cgroupID,
			isSSL:    info.isSSL,
			method:   req.Method,
			url:      req.URL.String(),
			reqHdrs:  hdrs,
			reqBody:  reqBody,
		})
		return
	}

	// Response path.
	br := bufioReaderPool.Get().(*bufio.Reader)
	br.Reset(bytes.NewReader(payload))
	defer bufioReaderPool.Put(br)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		d.log.Debugf("[TLS][HTTP1] DROP key=%s: ReadResponse failed: %v (payloadLen=%d prefix=%q)",
			key, err, len(payload),
			func() string {
				if len(payload) > 24 {
					return string(payload[:24])
				}
				return string(payload)
			}())
		return
	}
	if len(stream.pending) == 0 {
		d.log.Debugf("[TLS][HTTP1] DROP key=%s: response arrived but no pending request (status=%d)",
			key, resp.StatusCode)
		return
	}
	// Pop the matching request (FIFO pipelining).
	req := stream.pending[0]
	stream.pending = stream.pending[1:]

	d.log.Debugf("[TLS][HTTP1] MATCHED key=%s method=%s url=%s status=%d ssl=%v",
		key, req.method, req.url, resp.StatusCode, req.isSSL)

	respBody := d.readBody(resp.Body)
	respHdrs := headersToMap(resp.Header)

	evt := d.buildHTTP1Event(req, resp, respHdrs, respBody, info)
	if d.handler != nil {
		d.log.Debugf("[TLS][HTTP1] EMIT event key=%s method=%s url=%s status=%d",
			key, req.method, req.url, resp.StatusCode)
		d.handler(evt)
	}
}

func (d *Dissector) buildHTTP1Event(req h1Pending, resp *http.Response, respHdrs map[string]string, respBody string, _ streamInfo) *pb.APIEvent {
	dstLabel := req.dstIP
	if fqdn := d.svcFn(dstLabel); fqdn != "" {
		dstLabel = fqdn
	}

	statusCode := int32(resp.StatusCode)
	proto := "HTTP/1.1"
	if resp.Proto != "" {
		proto = resp.Proto
	}

	if req.reqHdrs == nil {
		req.reqHdrs = make(map[string]string)
	}
	req.reqHdrs[":method"] = req.method
	req.reqHdrs[":path"] = req.url
	if host := req.reqHdrs["Host"]; host != "" {
		req.reqHdrs[":authority"] = host
	}
	req.reqHdrs[":scheme"] = "http"
	if req.isSSL {
		req.reqHdrs[":scheme"] = "https"
	}

	return &pb.APIEvent{
		Source: &pb.Workload{
			Ip:   req.srcIP,
			Port: int32(req.srcPort),
		},
		Destination: &pb.Workload{
			Ip:   dstLabel,
			Port: int32(req.dstPort),
		},
		Req: &pb.APIEvent_Request{Request: &pb.Request{
			Method:  req.method,
			Path:    req.url,
			Headers: req.reqHdrs,
			Body:    capString(req.reqBody, d.cfg.MaxBodySize),
		}},
		Res: &pb.APIEvent_Response{Response: &pb.Response{
			StatusCode: statusCode,
			Headers:    respHdrs,
			Body:       capString(respBody, d.cfg.MaxBodySize),
		}},
		Protocol: proto,
	}
}

// ============================================================================
// HTTP/2 / gRPC stream handling
// ============================================================================

// h2Conn tracks all active HTTP/2 streams on a single TCP connection.
//
// reqBuf and respBuf are stream-reassembly byte buffers — one per direction.
// HTTP/2 is a continuous byte stream; a TLS chunk boundary can land anywhere
// inside a frame (between the 9-byte header and its payload, or in the middle
// of a multi-frame burst). We accumulate incoming bytes here and only dispatch
// to ReadFrame when the buffer contains a complete frame, following the
// oneuptime.com blog pattern:
//
//	while offset + HEADER_SIZE <= len(data):
//	    frameLen = parse_length(data[offset:])
//	    if offset + HEADER_SIZE + frameLen > len(data): break  # incomplete
//	    dispatch(data[offset : offset + HEADER_SIZE + frameLen])
//	    offset += HEADER_SIZE + frameLen
//
// lastSeen is updated on every write and used by gcStaleH2Conns to evict
// connections whose buffers have been idle for more than 5 minutes.
type h2Conn struct {
	mu       sync.Mutex
	key      string
	peerDec  *hpack.Decoder
	selfDec  *hpack.Decoder
	streams  map[uint32]*h2Stream
	lastSeen time.Time

	plaintextClientDir    int
	plaintextClientDirSet bool

	// Stream-reassembly buffers: one per direction.
	// reqBuf  accumulates client→server bytes (HEADERS/DATA sent by the client).
	// respBuf accumulates server→client bytes (HEADERS/DATA sent by the server).
	reqBuf  bytes.Buffer
	respBuf bytes.Buffer
}

// h2Stream tracks a single HTTP/2 stream.
type h2Stream struct {
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

func (d *Dissector) getH2Conn_locked(key string) *h2Conn {
	c, ok := d.h2conns[key]
	if !ok {
		c = &h2Conn{
			key:      key,
			peerDec:  hpack.NewDecoder(4096, nil),
			selfDec:  hpack.NewDecoder(4096, nil),
			streams:  make(map[uint32]*h2Stream),
			lastSeen: time.Now(),
		}
		d.h2conns[key] = c
	}
	return c
}

func (d *Dissector) getH2Conn(key string) *h2Conn {
	d.h2mu.Lock()
	defer d.h2mu.Unlock()
	return d.getH2Conn_locked(key)
}

// gcStaleH2Conns evicts h2Conn entries whose reassembly buffers have been
// idle for more than 5 minutes. Call this periodically (e.g. from a goroutine
// in the Dissector) to prevent unbounded buffer growth for connections that
// were closed without a TCP FIN (e.g. pod restarts).
func (d *Dissector) gcStaleH2Conns(maxAge time.Duration) {
	cutoff := time.Now().Add(-maxAge)
	d.h2mu.Lock()
	defer d.h2mu.Unlock()
	for key, conn := range d.h2conns {
		conn.mu.Lock()
		if conn.lastSeen.Before(cutoff) {
			delete(d.h2conns, key)
		}
		conn.mu.Unlock()
	}
}

// h2FrameHeaderSize is the fixed size of the HTTP/2 frame header (RFC 9113 §4.1):
// [3B length][1B type][1B flags][4B stream_id]
const h2FrameHeaderSize = 9

// handleHTTP2 appends the chunk payload into the per-direction reassembly
// buffer and then dispatches every complete frame it can extract.
//
// KEY INSIGHT (from the oneuptime.com eBPF/TLS blog):
// A TLS chunk boundary can land anywhere inside an HTTP/2 frame — between
// the 9-byte frame header and its payload, or mid-payload. We must buffer
// bytes and only call ReadFrame when we know a full frame is available:
//
//	while buf.Len() >= 9:
//	    frameLen = parse_uint24(buf[0:3])
//	    if buf.Len() < 9 + frameLen: break   ← partial frame, wait
//	    dispatch buf[0 : 9+frameLen] to framer
//	    buf.Discard(9 + frameLen)
//
// This is what the old code was missing. Previously ANY io.EOF from
// framer.ReadFrame() (which fires at every chunk boundary) caused the
// h2Conn to be deleted, wiping HPACK state and silently dropping all
// subsequent traffic on that connection.
func (d *Dissector) handleHTTP2(info streamInfo, payload []byte) {
	// Strip the HTTP/2 connection preface if present.
	const h2Preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
	isNewConn := bytes.HasPrefix(payload, []byte(h2Preface))
	data := payload
	if isNewConn {
		data = data[len(h2Preface):]
	}
	if len(data) == 0 && !isNewConn {
		return
	}

	key := info.connKey()

	// A new connection preface means a fresh HTTP/2 session.
	// The old HPACK dynamic tables are stale — discard them.
	if isNewConn {
		d.h2mu.Lock()
		delete(d.h2conns, key)
		d.h2mu.Unlock()
		d.log.Debugf("[TLS][HTTP2] new conn preface on key=%s — HPACK state reset", key)

		// If plaintext, track the direction of the client that sent the preface.
		if !info.isSSL {
			conn := d.getH2Conn(key)
			conn.mu.Lock()
			conn.plaintextClientDir = int(info.direction)
			conn.plaintextClientDirSet = true
			conn.mu.Unlock()
		}

		if len(data) == 0 {
			return
		}
	}

	conn := d.getH2Conn(key)
	conn.mu.Lock()
	defer conn.mu.Unlock()

	conn.lastSeen = time.Now()

	// Override isRequest for plaintext HTTP/2 traffic since text-based method sniff fails on binary frames
	if !info.isSSL && conn.plaintextClientDirSet {
		info.isRequest = (int(info.direction) == conn.plaintextClientDir)
	}

	// Append this chunk to the correct directional buffer.
	// info.isRequest is true for client→server data, false for server→client.
	var buf *bytes.Buffer
	if info.isRequest {
		buf = &conn.reqBuf
	} else {
		buf = &conn.respBuf
	}
	buf.Write(data)

	// Pick the HPACK decoder for this direction.
	// HTTP/2 has two independent HPACK dynamic tables (RFC 9113 §4.3):
	//   selfDec: client's encoding context (used to decode request HEADERS)
	//   peerDec: server's encoding context (used to decode response HEADERS)
	var hpackDec *hpack.Decoder
	if info.isRequest {
		hpackDec = conn.selfDec
	} else {
		hpackDec = conn.peerDec
	}

	// Parse as many complete frames as the buffer contains.
	// We check the frame header (9 bytes) to learn the payload length, then
	// only call ReadFrame when the buffer holds at least header+payload bytes.
	// This is the critical fix: if the buffer is short, we break and wait for
	// the next TLS chunk — without destroying HPACK state.
	for buf.Len() >= h2FrameHeaderSize {
		// Peek at the 9-byte frame header to read the declared payload length.
		// bytes.Buffer.Bytes() returns a slice of the unread portion; we never
		// advance past the header until we confirm the full frame is present.
		header := buf.Bytes()
		framePayloadLen := int(uint32(header[0])<<16 | uint32(header[1])<<8 | uint32(header[2]))

		// Sanity check: HTTP/2 default max frame size is 16384 bytes.
		// Peers can negotiate a larger value via SETTINGS_MAX_FRAME_SIZE (up to
		// 16MB = 1<<24-1). We allow up to 1MB as a conservative upper bound;
		// larger values are almost certainly corrupt data.
		const maxAllowedFramePayload = 1 << 20 // 1 MB
		if framePayloadLen > maxAllowedFramePayload {
			// Corrupt data or mid-stream attachment with unknown HPACK state.
			// Reset to avoid wasting memory on a buffer that will never parse.
			d.log.Debugf("[TLS][HTTP2] oversized frame payload (%d bytes) on key=%s isRequest=%v — resetting",
				framePayloadLen, key, info.isRequest)
			buf.Reset()
			// Also reset the HPACK decoder since we may have partial state.
			if info.isRequest {
				conn.selfDec = hpack.NewDecoder(4096, nil)
			} else {
				conn.peerDec = hpack.NewDecoder(4096, nil)
			}
			return
		}

		totalFrameLen := h2FrameHeaderSize + framePayloadLen
		if buf.Len() < totalFrameLen {
			// Partial frame — wait for the next chunk to arrive.
			// This is the normal case for chunked TLS reads; do NOT reset state.
			break
		}

		// Extract exactly one complete frame from the buffer.
		frameBytes := make([]byte, totalFrameLen)
		_, _ = io.ReadFull(buf, frameBytes) // guaranteed to succeed: buf.Len() >= totalFrameLen

		// Feed the isolated frame into a fresh Framer.
		// The Framer is stateless for framing (only HPACK decoders are stateful),
		// so creating a new one per frame is correct and avoids any internal
		// EOF/buffering surprises.
		framer := http2.NewFramer(io.Discard, bytes.NewReader(frameBytes))
		framer.ReadMetaHeaders = hpackDec

		frame, err := framer.ReadFrame()
		if err != nil {
			// A real framing or HPACK decode error on a complete frame.
			// This is NOT a chunk-boundary issue — we already confirmed the
			// frame is fully present. The most likely cause is mid-stream probe
			// attachment where HPACK tables are already in a non-initial state.
			//
			// Reset the HPACK decoder for this direction so the next properly
			// formed frame (after a reconnect or SETTINGS reset) can parse.
			// Do NOT delete the entire h2Conn: that would wipe the other
			// direction's state and all tracked streams.
			d.log.Debugf("[TLS][HTTP2] frame parse error on key=%s isRequest=%v: %v",
				key, info.isRequest, err)
			if info.isRequest {
				conn.selfDec = hpack.NewDecoder(4096, nil)
			} else {
				conn.peerDec = hpack.NewDecoder(4096, nil)
			}

			// Skip the remaining buffer for this direction — we can't know
			// which bytes are valid after a decode error without the HPACK state.
			buf.Reset()
			return
		}

		d.processH2Frame(conn, frame, info)
	}
}

// processH2Frame dispatches individual HTTP/2 frames to the appropriate handler.
func (d *Dissector) processH2Frame(conn *h2Conn, frame http2.Frame, info streamInfo) {
	switch f := frame.(type) {
	case *http2.MetaHeadersFrame:
		d.processH2Headers(conn, f, info)
	case *http2.DataFrame:
		d.processH2Data(conn, f, info)
	case *http2.RSTStreamFrame:
		// Emit whatever we have on stream reset.
		if s, ok := conn.streams[f.StreamID]; ok {
			d.emitH2Event(s)
			delete(conn.streams, f.StreamID)
		}
	}
}

func (d *Dissector) processH2Headers(conn *h2Conn, f *http2.MetaHeadersFrame, info streamInfo) {
	sid := f.StreamID
	s, ok := conn.streams[sid]
	if !ok {
		s = &h2Stream{
			ts:    info.timestamp,
			srcIP: info.srcIP, dstIP: info.dstIP,
			srcPort: info.srcPort, dstPort: info.dstPort,
			cgroupID: info.cgroupID,
			isSSL:    info.isSSL,
			reqHdrs:  make(map[string]string),
			respHdrs: make(map[string]string),
		}
		conn.streams[sid] = s
	}

	// Determine if this HEADERS frame is a request or response from frame CONTENT
	// (not from info.isRequest which is unreliable for HTTP/2 binary frames).
	// HTTP/2 spec: request HEADERS contain ":method", response HEADERS contain ":status".
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

	d.log.Debugf("[TLS][HTTP2] HEADERS key=%s streamID=%d isReqFrame=%v endStream=%v fields=%d",
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
			d.emitH2Event(s)
			delete(conn.streams, sid)
		}
	}
}

func (d *Dissector) processH2Data(conn *h2Conn, f *http2.DataFrame, info streamInfo) {
	s, ok := conn.streams[f.StreamID]
	if !ok {
		return
	}

	// Removed: We now capture the gRPC body (which is binary protobuf).
	// To avoid invalid UTF-8 errors downstream, it will be base64-encoded in emitH2Event.

	data := f.Data()
	d.log.Debugf("[TLS][HTTP2] DATA key=%s streamID=%d isReq=%v len=%d endStream=%v", conn.key, f.StreamID, info.isRequest, len(data), f.StreamEnded())

	if info.isRequest {
		if s.reqBodyBuf.Len() < d.cfg.MaxBodySize {
			s.reqBodyBuf.Write(data)
		}
	} else {
		if s.respBodyBuf.Len() < d.cfg.MaxBodySize {
			s.respBodyBuf.Write(data)
		}
		if f.StreamEnded() {
			d.emitH2Event(s)
			delete(conn.streams, f.StreamID)
		}
	}
}

// emitH2Event builds and delivers a pb.APIEvent for a completed HTTP/2 stream.
func (d *Dissector) emitH2Event(s *h2Stream) {
	if s.reqMethod == "" && s.reqPath == "" {
		d.log.Debugf("[TLS][HTTP2] DROP emitH2Event: incomplete stream src=%s:%d dst=%s:%d (no method or path)",
			s.srcIP, s.srcPort, s.dstIP, s.dstPort)
		return // incomplete — drop
	}
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
	reqHdrs[":scheme"] = "http"
	if s.isSSL {
		reqHdrs[":scheme"] = "https"
	}

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

	// If it's gRPC, the body is binary protobuf. We base64-encode it to prevent
	// invalid UTF-8 errors in downstream marshaling layers.
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

	evt := &pb.APIEvent{
		Source: &pb.Workload{
			Ip:   s.srcIP,
			Port: int32(s.srcPort),
		},
		Destination: &pb.Workload{
			Ip:   dstLabel,
			Port: int32(s.dstPort),
		},
		Req: &pb.APIEvent_Request{Request: &pb.Request{
			Method:      s.reqMethod,
			Path:        s.reqPath,
			Headers:     reqHdrs,
			Body:        capString(reqBodyStr, d.cfg.MaxBodySize),
			GrpcService: s.grpcService,
			GrpcMethod:  s.grpcMethod,
			ContentType: s.contentType,
		}},
		Res: &pb.APIEvent_Response{Response: &pb.Response{
			StatusCode:        statusCode,
			Headers:           respHdrs,
			Body:              capString(respBodyStr, d.cfg.MaxBodySize),
			GrpcStatusCode:    s.grpcStatus,
			GrpcStatusMessage: grpcMsg,
		}},
		Protocol: proto,
	}
	if d.handler != nil {
		d.log.Debugf("[TLS][HTTP2] EMIT proto=%s method=%s path=%s status=%s src=%s:%d dst=%s:%d ssl=%v",
			proto, s.reqMethod, s.reqPath, s.respStatus,
			s.srcIP, s.srcPort, s.dstIP, s.dstPort, s.isSSL)
		d.handler(evt)
	}
}

// ============================================================================
// Helpers
// ============================================================================

func headersToMap(hdr http.Header) map[string]string {
	m := make(map[string]string, len(hdr))
	for k, vs := range hdr {
		m[k] = strings.Join(vs, ", ")
	}
	return m
}

func (d *Dissector) readBody(body io.ReadCloser) string {
	if body == nil {
		return ""
	}
	defer body.Close()
	lr := io.LimitReader(body, int64(d.cfg.MaxBodySize))
	b, err := io.ReadAll(lr)
	if err != nil {
		return ""
	}
	return string(b)
}

func capString(s string, max int) string {
	if len(s) > max {
		return s[:max]
	}
	return s
}

// isHTTPRequest peeks at the payload bytes to decide if this is an HTTP
// request (starts with a known HTTP method) vs a response ("HTTP/") vs
// something else (binary proto, etc).
// This is far more reliable than using Direction alone, because Direction
// reflects the packet direction from the pod's perspective (egress/ingress),
// not whether it is a client or server — a pod can receive requests (ingress)
// and a client pod sends them (egress).
func isHTTPRequest(payload []byte) bool {
	if len(payload) < 4 {
		return false
	}
	methods := []string{"GET ", "POST", "PUT ", "DEL ", "HEAD", "OPTI", "PATC", "CONN", "TRAC", "PRI "}
	for _, m := range methods {
		if len(payload) >= len(m) && string(payload[:len(m)]) == m {
			return true
		}
	}
	return false
}

// extractTransportPayload parses a raw IP packet (from PacketsPoller.RawPacket.Data)
// to extract TCP or UDP payload bytes and connection metadata.
func extractTransportPayload(pkt *poller.RawPacket) (streamInfo, []byte, error) {
	data := pkt.Data
	if len(data) < 20 {
		return streamInfo{}, nil, fmt.Errorf("packet too short for IP header")
	}

	const (
		ethPIP   = 0x0800
		ethPIPv6 = 0x86DD
	)

	switch pkt.IPHdrType {
	case ethPIP:
		ihl := int(data[0]&0x0f) * 4
		if ihl < 20 || len(data) < ihl+20 {
			return streamInfo{}, nil, fmt.Errorf("invalid IPv4 header")
		}
		proto := data[9]
		if proto != 6 && proto != 17 { // TCP=6, UDP=17
			return streamInfo{}, nil, fmt.Errorf("not TCP/UDP (proto=%d)", proto)
		}
		srcIP := fmt.Sprintf("%d.%d.%d.%d", data[12], data[13], data[14], data[15])
		dstIP := fmt.Sprintf("%d.%d.%d.%d", data[16], data[17], data[18], data[19])
		hdrStart := ihl

		if proto == 6 { // TCP
			if len(data) < hdrStart+20 {
				return streamInfo{}, nil, fmt.Errorf("too short for TCP header")
			}
			srcPort := uint16(data[hdrStart])<<8 | uint16(data[hdrStart+1])
			dstPort := uint16(data[hdrStart+2])<<8 | uint16(data[hdrStart+3])
			dataOffset := int((data[hdrStart+12] >> 4) * 4)
			payloadStart := hdrStart + dataOffset

			var payload []byte
			if payloadStart < len(data) {
				payload = data[payloadStart:]
			}

			info := streamInfo{
				srcIP: srcIP, dstIP: dstIP,
				srcPort: srcPort, dstPort: dstPort, proto: proto,
				cgroupID: pkt.CgroupID, timestamp: pkt.Timestamp, direction: pkt.Direction,
				isRequest: isHTTPRequest(payload),
			}
			return info, payload, nil
		} else { // UDP
			if len(data) < hdrStart+8 {
				return streamInfo{}, nil, fmt.Errorf("too short for UDP header")
			}
			srcPort := uint16(data[hdrStart])<<8 | uint16(data[hdrStart+1])
			dstPort := uint16(data[hdrStart+2])<<8 | uint16(data[hdrStart+3])
			payloadStart := hdrStart + 8

			var payload []byte
			if payloadStart < len(data) {
				payload = data[payloadStart:]
			}

			info := streamInfo{
				srcIP: srcIP, dstIP: dstIP,
				srcPort: srcPort, dstPort: dstPort, proto: proto,
				cgroupID: pkt.CgroupID, timestamp: pkt.Timestamp, direction: pkt.Direction,
				isRequest: false,
			}
			return info, payload, nil
		}

	case ethPIPv6:
		// IPv6 fixed header is 40 bytes.
		if len(data) < 40+20 {
			return streamInfo{}, nil, fmt.Errorf("IPv6 packet too short")
		}
		nextHeader := data[6]
		if nextHeader != 6 && nextHeader != 17 { // TCP=6, UDP=17 (skip extension headers for now)
			return streamInfo{}, nil, fmt.Errorf("IPv6 not TCP/UDP (next=%d)", nextHeader)
		}
		srcIP := fmt.Sprintf("%x:%x:%x:%x:%x:%x:%x:%x",
			uint16(data[8])<<8|uint16(data[9]),
			uint16(data[10])<<8|uint16(data[11]),
			uint16(data[12])<<8|uint16(data[13]),
			uint16(data[14])<<8|uint16(data[15]),
			uint16(data[16])<<8|uint16(data[17]),
			uint16(data[18])<<8|uint16(data[19]),
			uint16(data[20])<<8|uint16(data[21]),
			uint16(data[22])<<8|uint16(data[23]),
		)
		dstIP := fmt.Sprintf("%x:%x:%x:%x:%x:%x:%x:%x",
			uint16(data[24])<<8|uint16(data[25]),
			uint16(data[26])<<8|uint16(data[27]),
			uint16(data[28])<<8|uint16(data[29]),
			uint16(data[30])<<8|uint16(data[31]),
			uint16(data[32])<<8|uint16(data[33]),
			uint16(data[34])<<8|uint16(data[35]),
			uint16(data[36])<<8|uint16(data[37]),
			uint16(data[38])<<8|uint16(data[39]),
		)
		hdrStart := 40

		if nextHeader == 6 { // TCP
			if len(data) < hdrStart+20 {
				return streamInfo{}, nil, fmt.Errorf("IPv6 too short for TCP header")
			}
			srcPort := uint16(data[hdrStart])<<8 | uint16(data[hdrStart+1])
			dstPort := uint16(data[hdrStart+2])<<8 | uint16(data[hdrStart+3])
			dataOffset := int((data[hdrStart+12] >> 4) * 4)
			payloadStart := hdrStart + dataOffset

			var payload []byte
			if payloadStart < len(data) {
				payload = data[payloadStart:]
			}

			info := streamInfo{
				srcIP: srcIP, dstIP: dstIP,
				srcPort: srcPort, dstPort: dstPort, proto: nextHeader,
				cgroupID: pkt.CgroupID, timestamp: pkt.Timestamp, direction: pkt.Direction,
				isRequest: isHTTPRequest(payload),
			}
			return info, payload, nil
		} else { // UDP
			if len(data) < hdrStart+8 {
				return streamInfo{}, nil, fmt.Errorf("IPv6 too short for UDP header")
			}
			srcPort := uint16(data[hdrStart])<<8 | uint16(data[hdrStart+1])
			dstPort := uint16(data[hdrStart+2])<<8 | uint16(data[hdrStart+3])
			payloadStart := hdrStart + 8

			var payload []byte
			if payloadStart < len(data) {
				payload = data[payloadStart:]
			}

			info := streamInfo{
				srcIP: srcIP, dstIP: dstIP,
				srcPort: srcPort, dstPort: dstPort, proto: nextHeader,
				cgroupID: pkt.CgroupID, timestamp: pkt.Timestamp, direction: pkt.Direction,
				isRequest: false,
			}
			return info, payload, nil
		}

	default:
		return streamInfo{}, nil, fmt.Errorf("unsupported IP header type: 0x%x", pkt.IPHdrType)
	}
}

// buildH2APIEvent constructs a pb.APIEvent for an HTTP/2 stream.
// Used by both the old h2Conn path (raw packets) and the new TlsStreamAssembler.
func (d *Dissector) buildH2APIEvent(
	ts time.Time,
	srcIP, dstIP, dstLabel string,
	srcPort, dstPort uint16,
	cgroupID uint64,
	isSSL bool,
	reqMethod, reqPath, contentType string,
	reqHdrs, respHdrs map[string]string,
	reqBodyStr, respBodyStr string,
	statusCode int32,
	proto string,
	grpcService, grpcMethod string,
	grpcStatus int32,
	grpcMsg string,
) *pb.APIEvent {
	return &pb.APIEvent{
		Source: &pb.Workload{
			Ip:   srcIP,
			Port: int32(srcPort),
		},
		Destination: &pb.Workload{
			Ip:   dstLabel,
			Port: int32(dstPort),
		},
		Req: &pb.APIEvent_Request{Request: &pb.Request{
			Method:      reqMethod,
			Path:        reqPath,
			Headers:     reqHdrs,
			Body:        capString(reqBodyStr, d.cfg.MaxBodySize),
			GrpcService: grpcService,
			GrpcMethod:  grpcMethod,
			ContentType: contentType,
		}},
		Res: &pb.APIEvent_Response{Response: &pb.Response{
			StatusCode:        statusCode,
			Headers:           respHdrs,
			Body:              capString(respBodyStr, d.cfg.MaxBodySize),
			GrpcStatusCode:    grpcStatus,
			GrpcStatusMessage: grpcMsg,
		}},
		Protocol: proto,
	}
}
