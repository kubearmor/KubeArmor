// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

// Package conn implements per-connection lifecycle tracking.
//
// One ConnectionTracker per TCP connection. It owns the per-direction byte
// buffers, set of protocol parsers, and routes
// complete messages into the shared Correlator.

package conn

import (
	"bytes"
	"context"
	"fmt"
	"math/rand"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kubearmor/KubeArmor/KubeArmor/apiObserver/events"
	"github.com/kubearmor/KubeArmor/KubeArmor/apiObserver/protocols/grpc"
	"github.com/kubearmor/KubeArmor/KubeArmor/apiObserver/protocols/http1"
	"github.com/kubearmor/KubeArmor/KubeArmor/apiObserver/protocols/http2"
	"github.com/kubearmor/KubeArmor/KubeArmor/log"
)

// CorrelatorIface is the subset of events.Correlator that ConnectionTracker calls.
type CorrelatorIface interface {
	AddHTTP1Request(key events.ConnectionKey, req events.PendingRequest)
	AddHTTP2Request(key events.ConnectionKey, streamID uint32, req events.PendingRequest)

	// MatchHTTP1Response pops the oldest pending request (FIFO pipelining) and
	// returns a completed CorrelatedTrace, or nil on mismatch.
	MatchHTTP1Response(
		key events.ConnectionKey,
		status string,
		respHeaders map[string]string,
		respBody string,
		serverURI string,
	) *events.CorrelatedTrace

	// MatchHTTP2Response matches by stream ID (HTTP/2 multiplexing).
	MatchHTTP2Response(
		key events.ConnectionKey,
		streamID uint32,
		status string,
		respHeaders map[string]string,
		respBody string,
		serverURI string,
	) *events.CorrelatedTrace

	CloseConnection(key events.ConnectionKey)
}

type ConnState int

const (
	ConnEstablished ConnState = iota // handshake complete; no application data yet
	ConnActive                       // application data has been observed
	ConnClosed                       // TCP FIN/RST seen; pending GC
)

// maxConsecutiveParseErrors is the circuit-breaker threshold: if the HTTP/1
// parser returns an error this many times in a row without making progress,
// the buffer is discarded to break the infinite re-park loop.
const maxConsecutiveParseErrors = 10

// StreamKey identifies a TCP connection by its IP:port 4-tuple.
// The watcher uses this to look up pod/service metadata.
type StreamKey struct {
	SrcIP   string
	SrcPort uint16
	DstIP   string
	DstPort uint16
}

type TrackerConfig struct {
	InactivityTimeout time.Duration // evict after this long with no data
	MaxBufferSize     int           // per-direction byte buffer cap (bytes)
	MaxConnections    int           // max concurrent connections
	OverloadThreshold int           // soft limit to trigger backpressure
}

func DefaultConfig() TrackerConfig {
	return TrackerConfig{
		InactivityTimeout: 30 * time.Second,
		MaxBufferSize:     192 * 1024, // 192KB per direction
		MaxConnections:    10000,
		OverloadThreshold: 7500,
	}
}

// ConnectionTracker manages one TCP connection end-to-end.
type ConnectionTracker struct {
	Key           events.ConnectionKey
	StreamKey     StreamKey
	Protocol      uint8
	State         ConnState
	EstablishedAt time.Time
	LastSeen      atomic.Int64 // UnixNano

	sendBuf *DataStreamBuffer
	recvBuf *DataStreamBuffer

	// Protocol parsers — created lazily on first protocol detection.
	http1Req  *http1.Parser
	http1Resp *http1.Parser
	// Two HTTP/2 parsers: one per direction, each with its own HPACK
	// dynamic table as required by RFC 7541 §2.2.
	h2Send *http2.Parser // egress (send) direction
	h2Recv *http2.Parser // ingress (recv) direction
	gRPC   *grpc.Parser

	isClientSide bool
	directionSet bool

	// Per-connection gRPC protocol memory (OpenTelemetry pattern).
	// Once any stream on this connection is identified as gRPC
	// (via content-type header or grpc-status trailer), all
	// subsequent streams inherit the gRPC classification.
	detectedGRPC bool

	// FIX 2: circuit-breaker for repeated parse failures on the same data.
	parseErrCount int

	cfg        TrackerConfig
	mu         sync.Mutex
	closed     atomic.Bool
	forceEvict atomic.Bool
}

// newConnectionTracker allocates a tracker for a newly established TCP connection.
// Buffers are acquired from the pool to reduce GC allocation churn.
func newConnectionTracker(key events.ConnectionKey, sk StreamKey, cfg TrackerConfig) *ConnectionTracker {
	ct := &ConnectionTracker{
		Key:           key,
		StreamKey:     sk,
		Protocol:      events.ProtoUnknown,
		State:         ConnEstablished,
		EstablishedAt: time.Now(),
		sendBuf:       AcquireDataStreamBuffer(cfg.MaxBufferSize),
		recvBuf:       AcquireDataStreamBuffer(cfg.MaxBufferSize),
		cfg:           cfg,
	}
	ct.LastSeen.Store(time.Now().UnixNano())
	return ct
}

func (ct *ConnectionTracker) Route(ev *events.DataEvent, cor CorrelatorIface) []*events.CorrelatedTrace {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	if ct.closed.Load() {
		return nil
	}

	ct.LastSeen.Store(time.Now().UnixNano())
	ct.State = ConnActive

	if !ct.directionSet {
		ct.directionSet = true

		// Use BPF ground truth when available (TLS chunks from
		// connect/accept tracepoints). This is critical: the old
		// direction-based guess was WRONG for server connections
		// where the first event is SSL_write (response/egress),
		// which caused isClientSide=true → inverted req/resp → drops.
		if ev.HasConnRole {
			ct.isClientSide = ev.IsClientConn
		} else {
			// Fallback for non-SSL (kprobe) events: guess from direction.
			ct.isClientSide = (ev.Direction == events.DirEgress)
		}

		log.Debugf("Tracker: new connection pid=%d fd=%d dir=%d isClient=%v hasConnRole=%v src=%s:%d dst=%s:%d ssl=%v",
			ct.Key.PID, ct.Key.FD, ev.Direction, ct.isClientSide, ev.HasConnRole,
			ev.SrcIPString(), ev.SrcPort, ev.DstIPString(), ev.DstPort,
			ev.IsSSL())
	}

	if ct.Protocol == events.ProtoUnknown && ev.Protocol != events.ProtoUnknown {
		ct.Protocol = ev.Protocol
		ct.initParsers()
	}

	// Buffer the payload in the right direction.
	if ev.Direction == events.DirEgress {
		ct.sendBuf.Write(ev.Payload)
	} else {
		ct.recvBuf.Write(ev.Payload)
	}

	if ct.Protocol == events.ProtoUnknown {
		oldProto := ct.Protocol
		ct.detectProtocol()
		if ct.Protocol != oldProto {
			log.Debugf("Tracker: protocol detected pid=%d fd=%d proto=%d sendBufLen=%d recvBufLen=%d",
				ct.Key.PID, ct.Key.FD, ct.Protocol, ct.sendBuf.Len(), ct.recvBuf.Len())
		}
		if ct.Protocol == events.ProtoUnknown {
			return nil
		}
	}

	// Propagate detected protocol back to the DataEvent so downstream
	// consumers (enrichAndEmit) see the correct protocol string.
	if ev.Protocol == events.ProtoUnknown {
		ev.Protocol = ct.Protocol
	}

	traces := ct.iterMessages(ev, cor)
	if len(traces) > 0 {
		log.Debugf("Tracker: %d traces emitted pid=%d fd=%d proto=%d dir=%d",
			len(traces), ct.Key.PID, ct.Key.FD, ct.Protocol, ev.Direction)
	}
	return traces
}

// Close marks the connection closed, flushes the correlator, and releases buffers
// back to the pool. This is the primary memory reclamation path — called either
// by BPF TCP_CLOSE notifications (immediate) or the eviction loop (safety net).
func (ct *ConnectionTracker) Close(cor CorrelatorIface) {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	if ct.closed.Load() {
		return
	}

	ct.closed.Store(true)
	ct.State = ConnClosed

	if cor != nil {
		cor.CloseConnection(ct.Key)
	}

	// Release buffers back to the pool for reuse by future connections.
	// This avoids GC churn: the backing arrays are recycled, not freed.
	ReleaseDataStreamBuffer(ct.sendBuf)
	ReleaseDataStreamBuffer(ct.recvBuf)
	ct.sendBuf = nil
	ct.recvBuf = nil
}

// IsStale returns true if the connection has been idle longer than
// cfg.InactivityTimeout.
func (ct *ConnectionTracker) IsStale() bool {
	return !ct.closed.Load() && time.Since(time.Unix(0, ct.LastSeen.Load())) > ct.cfg.InactivityTimeout
}

const http2Preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

func (ct *ConnectionTracker) detectProtocol() {
	// Check BOTH buffers for HTTP/2 preface
	for _, buf := range [][]byte{ct.sendBuf.Bytes(), ct.recvBuf.Bytes()} {
		n := len(http2Preface)
		if len(buf) >= n {
			if string(buf[:n]) == http2Preface {
				ct.Protocol = events.ProtoHTTP2
				ct.initParsers()
				return
			}
		} else if string(buf) == http2Preface[:len(buf)] {
			return
		}
	}

	// HTTP/1 fallback — check both buffers
	for _, buf := range [][]byte{ct.sendBuf.Bytes(), ct.recvBuf.Bytes()} {
		if len(buf) == 0 {
			continue
		}
		if isHTTP1RequestPrefix(buf) {
			ct.Protocol = events.ProtoHTTP1
			ct.initParsers()
			return
		}
		if len(buf) >= 5 && string(buf[:5]) == "HTTP/" {
			ct.Protocol = events.ProtoHTTP1
			ct.initParsers()
			return
		}
	}
}

func (ct *ConnectionTracker) initParsers() {
	switch ct.Protocol {
	case events.ProtoHTTP1:
		if ct.http1Req == nil {
			ct.http1Req = http1.NewParser(true)   // request side
			ct.http1Resp = http1.NewParser(false) // response side
		}
	case events.ProtoHTTP2, events.ProtoGRPC:
		if ct.h2Send == nil {
			ct.h2Send = http2.NewParser()
			ct.h2Recv = http2.NewParser()
		}
		if ct.gRPC == nil {
			ct.gRPC = grpc.NewParser()
		}
	}
}

func (ct *ConnectionTracker) iterMessages(ev *events.DataEvent, cor CorrelatorIface) []*events.CorrelatedTrace {
	switch ct.Protocol {
	case events.ProtoHTTP1:
		return ct.iterHTTP1(ev, cor)
	case events.ProtoHTTP2, events.ProtoGRPC:
		return ct.iterHTTP2(ev, cor)
	}
	return nil
}

func isTLSRecord(data []byte) bool {
	return len(data) >= 2 &&
		(data[0] == 0x14 || data[0] == 0x15 || data[0] == 0x16 || data[0] == 0x17) &&
		data[1] == 0x03
}

// iterHTTP1 extracts HTTP/1.x frames from the active direction buffer and
// routes them into the correlator.
func (ct *ConnectionTracker) iterHTTP1(ev *events.DataEvent, cor CorrelatorIface) []*events.CorrelatedTrace {
	var out []*events.CorrelatedTrace

	// Determine if this event carries request or response data.
	// Client-side: egress = request, ingress = response.
	// Server-side: ingress = request, egress = response.
	var isRequest bool
	if ct.isClientSide {
		isRequest = (ev.Direction == events.DirEgress)
	} else {
		isRequest = (ev.Direction == events.DirIngress)
	}

	// Select the correct buffers based on perspective.
	// Client: sendBuf = requests, recvBuf = responses.
	// Server: recvBuf = requests, sendBuf = responses.
	var reqBuf, respBuf *DataStreamBuffer
	if ct.isClientSide {
		reqBuf = ct.sendBuf
		respBuf = ct.recvBuf
	} else {
		reqBuf = ct.recvBuf
		respBuf = ct.sendBuf
	}

	if isRequest {
		data := reqBuf.Bytes()
		if len(data) == 0 {
			return nil
		}

		// Reject TLS data misrouted to the HTTP/1 parser.
		// TLS records start with 0x14-0x17 0x03.
		// This happens when a TLS client connects to a plain HTTP port.
		if isTLSRecord(data) {
			reqBuf.Reset()
			return nil
		}

		if bytes.HasPrefix(data, []byte("HTTP/")) {
			log.Warnf("HTTP/1: response data in REQUEST buffer pid=%d fd=%d isClient=%v — direction mismatch!",
				ct.Key.PID, ct.Key.FD, ct.isClientSide)
			reqBuf.Reset()
			return nil
		}

		// capture skipBytes (was discarded with _)
		reqs, consumed, skipBytes, _, err := ct.http1Req.Parse(data)

		if consumed > 0 {
			ct.parseErrCount = 0
			reqBuf.Advance(consumed)
		}
		if reqBuf.HasRepeatedOverflow() {
			ct.forceEvict.Store(true)
		}
		// drain remaining request body bytes off the wire
		if skipBytes > 0 {
			reqBuf.SkipNextBytes(skipBytes)
		}

		for _, req := range reqs {
			log.Debugf("HTTP/1: request queued pid=%d fd=%d method=%s path=%s isClient=%v ssl=%v",
				ct.Key.PID, ct.Key.FD, req.Method, req.Path, ct.isClientSide, ev.IsSSL())
			cor.AddHTTP1Request(ct.Key, events.PendingRequest{
				Timestamp:   time.Now(),
				Method:      req.Method,
				URL:         req.Path,
				Headers:     req.Headers,
				Body:        string(req.Body),
				Src:         fmt.Sprintf("%s:%d", ev.SrcIPString(), ev.SrcPort),
				Dst:         fmt.Sprintf("%s:%d", ev.DstIPString(), ev.DstPort),
				IsEncrypted: ev.IsSSL(),
			})
		}

		if err != nil {
			ct.parseErrCount++
			// BUG 2 fix: rate-limit parse error logs — emit on 1st
			// and every 10th consecutive error to reduce flooding.
			if ct.parseErrCount == 1 || ct.parseErrCount%10 == 0 {
				log.Warnf("HTTP/1 request parse error pid=%d fd=%d err=%v consecutive=%d dataLen=%d preview=%q",
					ct.Key.PID, ct.Key.FD, err, ct.parseErrCount, len(data), truncPreview(data, 80))
			}
			if ct.parseErrCount >= maxConsecutiveParseErrors {
				log.Warnf("HTTP/1: too many consecutive parse errors, resetting buffer, sockptr: %s, protocol: %d",
					fmt.Sprintf("0x%x", ct.Key.SockPtr), ct.Protocol)
				reqBuf.Reset()
				ct.parseErrCount = 0
			}
			return nil
		}
	} else {
		data := respBuf.Bytes()
		if len(data) == 0 {
			return nil
		}

		// Reject TLS data in the response buffer (same rationale as above).
		if isTLSRecord(data) {
			respBuf.Reset()
			return nil
		}

		if isHTTP1RequestPrefix(data) {
			log.Warnf("HTTP/1: request data in RESPONSE buffer pid=%d fd=%d isClient=%v — direction mismatch!",
				ct.Key.PID, ct.Key.FD, ct.isClientSide)
			respBuf.Reset()
			return nil
		}

		// capture skipBytes (was discarded with _)
		resps, consumed, skipBytes, _, err := ct.http1Resp.Parse(data)

		if consumed > 0 {
			ct.parseErrCount = 0
			respBuf.Advance(consumed)
		}
		if respBuf.HasRepeatedOverflow() {
			ct.forceEvict.Store(true)
		}
		// drain remaining response body bytes off the wire
		if skipBytes > 0 {
			respBuf.SkipNextBytes(skipBytes)
		}

		serverURI := fmt.Sprintf("%s:%d", ev.SrcIPString(), ev.SrcPort)
		for _, resp := range resps {
			log.Debugf("HTTP/1: response parsed pid=%d fd=%d status=%d isClient=%v",
				ct.Key.PID, ct.Key.FD, resp.StatusCode, ct.isClientSide)
			trace := cor.MatchHTTP1Response(
				ct.Key,
				fmt.Sprintf("%d", resp.StatusCode),
				resp.Headers,
				string(resp.Body),
				serverURI,
			)
			if trace != nil {
				log.Debugf("HTTP/1: matched! pid=%d fd=%d method=%s path=%s status=%d",
					ct.Key.PID, ct.Key.FD, trace.Method, trace.URL, resp.StatusCode)
				out = append(out, trace)
			} else {
				log.Warnf("HTTP/1: response UNMATCHED (no pending request) pid=%d fd=%d status=%d",
					ct.Key.PID, ct.Key.FD, resp.StatusCode)
			}
		}

		if err != nil {
			ct.parseErrCount++
			if ct.parseErrCount == 1 || ct.parseErrCount%10 == 0 {
				log.Warnf("HTTP/1 response parse error pid=%d fd=%d err=%v consecutive=%d dataLen=%d preview=%q",
					ct.Key.PID, ct.Key.FD, err, ct.parseErrCount, len(data), truncPreview(data, 80))
			}
			if ct.parseErrCount >= maxConsecutiveParseErrors {
				log.Warnf("HTTP/1: too many consecutive parse errors, resetting buffer, sockptr: %s, protocol: %d",
					fmt.Sprintf("0x%x", ct.Key.SockPtr), ct.Protocol)
				respBuf.Reset()
				ct.parseErrCount = 0
			}
			return out
		}
	}

	return out
}

// isHTTP1RequestPrefix returns true if buf starts with a known HTTP/1.x
// request method token (full token including trailing space).
func isHTTP1RequestPrefix(buf []byte) bool {
	if len(buf) < 4 {
		return false
	}
	for _, tok := range [][]byte{
		[]byte("GET "), []byte("POST "), []byte("PUT "),
		[]byte("DELETE "), []byte("PATCH "), []byte("HEAD "), []byte("OPTIONS "),
	} {
		if bytes.HasPrefix(buf, tok) {
			return true
		}
	}
	return false
}

// truncPreview returns a string preview of buf, truncated to maxLen bytes.
func truncPreview(buf []byte, maxLen int) string {
	if len(buf) <= maxLen {
		return string(buf)
	}
	return string(buf[:maxLen])
}

// iterHTTP2 extracts HTTP/2 frames, identifies request/response by stream ID,
// and feeds them to the correlator.
func (ct *ConnectionTracker) iterHTTP2(ev *events.DataEvent, cor CorrelatorIface) []*events.CorrelatedTrace {
	var out []*events.CorrelatedTrace

	// Select the buffer AND parser for this direction.
	// Each direction has its own HPACK dynamic table (RFC 7541 §2.2).
	var buf *DataStreamBuffer
	var parser *http2.Parser
	if ev.Direction == events.DirEgress {
		buf = ct.sendBuf
		parser = ct.h2Send
	} else {
		buf = ct.recvBuf
		parser = ct.h2Recv
	}

	data := buf.Bytes()
	if len(data) == 0 {
		return nil
	}

	msgs, remaining, err := parser.ParseFrames(data)
	if err != nil {
		log.Debugf("HTTP/2 parse error sockptr=0x%x err=%v",
			ct.Key.SockPtr, err)
	}

	buf.SetRemaining(remaining)
	if buf.HasRepeatedOverflow() {
		ct.forceEvict.Store(true)
	}

	// Use BPF direction as ground truth for request vs response.
	// For server-side tracing: ingress = request, egress = response.
	// For client-side tracing: egress = request, ingress = response.
	var isRequest bool
	if ct.isClientSide {
		isRequest = (ev.Direction == events.DirEgress)
	} else {
		isRequest = (ev.Direction == events.DirIngress)
	}

	for _, msg := range msgs {
		// Detect gRPC content-type for body decoding.
		contentType := ""
		if ctHeader, ok := msg.Headers["content-type"]; ok {
			contentType = ctHeader
		}
		isGRPCContent := grpc.IsGRPCContentType(contentType)

		if !isGRPCContent {
			if ct.detectedGRPC {
				isGRPCContent = true
				contentType = "application/grpc"
			} else if grpc.IsGRPCBody(msg.Body) {
				isGRPCContent = true
				contentType = "application/grpc"
				ct.detectedGRPC = true
				log.Debug(fmt.Sprint("gRPC detected by body heuristic",
					"sockptr", fmt.Sprintf("0x%x", ct.Key.SockPtr)))
			}
		} else {
			ct.detectedGRPC = true
		}

		if isRequest {
			// Decode gRPC body through LPM/protobuf parser if applicable.
			body := string(msg.Body)
			if isGRPCContent && len(msg.Body) > 0 {
				grpcMsg, _, parseErr := ct.gRPC.ParseMessage(msg.Body, msg.Headers)
				if parseErr == nil && grpcMsg != nil {
					body = grpcMsg.Body
				}
			}
			if msg.BodyTruncated {
				body += fmt.Sprintf(" ... [truncated, original=%dB]", msg.OriginalBodySize)
			}

			var grpcService, grpcMethod string
			if isGRPCContent && msg.Path != "" {
				grpcService, grpcMethod = grpc.ExtractServiceMethod(msg.Path)
			}

			cor.AddHTTP2Request(ct.Key, msg.StreamID, events.PendingRequest{
				Timestamp:   time.Now(),
				Method:      msg.Method,
				URL:         msg.Path,
				Headers:     msg.Headers,
				Body:        body,
				Src:         fmt.Sprintf("%s:%d", ev.SrcIPString(), ev.SrcPort),
				Dst:         fmt.Sprintf("%s:%d", ev.DstIPString(), ev.DstPort),
				StreamID:    msg.StreamID,
				IsEncrypted: ev.IsSSL(),
				GRPCService: grpcService,
				GRPCMethod:  grpcMethod,
				ContentType: contentType,
			})
		} else {
			// Decode gRPC body through LPM/protobuf parser if applicable.
			body := string(msg.Body)
			if isGRPCContent && len(msg.Body) > 0 {
				grpcMsg, _, parseErr := ct.gRPC.ParseMessage(msg.Body, msg.Headers)
				if parseErr == nil && grpcMsg != nil {
					body = grpcMsg.Body
				}
			}
			if msg.BodyTruncated {
				body += fmt.Sprintf(" ... [truncated, original=%dB]", msg.OriginalBodySize)
			}

			// Extract gRPC status from trailers if present.
			status := msg.Status
			var grpcStatusCode int32
			var grpcMessage string
			if isGRPCContent {
				grpcStatusCode, grpcMessage, _ = ct.gRPC.ParseTrailers(msg.Headers)
				if status == "" {
					status = fmt.Sprintf("%d", grpcStatusCode)
				}
			} else if _, hasGRPCStatus := msg.Headers["grpc-status"]; hasGRPCStatus {
				// grpc-status in trailers but content-type was missed.
				ct.detectedGRPC = true
				isGRPCContent = true
				contentType = "application/grpc"
				grpcStatusCode, grpcMessage, _ = ct.gRPC.ParseTrailers(msg.Headers)
				if status == "" {
					status = fmt.Sprintf("%d", grpcStatusCode)
				}
			}

			trace := cor.MatchHTTP2Response(
				ct.Key,
				msg.StreamID,
				status,
				msg.Headers,
				body,
				fmt.Sprintf("%s:%d", ev.SrcIPString(), ev.SrcPort),
			)
			if trace != nil {
				if isGRPCContent {
					trace.GRPCStatus = grpcStatusCode
					trace.GRPCMessage = grpcMessage
					trace.ContentType = contentType
					// BUG 4 fix: If grpc-status was not in the message
					// headers (trailing HEADERS segment missed by BPF),
					// default to 0 (OK) for responses that have body data.
					if _, hasStatus := msg.Headers["grpc-status"]; !hasStatus && len(msg.Body) > 0 {
						trace.GRPCStatus = 0
						trace.GRPCMessage = "OK"
					}
				}
				out = append(out, trace)
			}
		}
	}

	return out
}

// iterGRPC extracts gRPC messages via the HTTP/2 frame parser + gRPC LPM parser.
// It handles gRPC-specific features: LPM body framing, protobuf decoding,
// trailer-based status codes, and service/method extraction.
//
// Reference: Pixie's grpc.cc:ParseReqRespBody + http2_streams_container.cc
func (ct *ConnectionTracker) iterGRPC(ev *events.DataEvent, cor CorrelatorIface) []*events.CorrelatedTrace {
	var out []*events.CorrelatedTrace

	// Select the buffer AND parser for this direction.
	var buf *DataStreamBuffer
	var parser *http2.Parser
	if ev.Direction == events.DirEgress {
		buf = ct.sendBuf
		parser = ct.h2Send
	} else {
		buf = ct.recvBuf
		parser = ct.h2Recv
	}

	data := buf.Bytes()
	if len(data) == 0 {
		return nil
	}

	msgs, remaining, err := parser.ParseFrames(data)
	if err != nil {
		log.Debugf("gRPC/HTTP2 parse error sockptr=0x%x err=%v",
			ct.Key.SockPtr, err)
	}

	buf.SetRemaining(remaining)

	// Use BPF direction as ground truth for request vs response.
	var isRequest bool
	if ct.isClientSide {
		isRequest = (ev.Direction == events.DirEgress)
	} else {
		isRequest = (ev.Direction == events.DirIngress)
	}

	for _, msg := range msgs {
		// Detect content type for gRPC classification
		contentType := ""
		if ctHeader, ok := msg.Headers["content-type"]; ok {
			contentType = ctHeader
		}
		isGRPC := grpc.IsGRPCContentType(contentType)

		// Heuristic gRPC detection (same as iterHTTP2).
		if !isGRPC {
			if ct.detectedGRPC {
				isGRPC = true
				contentType = "application/grpc"
			} else if grpc.IsGRPCBody(msg.Body) {
				isGRPC = true
				contentType = "application/grpc"
				ct.detectedGRPC = true
			}
		} else {
			ct.detectedGRPC = true
		}

		if isRequest {
			// Extract service/method from :path for gRPC
			var grpcService, grpcMethod string
			if isGRPC && msg.Path != "" {
				grpcService, grpcMethod = grpc.ExtractServiceMethod(msg.Path)
			}

			// Parse body through gRPC LPM parser if available
			body := string(msg.Body)
			if isGRPC && len(msg.Body) > 0 {
				grpcMsg, _, parseErr := ct.gRPC.ParseMessage(msg.Body, msg.Headers)
				if parseErr == nil && grpcMsg != nil {
					body = grpcMsg.Body
				}
			}
			if msg.BodyTruncated {
				body += fmt.Sprintf(" ... [truncated, original=%dB]", msg.OriginalBodySize)
			}

			cor.AddHTTP2Request(ct.Key, msg.StreamID, events.PendingRequest{
				Timestamp:   time.Now(),
				Method:      msg.Method,
				URL:         msg.Path,
				Headers:     msg.Headers,
				Body:        body,
				Src:         fmt.Sprintf("%s:%d", ev.SrcIPString(), ev.SrcPort),
				Dst:         fmt.Sprintf("%s:%d", ev.DstIPString(), ev.DstPort),
				StreamID:    msg.StreamID,
				GRPCService: grpcService,
				GRPCMethod:  grpcMethod,
				ContentType: contentType,
			})
		} else {
			// Response: extract grpc-status from trailers and decode body
			status := msg.Status
			var grpcStatusCode int32
			var grpcMessage string

			if isGRPC {
				// gRPC status comes from trailers (grpc-status header)
				grpcStatusCode, grpcMessage, _ = ct.gRPC.ParseTrailers(msg.Headers)
				// Use grpc-status as the status string for gRPC
				if status == "" {
					status = fmt.Sprintf("%d", grpcStatusCode)
				}
			} else if _, hasGRPCStatus := msg.Headers["grpc-status"]; hasGRPCStatus {
				// grpc-status in trailers but content-type was missed.
				ct.detectedGRPC = true
				isGRPC = true
				contentType = "application/grpc"
				grpcStatusCode, grpcMessage, _ = ct.gRPC.ParseTrailers(msg.Headers)
				if status == "" {
					status = fmt.Sprintf("%d", grpcStatusCode)
				}
			}

			body := string(msg.Body)
			if isGRPC && len(msg.Body) > 0 {
				grpcMsg, _, parseErr := ct.gRPC.ParseMessage(msg.Body, msg.Headers)
				if parseErr == nil && grpcMsg != nil {
					body = grpcMsg.Body
				}
			}
			if msg.BodyTruncated {
				body += fmt.Sprintf(" ... [truncated, original=%dB]", msg.OriginalBodySize)
			}

			trace := cor.MatchHTTP2Response(
				ct.Key,
				msg.StreamID,
				status,
				msg.Headers,
				body,
				fmt.Sprintf("%s:%d", ev.SrcIPString(), ev.SrcPort),
			)
			if trace != nil {
				// Populate gRPC-specific fields on the trace
				trace.GRPCStatus = grpcStatusCode
				trace.GRPCMessage = grpcMessage
				trace.ContentType = contentType
				// BUG 4 fix: If grpc-status was not in the message
				// headers (trailing HEADERS segment missed by BPF),
				// default to 0 (OK) for responses that have body data.
				if _, hasStatus := msg.Headers["grpc-status"]; !hasStatus && len(msg.Body) > 0 {
					trace.GRPCStatus = 0
					trace.GRPCMessage = "OK"
				}
				out = append(out, trace)
			}
		}
	}

	return out
}

// ConnectionManager is the population-level connection tracker.
type ConnectionManager struct {
	trackers map[events.ConnectionKey]*ConnectionTracker
	mu       sync.RWMutex
	cor      CorrelatorIface
	cfg      TrackerConfig
	ctx      context.Context
	cancel   context.CancelFunc
}

// NewManager creates a Manager that routes events through the given correlator.
func NewManager(cor CorrelatorIface, cfg TrackerConfig) *ConnectionManager {
	ctx, cancel := context.WithCancel(context.Background())
	m := &ConnectionManager{
		trackers: make(map[events.ConnectionKey]*ConnectionTracker),
		cor:      cor,
		cfg:      cfg,
		ctx:      ctx,
		cancel:   cancel,
	}
	m.Start()
	return m
}

// Start launches the background stale connection eviction goroutine.
func (m *ConnectionManager) Start() {
	go m.evictLoop()
}

// Route processes one DataEvent, creating or finding the ConnectionTracker
// and returning any completed correlated traces.
func (m *ConnectionManager) Route(ev *events.DataEvent) []*events.CorrelatedTrace {
	key := ev.ConnectionKey

	m.mu.RLock()
	ct, exists := m.trackers[key]
	trackerCount := len(m.trackers)
	m.mu.RUnlock()

	if !exists {
		// Overload mode: sampling. If we are above OverloadThreshold,
		// randomly drop new connections (e.g. 1 in 3).
		if m.cfg.OverloadThreshold > 0 && trackerCount > m.cfg.OverloadThreshold {
			if rand.Float32() < 0.33 {
				return nil
			}
		}

		var toClose []*ConnectionTracker

		m.mu.Lock()
		// Double-check inside write lock; construct only if still absent.
		if ct, exists = m.trackers[key]; !exists {
			ct = newConnectionTracker(key, StreamKey{
				SrcIP:   ev.SrcIPString(),
				SrcPort: ev.SrcPort,
				DstIP:   ev.DstIPString(),
				DstPort: ev.DstPort,
			}, m.cfg)
			m.trackers[key] = ct

			// Hard connection cap check
			if m.cfg.MaxConnections > 0 && len(m.trackers) > m.cfg.MaxConnections {
				// Evict 5% of MaxConnections to get well below cap
				evictCount := m.cfg.MaxConnections / 20
				if evictCount == 0 {
					evictCount = 1
				}
				toClose = m.evictBatchLocked(evictCount)
			}
		}
		m.mu.Unlock()

		for _, evictedCt := range toClose {
			evictedCt.Close(m.cor)
		}
	}

	return ct.Route(ev, m.cor)
}

func (m *ConnectionManager) evictBatchLocked(count int) []*ConnectionTracker {
	evicted := make([]*ConnectionTracker, 0, count)
	for key, ct := range m.trackers {
		delete(m.trackers, key)
		evicted = append(evicted, ct)
		if len(evicted) >= count {
			break
		}
	}
	return evicted
}

// Close removes a connection from the manager and flushes the correlator.
func (m *ConnectionManager) Close(key events.ConnectionKey) {
	m.mu.Lock()
	ct, exists := m.trackers[key]
	if exists {
		delete(m.trackers, key)
	}
	m.mu.Unlock()

	if ct != nil {
		ct.Close(m.cor)
	}
}

// Stop cancels the eviction goroutine.
func (m *ConnectionManager) Stop() {
	m.cancel()
}

// evictLoop periodically scans for stale connections and evicts them.
// The 20s stagger at startup prevents this loop from firing concurrently
// with the /proc scanner and correlator cleanup, which would compound
// GC pressure and lock contention.
func (m *ConnectionManager) evictLoop() {
	// Stagger: avoid firing simultaneously with /proc scanners (t=0)
	// and correlator cleanup (t=10s).
	select {
	case <-time.After(20 * time.Second):
	case <-m.ctx.Done():
		return
	}

	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			m.evictStale()
		case <-m.ctx.Done():
			return
		}
	}
}

// evictBatchSize is the number of stale connections deleted per write-lock
// acquisition. Batching bounds the write lock hold time to ~64 map deletes
// (microseconds) while avoiding thousands of lock/unlock cycles that would
// each incur a memory barrier + potential goroutine reschedule.
const evictBatchSize = 64

// evictStale removes connections that have been idle longer than
// cfg.InactivityTimeout using a two-phase approach:
//  1. Scan under read lock to identify stale keys (non-blocking for Route)
//  2. Delete in batches under short write locks with Gosched between batches
func (m *ConnectionManager) evictStale() {
	// Phase 1: identify stale keys under read lock — Route() is not blocked.
	var staleKeys []events.ConnectionKey

	m.mu.RLock()
	for key, ct := range m.trackers {
		if ct.IsStale() || ct.closed.Load() || ct.forceEvict.Load() {
			staleKeys = append(staleKeys, key)
		}
	}
	m.mu.RUnlock()

	if len(staleKeys) == 0 {
		return
	}

	// Phase 2: delete in batches — each write lock is short.
	for i := 0; i < len(staleKeys); i += evictBatchSize {
		end := i + evictBatchSize
		if end > len(staleKeys) {
			end = len(staleKeys)
		}
		var toClose []*ConnectionTracker
		
		m.mu.Lock()
		for _, key := range staleKeys[i:end] {
			if ct, exists := m.trackers[key]; exists {
				delete(m.trackers, key)
				toClose = append(toClose, ct)
			}
		}
		m.mu.Unlock()
		
		for _, ct := range toClose {
			ct.Close(m.cor)
		}
		// Yield between batches so pending Route() calls can proceed.
		runtime.Gosched()
	}

	log.Debugf("ConnectionManager: evicted stale connections count=%d", len(staleKeys))
}
