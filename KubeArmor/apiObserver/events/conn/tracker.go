// Package conn implements per-connection lifecycle tracking.
//
// One ConnectionTracker per TCP connection. It owns the per-direction byte
// buffers, set of protocol parsers, and routes
// complete messages into the shared Correlator.

package conn

import (
	"bytes"
	"fmt"
	"log/slog"
	"sync"
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
}

func DefaultConfig() TrackerConfig {
	return TrackerConfig{
		InactivityTimeout: 5 * time.Minute,
		MaxBufferSize:     192 * 1024, // 192KB per direction
	}
}

// ConnectionTracker manages one TCP connection end-to-end.
type ConnectionTracker struct {
	Key           events.ConnectionKey
	StreamKey     StreamKey
	Protocol      uint8
	State         ConnState
	EstablishedAt time.Time
	LastSeen      time.Time

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

	cfg    TrackerConfig
	mu     sync.Mutex
	closed bool
}

// newConnectionTracker allocates a tracker for a newly established TCP connection.
func newConnectionTracker(key events.ConnectionKey, sk StreamKey, cfg TrackerConfig) *ConnectionTracker {
	return &ConnectionTracker{
		Key:           key,
		StreamKey:     sk,
		Protocol:      events.ProtoUnknown,
		State:         ConnEstablished,
		EstablishedAt: time.Now(),
		LastSeen:      time.Now(),
		sendBuf:       NewDataStreamBuffer(cfg.MaxBufferSize),
		recvBuf:       NewDataStreamBuffer(cfg.MaxBufferSize),
		cfg:           cfg,
	}
}

func (ct *ConnectionTracker) Route(ev *events.DataEvent, cor CorrelatorIface) []*events.CorrelatedTrace {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	if ct.closed {
		return nil
	}

	ct.LastSeen = time.Now()
	ct.State = ConnActive

	if !ct.directionSet {
		ct.directionSet = true
		ct.isClientSide = (ev.Direction == events.DirEgress)
		if ct.isClientSide {
			slog.Debug("Classified as client-side connection",
				"pid", ct.Key.PID, "fd", ct.Key.FD,
				"sockptr", fmt.Sprintf("0x%x", ct.Key.SockPtr))
		}
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
		ct.detectProtocol()
		if ct.Protocol == events.ProtoUnknown {
			return nil
		}
	}

	// Propagate detected protocol back to the DataEvent so downstream
	// consumers (enrichAndEmit) see the correct protocol string.
	if ev.Protocol == events.ProtoUnknown {
		ev.Protocol = ct.Protocol
	}

	return ct.iterMessages(ev, cor)
}

// Close marks the connection closed, flushes the correlator, and releases buffers.
func (ct *ConnectionTracker) Close(cor CorrelatorIface) {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	if ct.closed {
		return
	}

	ct.closed = true
	ct.State = ConnClosed

	if cor != nil {
		cor.CloseConnection(ct.Key)
	}

	// Release buffer memory.
	ct.sendBuf.Reset()
	ct.recvBuf.Reset()
}

// IsStale returns true if the connection has been idle longer than
// cfg.InactivityTimeout.
func (ct *ConnectionTracker) IsStale() bool {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	return !ct.closed && time.Since(ct.LastSeen) > ct.cfg.InactivityTimeout
}

const http2Preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

func (ct *ConnectionTracker) detectProtocol() {
	buf := ct.sendBuf.Bytes()
	if len(buf) == 0 {
		buf = ct.recvBuf.Bytes()
	}

	if len(buf) < 4 {
		return
	}

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

	if isHTTP1RequestPrefix(buf) {
		ct.Protocol = events.ProtoHTTP1
		ct.initParsers()
		return
	}

	if len(buf) >= 5 && string(buf[:5]) == "HTTP/" {
		ct.Protocol = events.ProtoHTTP1
		ct.initParsers()
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
	case events.ProtoHTTP2:
		return ct.iterHTTP2(ev, cor)
	case events.ProtoGRPC:
		return ct.iterGRPC(ev, cor)
	}
	return nil
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

		if bytes.HasPrefix(data, []byte("HTTP/")) {
			slog.Debug("Response data in request buffer, discarding",
				"sockptr", fmt.Sprintf("0x%x", ct.Key.SockPtr))
			reqBuf.Reset()
			return nil
		}

		// capture skipBytes (was discarded with _)
		reqs, consumed, skipBytes, _, err := ct.http1Req.Parse(data)

		if consumed > 0 {
			ct.parseErrCount = 0
			reqBuf.Advance(consumed)
		}
		// drain remaining request body bytes off the wire
		if skipBytes > 0 {
			reqBuf.SkipNextBytes(skipBytes)
		}

		for _, req := range reqs {
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
				slog.Debug("HTTP/1 request parse error",
					"sockptr", fmt.Sprintf("0x%x", ct.Key.SockPtr),
					"err", err,
					"consecutive", ct.parseErrCount)
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

		if isHTTP1RequestPrefix(data) {
			slog.Debug("Request data in response buffer, discarding",
				"sockptr", fmt.Sprintf("0x%x", ct.Key.SockPtr))
			respBuf.Reset()
			return nil
		}

		// capture skipBytes (was discarded with _)
		resps, consumed, skipBytes, _, err := ct.http1Resp.Parse(data)

		if consumed > 0 {
			ct.parseErrCount = 0
			respBuf.Advance(consumed)
		}
		// drain remaining response body bytes off the wire
		if skipBytes > 0 {
			respBuf.SkipNextBytes(skipBytes)
		}

		serverURI := fmt.Sprintf("%s:%d", ev.SrcIPString(), ev.SrcPort)
		for _, resp := range resps {
			// FIX 4: use resp.StatusText (already a string, e.g. "OK") instead of
			// fmt.Sprintf("%d", resp.StatusCode) which allocates on every response.
			trace := cor.MatchHTTP1Response(
				ct.Key,
				fmt.Sprintf("%d", resp.StatusCode),
				resp.Headers,
				string(resp.Body),
				serverURI,
			)
			if trace != nil {
				out = append(out, trace)
			}
		}

		if err != nil {
			ct.parseErrCount++
			// BUG 2 fix: rate-limit parse error logs.
			if ct.parseErrCount == 1 || ct.parseErrCount%10 == 0 {
				slog.Debug("HTTP/1 response parse error",
					"sockptr", fmt.Sprintf("0x%x", ct.Key.SockPtr),
					"err", err,
					"consecutive", ct.parseErrCount)
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
		slog.Debug("HTTP/2 parse error",
			"sockptr", fmt.Sprintf("0x%x", ct.Key.SockPtr), "err", err)
	}

	buf.SetRemaining(remaining)

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
		slog.Debug("gRPC/HTTP2 parse error",
			"sockptr", fmt.Sprintf("0x%x", ct.Key.SockPtr), "err", err)
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
}

// NewManager creates a Manager that routes events through the given correlator.
func NewManager(cor CorrelatorIface, cfg TrackerConfig) *ConnectionManager {
	return &ConnectionManager{
		trackers: make(map[events.ConnectionKey]*ConnectionTracker),
		cor:      cor,
		cfg:      cfg,
	}
}

// Route processes one DataEvent, creating or finding the ConnectionTracker
// and returning any completed correlated traces.
func (m *ConnectionManager) Route(ev *events.DataEvent) []*events.CorrelatedTrace {
	key := ev.ConnectionKey

	m.mu.RLock()
	ct, exists := m.trackers[key]
	m.mu.RUnlock()

	if !exists {
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
		}
		m.mu.Unlock()
	}

	return ct.Route(ev, m.cor)
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

// Stop is a no-op shutdown hook for the manager.
func (m *ConnectionManager) Stop() {
	// Currently no background goroutines to stop.
}
