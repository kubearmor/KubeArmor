// Package conn implements per-connection lifecycle tracking.
//
//	One ConnectionTracker per TCP connection. It owns the per-direction byte
//	buffers, a lazily-created set of protocol parsers (one http2.Parser per
//	connection so HPACK state is preserved across streams), and routes
//	complete messages into the shared Correlator.

package conn

import (
	"slices"
	"bytes"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/kubearmor/KubeArmor/KubeArmor/apiObserver/events"
	"github.com/kubearmor/KubeArmor/KubeArmor/apiObserver/protocols/grpc"
	"github.com/kubearmor/KubeArmor/KubeArmor/apiObserver/protocols/http1"
	"github.com/kubearmor/KubeArmor/KubeArmor/apiObserver/protocols/http2"
)

// CorrelatorIface is the subset of events.Correlator that ConnectionTracker
// calls.  A local interface keeps the conn↔events dependency uni-directional
// and allows test mocks without importing the real correlator.
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

type State int

const (
	StateEstablished State = iota // handshake complete; no application data yet
	StateActive                   // application data has been observed
	StateClosed                   // TCP FIN/RST seen; pending GC
)

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
		MaxBufferSize:     4 << 20, // 4 MiB per direction
	}
}

// ConnectionTracker manages one TCP connection end-to-end.
type ConnectionTracker struct {
	Key           events.ConnectionKey
	StreamKey     StreamKey
	Protocol      uint8
	State         State
	EstablishedAt time.Time
	LastSeen      time.Time

	sendBuf *DataStreamBuffer 
	recvBuf *DataStreamBuffer 

	// Protocol parsers — created lazily on first protocol detection.
	http1Req  *http1.Parser 
	http1Resp *http1.Parser 
	h2        *http2.Parser 
	gRPC      *grpc.Parser  

	isClientSide bool 
	directionSet bool 

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
		State:         StateEstablished,
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
	ct.State = StateActive

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

	results := ct.iterMessages(ev, cor)
	return results
}

// Close marks the connection closed, flushes the correlator, and releases buffers.
func (ct *ConnectionTracker) Close(cor CorrelatorIface) {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	if ct.closed {
		return
	}
	ct.closed = true
	ct.State = StateClosed

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

	prefix := string(buf[:4])
	if slices.Contains([]string{"GET ", "POST", "PUT ", "DELE", "HEAD", "PATC", "OPTI"}, prefix) {
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
		if ct.h2 == nil {
			ct.h2 = http2.NewParser()
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

	if ev.Direction == events.DirEgress {
		data := ct.sendBuf.Bytes()
		if len(data) == 0 {
			return nil
		}

		if bytes.HasPrefix(data, []byte("HTTP/")) {
			slog.Debug("Response data on egress stream, discarding",
				"sockptr", fmt.Sprintf("0x%x", ct.Key.SockPtr))
			ct.sendBuf.Reset()
			return nil
		}

		reqs, remaining, err := ct.http1Req.Parse(data)
		if err != nil {
			slog.Debug("HTTP/1 request parse error",
				"sockptr", fmt.Sprintf("0x%x", ct.Key.SockPtr), "err", err)
		}
		ct.sendBuf.SetRemaining(remaining)

		for _, req := range reqs {
			cor.AddHTTP1Request(ct.Key, events.PendingRequest{
				Timestamp: time.Now(),
				Method:    req.Method,
				URL:       req.Path,
				Headers:   req.Headers,
				Body:      string(req.Body),
				Src:       fmt.Sprintf("%s:%d", ev.SrcIPString(), ev.SrcPort),
				Dst:       fmt.Sprintf("%s:%d", ev.DstIPString(), ev.DstPort),
			})
		}
	} else {
		data := ct.recvBuf.Bytes()
		if len(data) == 0 {
			return nil
		}

		if isHTTP1RequestPrefix(data) {
			slog.Debug("Request data on ingress stream, discarding",
				"sockptr", fmt.Sprintf("0x%x", ct.Key.SockPtr))
			ct.recvBuf.Reset()
			return nil
		}

		resps, remaining, err := ct.http1Resp.Parse(data)
		if err != nil {
			slog.Debug("HTTP/1 response parse error",
				"sockptr", fmt.Sprintf("0x%x", ct.Key.SockPtr), "err", err)
		}
		ct.recvBuf.SetRemaining(remaining)

		serverURI := fmt.Sprintf("%s:%d", ev.SrcIPString(), ev.SrcPort)
		for _, resp := range resps {
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
	}
	return out
}

// isHTTP1RequestPrefix returns true if buf starts with a known HTTP/1.x
// request method token.  Used for direction-aware sniffing.
func isHTTP1RequestPrefix(buf []byte) bool {
	if len(buf) < 4 {
		return false
	}
	for _, tok := range [][]byte{
		[]byte("GET "), []byte("POST"), []byte("PUT "),
		[]byte("DELE"), []byte("HEAD"), []byte("PATC"),
		[]byte("OPTI"),
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

	// Choose the correct direction buffer.
	var buf *DataStreamBuffer
	if ev.Direction == events.DirEgress {
		buf = ct.sendBuf
	} else {
		buf = ct.recvBuf
	}

	data := buf.Bytes()
	if len(data) == 0 {
		return nil
	}

	msgs, remaining, err := ct.h2.ParseFrames(data)
	if err != nil {
		slog.Debug("HTTP/2 parse error",
			"sockptr", fmt.Sprintf("0x%x", ct.Key.SockPtr), "err", err)
	}

	// Put unconsumed bytes back.
	buf.SetRemaining(remaining)

	for _, msg := range msgs {
		if msg.IsRequest {
			cor.AddHTTP2Request(ct.Key, msg.StreamID, events.PendingRequest{
				Timestamp: time.Now(),
				Method:    msg.Method,
				URL:       msg.Path,
				Headers:   msg.Headers,
				Body:      string(msg.Body),
				Src:       fmt.Sprintf("%s:%d", ev.SrcIPString(), ev.SrcPort),
				Dst:       fmt.Sprintf("%s:%d", ev.DstIPString(), ev.DstPort),
				StreamID:  msg.StreamID,
			})
		} else {
			trace := cor.MatchHTTP2Response(
				ct.Key,
				msg.StreamID,
				msg.Status,
				msg.Headers,
				string(msg.Body),
				fmt.Sprintf("%s:%d", ev.SrcIPString(), ev.SrcPort),
			)
			if trace != nil {
				out = append(out, trace)
			}
		}
	}
	return out
}

// iterGRPC extracts gRPC messages via the HTTP/2 frame parser + LPM parser.
func (ct *ConnectionTracker) iterGRPC(ev *events.DataEvent, cor CorrelatorIface) []*events.CorrelatedTrace {
	// gRPC runs over HTTP/2; delegate to iterHTTP2 for now.
	// TODO: add gRPC-specific LPM framing and trailer extraction.
	return ct.iterHTTP2(ev, cor)
}

// Manager is the population-level connection tracker.
type Manager struct {
	trackers map[events.ConnectionKey]*ConnectionTracker
	mu       sync.RWMutex
	cor      CorrelatorIface
	cfg      TrackerConfig
}

// NewManager creates a Manager that routes events through the given correlator.
func NewManager(cor CorrelatorIface, cfg TrackerConfig) *Manager {
	return &Manager{
		trackers: make(map[events.ConnectionKey]*ConnectionTracker),
		cor:      cor,
		cfg:      cfg,
	}
}

// Route processes one DataEvent, creating or finding the ConnectionTracker
// and returning any completed correlated traces.
func (m *Manager) Route(ev *events.DataEvent) []*events.CorrelatedTrace {
	key := ev.ConnectionKey

	m.mu.RLock()
	ct, exists := m.trackers[key]
	m.mu.RUnlock()

	if !exists {
		sk := StreamKey{
			SrcIP:   ev.SrcIPString(),
			SrcPort: ev.SrcPort,
			DstIP:   ev.DstIPString(),
			DstPort: ev.DstPort,
		}
		ct = newConnectionTracker(key, sk, m.cfg)
		m.mu.Lock()
		// Double-check after acquiring write lock.
		if existing, ok := m.trackers[key]; ok {
			ct = existing
		} else {
			m.trackers[key] = ct
		}
		m.mu.Unlock()
	}

	return ct.Route(ev, m.cor)
}

// Close removes a connection from the manager and flushes the correlator.
func (m *Manager) Close(key events.ConnectionKey) {
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
func (m *Manager) Stop() {
	// Currently no background goroutines to stop.
}
