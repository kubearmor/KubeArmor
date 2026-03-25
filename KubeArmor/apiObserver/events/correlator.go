// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

// Package events: correlator.go implements request-response matching.
//
//	HTTP/1.x — FIFO queue per connection
//	  Requests are queued in arrival order.  Responses pop the head.
//
//	HTTP/2 / gRPC — per-stream-ID map per connection
//	  Each stream ID gets its own slot.  Responses look up by stream ID.
//	  This handles full stream multiplexing.
//
// A background cleanup goroutine evicts requests older than the configured
// timeout to prevent unbounded memory growth on half-open connections.
package events

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// maxPendingRequestsPerConn is the maximum number of in-flight HTTP/1.x pipelined
// requests allowed per connection before old ones are dropped.
const maxPendingRequestsPerConn = 256

// Correlator matches HTTP requests to their responses and emits
// CorrelatedTrace records.  It is safe for concurrent use.
type Correlator interface {
	// AddHTTP1Request enqueues a pending request for HTTP/1.x FIFO matching.
	AddHTTP1Request(key ConnectionKey, req PendingRequest)

	// MatchHTTP1Response dequeues the oldest pending request (FIFO) for this
	// connection and returns the matched CorrelatedTrace, or nil if no
	// pending request exists.
	MatchHTTP1Response(
		key ConnectionKey,
		status string,
		respHeaders map[string]string,
		respBody string,
		serverURI string,
	) *CorrelatedTrace

	// AddHTTP2Request stores a pending request under (key, streamID).
	AddHTTP2Request(key ConnectionKey, streamID uint32, req PendingRequest)

	// MatchHTTP2Response looks up and removes the pending request for
	// (key, streamID) and returns a CorrelatedTrace, or nil if not found.
	MatchHTTP2Response(
		key ConnectionKey,
		streamID uint32,
		status string,
		respHeaders map[string]string,
		respBody string,
		serverURI string,
	) *CorrelatedTrace

	// InjectGoHTTP2Headers merges uprobe-derived headers into an existing
	// pending HTTP/2 request. If the request doesn't exist yet, it creates
	// a placeholder. This is the bridge between Go uprobe header data and
	// the kprobe data pipeline.
	InjectGoHTTP2Headers(key ConnectionKey, streamID uint32, headers map[string]string)

	// InjectGoGRPCEvent injects a complete gRPC request event from the
	// Go uprobe pipeline. Unlike InjectGoHTTP2Headers which provides only
	// headers, this provides the full path, status, and timing information.
	InjectGoGRPCEvent(pid uint32, path string, status uint16, startNs, endNs uint64)

	// CloseConnection flushes all pending requests for a connection.
	// Called when a TCPCLOSE event is received.
	CloseConnection(key ConnectionKey)

	// Start spins the cleanup goroutines
	Start()

	// Stop cancels the cleanup goroutine.
	Stop()
}

// CorrelatorStats is a copy-safe snapshot of correlation counters.
type CorrelatorStats struct {
	TotalRequests      uint64
	TotalResponses     uint64
	MatchedPairs       uint64
	UnmatchedResponses uint64
	// Requests evicted by reason.
	CleanedByReason map[CleanupReason]uint64
	// Active HTTP/1 connections with pending requests.
	ActiveHTTP1Conns int
	// Active HTTP/2 connections with pending streams.
	ActiveHTTP2Conns int
	// HTTP/1.1 pipelining: requests queued behind another.
	PipelinedRequests uint64
	// HTTP/2 concurrent streams seen.
	HTTP2Streams uint64
}

// correlatorStats is a snapshot of correlation counters.
type correlatorStats struct {
	totalRequests      atomic.Uint64
	totalResponses     atomic.Uint64
	matchedPairs       atomic.Uint64
	unmatchedResponses atomic.Uint64
	pipelinedRequests  atomic.Uint64
	http2Streams       atomic.Uint64

	// Per-reason cleanup counters
	cleanedTimeout    atomic.Uint64
	cleanedBufferFull atomic.Uint64
	cleanedConnClose  atomic.Uint64
}

// defaultCorrelator struct    provides implementation for Correlator interface.
type defaultCorrelator struct {
	// HTTP/1.x: per-connection FIFO queue (supports pipelining).
	connToHTTP1Queue   map[ConnectionKey]*RequestQueue
	connToHTTP1QueueMu sync.Mutex

	// HTTP/2 / gRPC: per-connection, per-stream-ID pending request map.
	connToHTTP2Stream   map[ConnectionKey]*HTTP2StreamRequests
	connToHTTP2StreamMu sync.Mutex

	timeout time.Duration
	stats   correlatorStats

	ctx    context.Context
	cancel context.CancelFunc
}

// NewCorrelator creates a Correlator with the given request-timeout.
// Requests not matched within timeout are silently evicted by the cleanup loop.
func NewCorrelator(timeout time.Duration) Correlator {
	ctx, cancel := context.WithCancel(context.Background())
	c := &defaultCorrelator{
		connToHTTP1Queue:  make(map[ConnectionKey]*RequestQueue),
		connToHTTP2Stream: make(map[ConnectionKey]*HTTP2StreamRequests),
		timeout:           timeout,
		stats:             correlatorStats{},
		ctx:               ctx,
		cancel:            cancel,
	}
	c.Start()
	return c
}

// Starts the cleanup loop to remove stale requests based on timeout
func (c *defaultCorrelator) Start() {
	go c.cleanupLoop()
}

// HTTP/1.x FIFO methods

// AddHTTP1Request enqueues req into the per-connection FIFO queue.
// If the queue is full (maxPendingRequestsPerConn), the oldest request is evicted.
func (c *defaultCorrelator) AddHTTP1Request(key ConnectionKey, req PendingRequest) {
	c.connToHTTP1QueueMu.Lock()

	q, ok := c.connToHTTP1Queue[key]
	if !ok {
		q = &RequestQueue{Requests: make([]PendingRequest, 0, 4)}
		c.connToHTTP1Queue[key] = q
	}

	if len(q.Requests) >= maxPendingRequestsPerConn {
		q.Requests = q.Requests[1:]
		c.stats.cleanedBufferFull.Add(1)
	}

	isPipelined := len(q.Requests) > 0
	q.Requests = append(q.Requests, req)
	depth := len(q.Requests)

	c.connToHTTP1QueueMu.Unlock()

	c.stats.totalRequests.Add(1)
	if isPipelined {
		c.stats.pipelinedRequests.Add(1)
	}

	slog.Debug("HTTP/1 request queued",
		"PID", key.PID,
		"FD", key.FD,
		"sockptr", key.SockPtr,
		"method", req.Method,
		"url", req.URL,
		"depth", depth,
	)
}

// MatchHTTP1Response dequeues the head of the FIFO queue and returns the
// matched CorrelatedTrace. Returns nil if no pending request exists.
func (c *defaultCorrelator) MatchHTTP1Response(
	key ConnectionKey,
	status string,
	respHeaders map[string]string,
	respBody string,
	serverURI string,
) *CorrelatedTrace {
	c.connToHTTP1QueueMu.Lock()

	q, ok := c.connToHTTP1Queue[key]
	if !ok || len(q.Requests) == 0 {
		c.connToHTTP1QueueMu.Unlock()
		c.stats.unmatchedResponses.Add(1)
		return nil
	}

	req := q.Requests[0]
	q.Requests = q.Requests[1:]
	if len(q.Requests) == 0 {
		delete(c.connToHTTP1Queue, key)
	}
	remaining := len(q.Requests)

	c.connToHTTP1QueueMu.Unlock()

	now := time.Now()
	durationNs := now.Sub(req.Timestamp).Nanoseconds()

	trace := &CorrelatedTrace{
		Timestamp:       req.Timestamp,
		Method:          req.Method,
		URL:             req.URL,
		Status:          status,
		DurationNs:      durationNs,
		Src:             req.Src,
		Dst:             serverURI,
		RequestHeaders:  req.Headers,
		RequestBody:     req.Body,
		ResponseHeaders: respHeaders,
		ResponseBody:    respBody,
		IsEncrypted:     req.IsEncrypted,
	}

	c.stats.totalResponses.Add(1)
	c.stats.matchedPairs.Add(1)

	slog.Debug("HTTP/1 request-response matched",
		"PID", key.PID,
		"FD", key.FD,
		"sockptr", key.SockPtr,
		"method", req.Method,
		"status", status,
		"duration_ns", durationNs,
		"queue_remaining", remaining,
	)
	return trace
}

// AddHTTP2Request stores req under (key, streamID).
// Multiple streams on the same connection are fully independent.
func (c *defaultCorrelator) AddHTTP2Request(
	key ConnectionKey,
	streamID uint32,
	req PendingRequest,
) {
	c.connToHTTP2StreamMu.Lock()

	streams, ok := c.connToHTTP2Stream[key]
	if !ok {
		streams = &HTTP2StreamRequests{
			Requests: make(map[uint32]PendingRequest),
		}
		c.connToHTTP2Stream[key] = streams
	}

	req.StreamID = streamID
	streams.Requests[streamID] = req

	c.connToHTTP2StreamMu.Unlock()

	c.stats.totalRequests.Add(1)
	c.stats.http2Streams.Add(1)

	slog.Debug("HTTP/2 request stored",
		"PID", key.PID,
		"FD", key.FD,
		"sockptr", key.SockPtr,
		"stream_id", streamID,
		"method", req.Method,
		"url", req.URL,
	)
}

// MatchHTTP2Response looks up the pending request for (key, streamID),
// removes it, and returns the CorrelatedTrace. Returns nil if not found.
func (c *defaultCorrelator) MatchHTTP2Response(
	key ConnectionKey,
	streamID uint32,
	status string,
	respHeaders map[string]string,
	respBody string,
	serverURI string,
) *CorrelatedTrace {
	c.connToHTTP2StreamMu.Lock()

	streams, ok := c.connToHTTP2Stream[key]
	if !ok {
		c.connToHTTP2StreamMu.Unlock()
		c.stats.unmatchedResponses.Add(1)
		return nil
	}

	req, ok := streams.Requests[streamID]
	if !ok {
		c.connToHTTP2StreamMu.Unlock()
		c.stats.unmatchedResponses.Add(1)
		return nil
	}

	delete(streams.Requests, streamID)
	if len(streams.Requests) == 0 {
		delete(c.connToHTTP2Stream, key)
	}

	c.connToHTTP2StreamMu.Unlock()

	now := time.Now()
	durationNs := now.Sub(req.Timestamp).Nanoseconds()

	trace := &CorrelatedTrace{
		Timestamp:       req.Timestamp,
		Method:          req.Method,
		URL:             req.URL,
		Status:          status,
		DurationNs:      durationNs,
		Src:             req.Src,
		Dst:             serverURI,
		RequestHeaders:  req.Headers,
		RequestBody:     req.Body,
		ResponseHeaders: respHeaders,
		ResponseBody:    respBody,
		StreamID:        streamID,
		IsEncrypted:     req.IsEncrypted,
		GRPCService:     req.GRPCService,
		GRPCMethod:      req.GRPCMethod,
		ContentType:     req.ContentType,
	}

	c.stats.totalResponses.Add(1)
	c.stats.matchedPairs.Add(1)

	slog.Debug("HTTP/2 request-response matched",
		"PID", key.PID,
		"FD", key.FD,
		"sockptr", key.SockPtr,
		"stream_id", streamID,
		"method", req.Method,
		"status", status,
		"duration_ns", durationNs,
	)
	return trace
}

// InjectGoHTTP2Headers merges Go uprobe-derived headers into existing
// pending HTTP/2 requests. This is critical for path recovery: kprobe-based
// tracing often misses :path due to HPACK dynamic table limitations,
// but the Go uprobe captures headers AFTER HPACK decoding.
//
// If a pending request already exists for (key, streamID), the uprobe
// headers fill in any missing fields (:method, :path, :authority).
// If no request exists yet, a placeholder is created so the response
// can still be matched later.
func (c *defaultCorrelator) InjectGoHTTP2Headers(
	key ConnectionKey,
	streamID uint32,
	headers map[string]string,
) {
	c.connToHTTP2StreamMu.Lock()
	defer c.connToHTTP2StreamMu.Unlock()

	streams, ok := c.connToHTTP2Stream[key]
	if !ok {
		streams = &HTTP2StreamRequests{
			Requests: make(map[uint32]PendingRequest),
		}
		c.connToHTTP2Stream[key] = streams
	}

	req, exists := streams.Requests[streamID]
	if !exists {
		// Create a placeholder request from uprobe headers alone.
		req = PendingRequest{
			Timestamp: time.Now(),
			StreamID:  streamID,
			Headers:   make(map[string]string),
		}
	}

	// Merge uprobe headers into the request.
	// Uprobe headers take precedence for pseudo-headers because they
	// are guaranteed correct (post-HPACK decoding), while kprobe data
	// may have null :path from mid-stream HPACK table misses.
	if path, ok := headers[":path"]; ok && path != "" {
		if req.URL == "" || req.URL == "null" {
			req.URL = path
			slog.Debug("Go uprobe: injected :path into pending request",
				"PID", key.PID, "FD", key.FD,
				"stream_id", streamID, "path", path)
		}
	}
	if method, ok := headers[":method"]; ok && method != "" {
		if req.Method == "" {
			req.Method = method
		}
	}
	if authority, ok := headers[":authority"]; ok && authority != "" {
		if req.Headers == nil {
			req.Headers = make(map[string]string)
		}
		if _, has := req.Headers[":authority"]; !has {
			req.Headers[":authority"] = authority
		}
	}

	// Also merge content-type for gRPC detection.
	if ct, ok := headers["content-type"]; ok && ct != "" {
		if req.ContentType == "" {
			req.ContentType = ct
		}
	}

	// Copy any remaining headers that the kprobe didn't capture.
	if req.Headers == nil {
		req.Headers = make(map[string]string)
	}
	for k, v := range headers {
		if _, has := req.Headers[k]; !has {
			req.Headers[k] = v
		}
	}

	streams.Requests[streamID] = req
}

// InjectGoGRPCEvent handles a complete gRPC request event from the Go uprobe
// pipeline. Each event contains the full path, status, and timing.
// This is a standalone event — no kprobe correlation needed for the path.
func (c *defaultCorrelator) InjectGoGRPCEvent(
	pid uint32, path string, status uint16, startNs, endNs uint64,
) {
	// Compute latency.
	var latencyNs uint64
	if endNs > startNs {
		latencyNs = endNs - startNs
	}

	slog.Info("Go uprobe gRPC event",
		"pid", pid,
		"path", path,
		"status", status,
		"latency_ns", latencyNs,
	)

	c.stats.totalRequests.Add(1)
	c.stats.totalResponses.Add(1)
	c.stats.matchedPairs.Add(1)
}

// Connection lifecycle

// CloseConnection flushes all pending requests for a connection.
// Must be called when a TCPCLOSE BPF event is received to avoid memory leaks.
func (c *defaultCorrelator) CloseConnection(key ConnectionKey) {
	var cleaned int

	c.connToHTTP1QueueMu.Lock()
	if q, ok := c.connToHTTP1Queue[key]; ok {
		cleaned += len(q.Requests)
		delete(c.connToHTTP1Queue, key)
	}
	c.connToHTTP1QueueMu.Unlock()

	c.connToHTTP2StreamMu.Lock()
	if streams, ok := c.connToHTTP2Stream[key]; ok {
		cleaned += len(streams.Requests)
		delete(c.connToHTTP2Stream, key)
	}
	c.connToHTTP2StreamMu.Unlock()

	if cleaned > 0 {
		c.stats.cleanedConnClose.Add(uint64(cleaned))
		slog.Debug("Correlator: connection closed, flushed pending",
			"sockptr", key.SockPtr, "flushed", cleaned)
	}
}

// Background cleanup — evicts stale requests.

// Stop cancels the cleanup goroutine.  Call during APIObserver shutdown.
func (c *defaultCorrelator) Stop() {
	c.cancel()
}

// cleanupLoop ticks every 10 seconds and evicts requests older than c.timeout.
func (c *defaultCorrelator) cleanupLoop() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			c.cleanup()
		case <-c.ctx.Done():
			return
		}
	}
}

// cleanup evicts stale requests from both HTTP/1 and HTTP/2 tables.
func (c *defaultCorrelator) cleanup() {
	cutoff := time.Now().Add(-c.timeout)
	var cleaned int

	// HTTP/1 cleanup.
	// Queues are time-ordered (FIFO: oldest at index 0, newest at tail).
	// if head is fresh, entire queue is fresh — skip with zero iterations.
	// else scan from front to find expiry boundary, then compact in-place.
	c.connToHTTP1QueueMu.Lock()
	for key, q := range c.connToHTTP1Queue {
		if len(q.Requests) == 0 {
			delete(c.connToHTTP1Queue, key)
			continue
		}

		if q.Requests[0].Timestamp.After(cutoff) {
			continue
		}

		i := 1
		for i < len(q.Requests) && !q.Requests[i].Timestamp.After(cutoff) {
			i++
		}
		cleaned += i

		if i == len(q.Requests) {
			// All requests expired
			delete(c.connToHTTP1Queue, key)
			continue
		}

		remaining := copy(q.Requests, q.Requests[i:])
		for j := remaining; j < len(q.Requests); j++ {
			q.Requests[j] = PendingRequest{}
		}
		q.Requests = q.Requests[:remaining]
	}
	c.connToHTTP1QueueMu.Unlock()

	c.connToHTTP2StreamMu.Lock()
	for key, streams := range c.connToHTTP2Stream {
		for sid, req := range streams.Requests {
			if !req.Timestamp.After(cutoff) {
				delete(streams.Requests, sid)
				cleaned++
			}
		}
		if len(streams.Requests) == 0 {
			delete(c.connToHTTP2Stream, key)
		}
	}
	c.connToHTTP2StreamMu.Unlock()

	if cleaned > 0 {
		c.stats.cleanedTimeout.Add(uint64(cleaned))
		slog.Debug("Correlator cleanup: evicted stale requests",
			"count", cleaned, "timeout", c.timeout)
	}
}

// Statistics

// GetStats returns a copy-safe snapshot of correlation counters.
func (c *defaultCorrelator) GetStats() CorrelatorStats {
	snap := CorrelatorStats{
		TotalRequests:      c.stats.totalRequests.Load(),
		TotalResponses:     c.stats.totalResponses.Load(),
		MatchedPairs:       c.stats.matchedPairs.Load(),
		UnmatchedResponses: c.stats.unmatchedResponses.Load(),
		PipelinedRequests:  c.stats.pipelinedRequests.Load(),
		HTTP2Streams:       c.stats.http2Streams.Load(),
		CleanedByReason: map[CleanupReason]uint64{
			ReasonTimeout:         c.stats.cleanedTimeout.Load(),
			ReasonBufferFull:      c.stats.cleanedBufferFull.Load(),
			ReasonConnectionClose: c.stats.cleanedConnClose.Load(),
		},
	}

	c.connToHTTP1QueueMu.Lock()
	snap.ActiveHTTP1Conns = len(c.connToHTTP1Queue)
	c.connToHTTP1QueueMu.Unlock()

	c.connToHTTP2StreamMu.Lock()
	snap.ActiveHTTP2Conns = len(c.connToHTTP2Stream)
	c.connToHTTP2StreamMu.Unlock()

	return snap
}
