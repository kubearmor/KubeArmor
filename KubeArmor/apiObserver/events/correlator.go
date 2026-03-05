// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

// Package events: correlator.go implements request-response matching.
//
//
//   HTTP/1.x — FIFO queue per connection (httpstitcher.cc)
//     Requests are queued in arrival order.  Responses pop the head.
//     This correctly handles HTTP/1.1 pipelining (RFC 7230 §6.3.2).
//
//   HTTP/2 / gRPC — per-stream-ID map per connection (http2stitcher.cc)
//     Each stream ID gets its own slot.  Responses look up by stream ID.
//     This handles full stream multiplexing (RFC 7540 §5).
//
// A background cleanup goroutine evicts requests older than the configured
// timeout to prevent unbounded memory growth on half-open connections.
package events

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// maxPendingPerConn is the maximum number of in-flight HTTP/1.x pipelined
// requests allowed per connection before old ones are dropped.
const maxPendingPerConn = 256

// Correlator interface — enables mocking in feedertest.go and unit tests.

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

	// CloseConnection flushes all pending requests for a connection.
	// Called when a TCPCLOSE event is received.
	CloseConnection(key ConnectionKey)

	// Stop cancels the cleanup goroutine.
	Stop()

	// GetStats returns a snapshot of correlation statistics.
	GetStats() CorrelatorStats
}

// CorrelatorStats — observable metrics.

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

// correlatorImpl — concrete implementation.

type correlatorImpl struct {
	// HTTP/1.x: per-connection FIFO queue (supports pipelining).
	http1Pending   map[ConnectionKey]*RequestQueue
	http1PendingMu sync.Mutex // protects http1Pending map and queue contents

	// HTTP/2 / gRPC: per-connection, per-stream-ID pending request map.
	http2Pending   map[ConnectionKey]*HTTP2StreamRequests
	http2PendingMu sync.Mutex // protects http2Pending map and stream contents

	timeout time.Duration

	// stats is guarded by statsMu.
	stats   CorrelatorStats
	statsMu sync.Mutex

	ctx    context.Context
	cancel context.CancelFunc
}

// NewCorrelator creates a Correlator with the given request-timeout.
// Requests not matched within timeout are silently evicted by the cleanup loop.
//
func NewCorrelator(timeout time.Duration) Correlator {
	ctx, cancel := context.WithCancel(context.Background())
	c := &correlatorImpl{
		http1Pending: make(map[ConnectionKey]*RequestQueue),
		http2Pending: make(map[ConnectionKey]*HTTP2StreamRequests),
		timeout:      timeout,
		stats: CorrelatorStats{
			CleanedByReason: make(map[CleanupReason]uint64),
		},
		ctx:    ctx,
		cancel: cancel,
	}
	go c.cleanupLoop()
	return c
}

// HTTP/1.x FIFO methods

// AddHTTP1Request enqueues req into the per-connection FIFO queue.
// If the queue is full (maxPendingPerConn), the oldest request is evicted.
func (c *correlatorImpl) AddHTTP1Request(key ConnectionKey, req PendingRequest) {
	c.http1PendingMu.Lock()
	defer c.http1PendingMu.Unlock()

	q, ok := c.http1Pending[key]
	if !ok {
		q = &RequestQueue{Requests: make([]PendingRequest, 0, 4)}
		c.http1Pending[key] = q
	}

	// Enforce per-connection cap.
	if len(q.Requests) >= maxPendingPerConn {
		q.Requests = q.Requests[1:] // evict oldest
		c.bumpCleaned(ReasonBufferFull)
	}

	isPipelined := len(q.Requests) > 0
	q.Requests = append(q.Requests, req)

	c.statsMu.Lock()
	c.stats.TotalRequests++
	if isPipelined {
		c.stats.PipelinedRequests++
	}
	c.statsMu.Unlock()

	slog.Debug("HTTP/1 request queued",
		"sockptr", key.SockPtr,
		"method", req.Method,
		"url", req.URL,
		"depth", len(q.Requests),
	)
}

// MatchHTTP1Response dequeues the head of the FIFO queue and returns the
// matched CorrelatedTrace.  Returns nil if no pending request exists.
func (c *correlatorImpl) MatchHTTP1Response(
	key ConnectionKey,
	status string,
	respHeaders map[string]string,
	respBody string,
	serverURI string,
) *CorrelatedTrace {
	c.http1PendingMu.Lock()
	defer c.http1PendingMu.Unlock()

	q, ok := c.http1Pending[key]
	if !ok || len(q.Requests) == 0 {
		c.bumpUnmatched()
		return nil
	}

	// Pop the head (FIFO — oldest request matches oldest response).
	req := q.Requests[0]
	q.Requests = q.Requests[1:]
	if len(q.Requests) == 0 {
		delete(c.http1Pending, key)
	}

	now := time.Now()
	durationMs := now.Sub(req.Timestamp).Milliseconds()

	trace := &CorrelatedTrace{
		Timestamp:       req.Timestamp,
		Method:          req.Method,
		URL:             req.URL,
		Status:          status,
		DurationMs:      durationMs,
		Src:             req.Src,
		Dst:             serverURI,
		RequestHeaders:  req.Headers,
		RequestBody:     req.Body,
		ResponseHeaders: respHeaders,
		ResponseBody:    respBody,
		IsEncrypted:     req.IsEncrypted,
	}

	c.statsMu.Lock()
	c.stats.TotalResponses++
	c.stats.MatchedPairs++
	c.statsMu.Unlock()

	slog.Debug("HTTP/1 request-response matched",
		"sockptr", key.SockPtr,
		"method", req.Method,
		"status", status,
		"duration_ms", durationMs,
		"queue_remaining", len(q.Requests),
	)
	return trace
}

// HTTP/2 / gRPC stream-ID methods

// AddHTTP2Request stores req under (key, streamID).
// Multiple streams on the same connection are fully independent.
func (c *correlatorImpl) AddHTTP2Request(
	key ConnectionKey,
	streamID uint32,
	req PendingRequest,
) {
	c.http2PendingMu.Lock()
	defer c.http2PendingMu.Unlock()

	streams, ok := c.http2Pending[key]
	if !ok {
		streams = &HTTP2StreamRequests{
			Requests: make(map[uint32]PendingRequest),
		}
		c.http2Pending[key] = streams
	}

	req.StreamID = streamID
	streams.Requests[streamID] = req

	c.statsMu.Lock()
	c.stats.TotalRequests++
	c.stats.HTTP2Streams++
	c.statsMu.Unlock()

	slog.Debug("HTTP/2 request stored",
		"sockptr", key.SockPtr,
		"stream_id", streamID,
		"method", req.Method,
		"url", req.URL,
	)
}

// MatchHTTP2Response looks up the pending request for (key, streamID),
// removes it, and returns the CorrelatedTrace.  Returns nil if not found.
func (c *correlatorImpl) MatchHTTP2Response(
	key ConnectionKey,
	streamID uint32,
	status string,
	respHeaders map[string]string,
	respBody string,
	serverURI string,
) *CorrelatedTrace {
	c.http2PendingMu.Lock()
	defer c.http2PendingMu.Unlock()

	streams, ok := c.http2Pending[key]
	if !ok {
		c.bumpUnmatched()
		return nil
	}

	req, ok := streams.Requests[streamID]
	if !ok {
		c.bumpUnmatched()
		return nil
	}
	delete(streams.Requests, streamID)
	if len(streams.Requests) == 0 {
		delete(c.http2Pending, key)
	}

	now := time.Now()
	durationMs := now.Sub(req.Timestamp).Milliseconds()

	trace := &CorrelatedTrace{
		Timestamp:       req.Timestamp,
		Method:          req.Method,
		URL:             req.URL,
		Status:          status,
		DurationMs:      durationMs,
		Src:             req.Src,
		Dst:             serverURI,
		RequestHeaders:  req.Headers,
		RequestBody:     req.Body,
		ResponseHeaders: respHeaders,
		ResponseBody:    respBody,
		StreamID:        streamID,
		IsEncrypted:     req.IsEncrypted,
	}

	c.statsMu.Lock()
	c.stats.TotalResponses++
	c.stats.MatchedPairs++
	c.statsMu.Unlock()

	slog.Debug("HTTP/2 request-response matched",
		"sockptr", key.SockPtr,
		"stream_id", streamID,
		"method", req.Method,
		"status", status,
		"duration_ms", durationMs,
	)
	return trace
}

// Connection lifecycle

// CloseConnection flushes all pending requests for a connection.
// Must be called when a TCPCLOSE BPF event is received to avoid memory leaks.
func (c *correlatorImpl) CloseConnection(key ConnectionKey) {
	var cleaned int

	c.http1PendingMu.Lock()
	if q, ok := c.http1Pending[key]; ok {
		cleaned += len(q.Requests)
		delete(c.http1Pending, key)
	}
	c.http1PendingMu.Unlock()

	c.http2PendingMu.Lock()
	if streams, ok := c.http2Pending[key]; ok {
		cleaned += len(streams.Requests)
		delete(c.http2Pending, key)
	}
	c.http2PendingMu.Unlock()

	if cleaned > 0 {
		c.statsMu.Lock()
		c.stats.CleanedByReason[ReasonConnectionClose] += uint64(cleaned)
		c.statsMu.Unlock()
		slog.Debug("Correlator: connection closed, flushed pending",
			"sockptr", key.SockPtr, "flushed", cleaned)
	}
}

// Background cleanup — evicts stale requests.

// Stop cancels the cleanup goroutine.  Call during APIObserver shutdown.
func (c *correlatorImpl) Stop() {
	c.cancel()
}

// cleanupLoop ticks every 10 seconds and evicts requests older than c.timeout.
func (c *correlatorImpl) cleanupLoop() {
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
func (c *correlatorImpl) cleanup() {
	cutoff := time.Now().Add(-c.timeout)
	var cleaned int

	// HTTP/1 cleanup.
	c.http1PendingMu.Lock()
	for key, q := range c.http1Pending {
		valid := q.Requests[:0]
		for _, req := range q.Requests {
			if req.Timestamp.After(cutoff) {
				valid = append(valid, req)
			} else {
				cleaned++
			}
		}
		if len(valid) == 0 {
			delete(c.http1Pending, key)
		} else {
			q.Requests = valid
		}
	}
	c.http1PendingMu.Unlock()

	// HTTP/2 cleanup.
	c.http2PendingMu.Lock()
	for key, streams := range c.http2Pending {
		for sid, req := range streams.Requests {
			if !req.Timestamp.After(cutoff) {
				delete(streams.Requests, sid)
				cleaned++
			}
		}
		if len(streams.Requests) == 0 {
			delete(c.http2Pending, key)
		}
	}
	c.http2PendingMu.Unlock()

	if cleaned > 0 {
		c.statsMu.Lock()
		c.stats.CleanedByReason[ReasonTimeout] += uint64(cleaned)
		c.statsMu.Unlock()
		slog.Debug("Correlator cleanup: evicted stale requests",
			"count", cleaned, "timeout", c.timeout)
	}
}

// Statistics

// GetStats returns a copy-safe snapshot of correlation counters.
func (c *correlatorImpl) GetStats() CorrelatorStats {
	c.statsMu.Lock()
	snap := CorrelatorStats{
		TotalRequests:      c.stats.TotalRequests,
		TotalResponses:     c.stats.TotalResponses,
		MatchedPairs:       c.stats.MatchedPairs,
		UnmatchedResponses: c.stats.UnmatchedResponses,
		PipelinedRequests:  c.stats.PipelinedRequests,
		HTTP2Streams:       c.stats.HTTP2Streams,
		CleanedByReason:    make(map[CleanupReason]uint64, len(c.stats.CleanedByReason)),
	}
	for k, v := range c.stats.CleanedByReason {
		snap.CleanedByReason[k] = v
	}
	c.statsMu.Unlock()

	c.http1PendingMu.Lock()
	snap.ActiveHTTP1Conns = len(c.http1Pending)
	c.http1PendingMu.Unlock()

	c.http2PendingMu.Lock()
	snap.ActiveHTTP2Conns = len(c.http2Pending)
	c.http2PendingMu.Unlock()

	return snap
}

// Private helpers

func (c *correlatorImpl) bumpUnmatched() {
	c.statsMu.Lock()
	c.stats.UnmatchedResponses++
	c.statsMu.Unlock()
}

func (c *correlatorImpl) bumpCleaned(reason CleanupReason) {
	c.statsMu.Lock()
	c.stats.CleanedByReason[reason]++
	c.statsMu.Unlock()
}
