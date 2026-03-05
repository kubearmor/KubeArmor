// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

// Package events: types.go defines the internal Go types that flow between
// the stream reassembler, protocol parsers, and the correlator.

package events

import "time"

// PendingRequest is stored in the Correlator until a matching response
// arrives or the request times out.
type PendingRequest struct {
	// Populated from the BPF DataEvent.
	Timestamp time.Time
	Src       string
	Dst       string

	// Populated from protocol parser output.
	Method        string
	URL           string
	Headers       map[string]string
	Body          string
	ContentLength int64

	// HTTP/2 and gRPC stream identifier; 0 for HTTP/1.
	StreamID uint32

	IsEncrypted bool
}

// CorrelatedTrace is produced by the Correlator when a request and its
// response have been matched. It is converted to pb.APIEvent in
// apiObserver.go:convertToAPIEvent before being handed to the feeder.
type CorrelatedTrace struct {
	// When the request arrived (from BPF event timestamp).
	Timestamp time.Time

	Method string
	URL    string
	Status string 

	// observer latency
	DurationMs int64

	// ip:port
	Src string 
	Dst string 

	RequestHeaders  map[string]string
	ResponseHeaders map[string]string
	RequestBody     string
	ResponseBody    string

	// HTTP/2 / gRPC stream identifier; 0 for HTTP/1.
	StreamID uint32
	IsEncrypted bool
}

// RequestQueue is the per-connection state for HTTP/1.x correlation.
// HTTP/1.1 allows pipelining — multiple requests may be
// in-flight before the first response, and responses MUST be sent in the
// same order as requests.
type RequestQueue struct {
	Requests []PendingRequest // FIFO
}

// HTTP2StreamRequests is the per-connection state for HTTP/2 correlation.
// Each stream ID independently holds one in-flight request.
// Stream IDs are odd for client-initiated streams (RFC 7540 §5.1.1).
type HTTP2StreamRequests struct {
	Requests map[uint32]PendingRequest // stream ID -> pending request
}

// StreamState tracks the current lifecycle state of an HTTP/2 stream.
type StreamState int

const (
	// StreamOpen: HEADERS frame received, no END_STREAM seen yet.
	StreamOpen StreamState = iota

	// StreamHalfClosed: END_STREAM seen in one direction.
	StreamHalfClosed

	// StreamClosed: RST_STREAM received or END_STREAM on both sides.
	StreamClosed
)

// CleanupReason is used in CorrelatorStats to distinguish eviction causes.
type CleanupReason int

const (
	// ReasonTimeout: request waited longer than Correlator.timeout.
	ReasonTimeout CleanupReason = iota

	// ReasonConnectionClose: connection was closed before response arrived.
	ReasonConnectionClose

	// ReasonBufferFull: per-connection queue exceeded maxPendingPerConn.
	ReasonBufferFull
)
