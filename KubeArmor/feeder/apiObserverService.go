// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

// Package feeder: apiObserverService.go implements the gRPC streaming
// service for API observability events.  It mirrors logServer.go's pattern
// (replacing pb.Log with pb.APIEvent) and is owned by the Feeder, not by
// the APIObserver.
//
// Data flow (Pixie sockettraceconnector.cc → data table export):
//
//	APIObserver.processMessage()
//	  → feeder.PushAPIEvent(pb.APIEvent)           [handoff point]
//	    → APIObserverService.PublishEvent()         [fan-out]
//	      → subscriber.ch (buffered)
//	        → stream.Send()                         [gRPC to client]
package feeder

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	pb "github.com/accuknox/SentryFlow/protobuf/golang"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	kl "github.com/kubearmor/KubeArmor/KubeArmor/common"
	kg "github.com/kubearmor/KubeArmor/KubeArmor/log"
)

// ═══════════════════════════════════════════════════════════════════════════
// APIObserverService — gRPC service + internal event bus
// ═══════════════════════════════════════════════════════════════════════════

type APIObserverService struct {
	pb.UnimplementedAPIObserverServiceServer

	subscribers   map[string]*apiEventSubscriber
	subscribersMu sync.RWMutex

	metrics metricsAggregator
	running bool
}

type apiEventSubscriber struct {
	id     string
	filter *pb.APIEventFilter
	ch     chan *pb.APIEvent
	ctx    context.Context
	cancel context.CancelFunc
}

type metricsAggregator struct {
	mu                sync.RWMutex
	totalEvents       uint64
	eventsByProtocol  map[string]uint64
	eventsByStatus    map[string]uint64
	endpointCounts    map[string]uint64
	endpointLatencies map[string][]int64
}

func NewAPIObserverService(running bool) *APIObserverService {
	return &APIObserverService{
		subscribers: make(map[string]*apiEventSubscriber),
		metrics: metricsAggregator{
			eventsByProtocol:  make(map[string]uint64),
			eventsByStatus:    make(map[string]uint64),
			endpointCounts:    make(map[string]uint64),
			endpointLatencies: make(map[string][]int64),
		},
		running: running,
	}
}

func (s *APIObserverService) GetAPIEvents(
	filter *pb.APIEventFilter,
	stream grpc.ServerStreamingServer[pb.APIEvent],
) error {
	if !s.running {
		return status.Error(codes.Unavailable, "API Observer service is not running")
	}
	sub := s.createSubscriber(filter, stream.Context())
	defer s.removeSubscriber(sub)

	kg.Printf("API event subscriber connected: id=%s filter=%v", sub.id, filter)

	for {
		select {
		case event, ok := <-sub.ch:
			if !ok {
				return nil
			}
			if !matchesFilter(event, filter) {
				continue
			}
			if err := stream.Send(event); err != nil {
				kg.Warnf("Error sending to subscriber %s: %v", sub.id, err)
				return err
			}
		case <-sub.ctx.Done():
			return sub.ctx.Err()
		case <-stream.Context().Done():
			return stream.Context().Err()
		}
	}
}

func (s *APIObserverService) GetAPIMetrics(
	_ context.Context,
	req *pb.MetricsRequest,
) (*pb.APIObserverMetrics, error) {
	if !s.running {
		return nil, status.Error(codes.Unavailable, "API Observer service is not running")
	}
	s.metrics.mu.RLock()
	defer s.metrics.mu.RUnlock()

	// ✅ Changed: &pb.APIMetrics{} → &pb.APIObserverMetrics{}
	return &pb.APIObserverMetrics{
		Timestamp:            kl.GetCurrentTimeStamp(),
		TotalEvents:          s.metrics.totalEvents,
		EventsByProtocol:     cloneMapSU64(s.metrics.eventsByProtocol),
		EventsByStatus:       cloneMapSU64(s.metrics.eventsByStatus),
		TopEndpoints:         s.topEndpointsLocked(),
		AvgLatencyByEndpoint: s.avgLatencyMapLocked(),
		ErrorRate:            s.errorRateLocked(),
	}, nil
}

// ═══════════════════════════════════════════════════════════════════════════
// Internal API — called by feeder.PushAPIEvent
// ═══════════════════════════════════════════════════════════════════════════

func (s *APIObserverService) PublishEvent(event pb.APIEvent) {
	s.updateMetrics(event)
	ptr := &event

	s.subscribersMu.RLock()
	defer s.subscribersMu.RUnlock()

	for _, sub := range s.subscribers {
		select {
		case sub.ch <- ptr:
		default:
			kg.Warnf("Subscriber %s channel full, dropping API event", sub.id)
		}
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// Subscriber lifecycle
// ═══════════════════════════════════════════════════════════════════════════

func (s *APIObserverService) createSubscriber(
	filter *pb.APIEventFilter,
	parentCtx context.Context,
) *apiEventSubscriber {
	ctx, cancel := context.WithCancel(parentCtx)
	sub := &apiEventSubscriber{
		id:     uuid.New().String()[:16],
		filter: filter,
		ch:     make(chan *pb.APIEvent, 1024),
		ctx:    ctx,
		cancel: cancel,
	}
	s.subscribersMu.Lock()
	s.subscribers[sub.id] = sub
	s.subscribersMu.Unlock()
	return sub
}

func (s *APIObserverService) removeSubscriber(sub *apiEventSubscriber) {
	sub.cancel()
	s.subscribersMu.Lock()
	delete(s.subscribers, sub.id)
	s.subscribersMu.Unlock()
	close(sub.ch)
	kg.Printf("API event subscriber disconnected: %s", sub.id)
}

// ═══════════════════════════════════════════════════════════════════════════
// Filter matching
// ═══════════════════════════════════════════════════════════════════════════

func matchesFilter(event *pb.APIEvent, f *pb.APIEventFilter) bool {
	if f == nil {
		return true
	}
	if f.Namespace != "" {
		ns := ""
		if event.Source != nil {
			ns = event.Source.Namespace
		}
		if ns != f.Namespace {
			return false
		}
	}
	if f.PodName != "" {
		pod := ""
		if event.Source != nil {
			pod = event.Source.Name
		}
		if !wildcardMatch(pod, f.PodName) {
			return false
		}
	}
	if len(f.Protocols) > 0 && !sliceContains(f.Protocols, event.Protocol) {
		return false
	}
	if len(f.Methods) > 0 {
		method := ""
		if event.Request != nil {
			method = event.Request.Method
		}
		if !sliceContains(f.Methods, method) {
			return false
		}
	}
	if len(f.StatusPatterns) > 0 {
		code := ""
		if event.Response != nil {
			code = fmt.Sprintf("%d", event.Response.StatusCode)
		}
		matched := false
		for _, p := range f.StatusPatterns {
			if statusPatternMatch(code, p) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	if f.MinDurationMs > 0 {
		var d int64
		if event.LatencyNs > 0 {
			d = int64(event.LatencyNs / 1_000_000)
		}
		if d < f.MinDurationMs {
			return false
		}
	}
	return true
}

// ═══════════════════════════════════════════════════════════════════════════
// Metrics helpers
// ═══════════════════════════════════════════════════════════════════════════

func (s *APIObserverService) updateMetrics(event pb.APIEvent) {
	s.metrics.mu.Lock()
	defer s.metrics.mu.Unlock()

	s.metrics.totalEvents++
	s.metrics.eventsByProtocol[event.Protocol]++

	code := ""
	if event.Response != nil {
		code = fmt.Sprintf("%d", event.Response.StatusCode)
	}
	s.metrics.eventsByStatus[code]++

	method, path := "", ""
	if event.Request != nil {
		method, path = event.Request.Method, event.Request.Path
	}
	endpoint := method + " " + path

	var dur int64
	if event.LatencyNs > 0 {
		dur = int64(event.LatencyNs / 1_000_000)
	}
	s.metrics.endpointCounts[endpoint]++
	s.metrics.endpointLatencies[endpoint] = append(s.metrics.endpointLatencies[endpoint], dur)
}

func (s *APIObserverService) topEndpointsLocked() []*pb.EndpointMetric {
	out := make([]*pb.EndpointMetric, 0, len(s.metrics.endpointCounts))
	for ep, count := range s.metrics.endpointCounts {
		lats := s.metrics.endpointLatencies[ep]
		parts := strings.SplitN(ep, " ", 2)
		method, path := "", ep
		if len(parts) == 2 {
			method, path = parts[0], parts[1]
		}
		out = append(out, &pb.EndpointMetric{
			Method:       method,
			Path:         path,
			RequestCount: count,
			AvgLatencyMs: calcAvg(lats),
			P95LatencyMs: calcPct(lats, 0.95),
			P99LatencyMs: calcPct(lats, 0.99),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].RequestCount > out[j].RequestCount
	})
	if len(out) > 20 {
		out = out[:20]
	}
	return out
}

func (s *APIObserverService) avgLatencyMapLocked() map[string]float64 {
	m := make(map[string]float64, len(s.metrics.endpointLatencies))
	for ep, lats := range s.metrics.endpointLatencies {
		m[ep] = calcAvg(lats)
	}
	return m
}

func (s *APIObserverService) errorRateLocked() float64 {
	if s.metrics.totalEvents == 0 {
		return 0
	}
	var errs uint64
	for code, n := range s.metrics.eventsByStatus {
		if strings.HasPrefix(code, "4") || strings.HasPrefix(code, "5") {
			errs += n
		}
	}
	return float64(errs) / float64(s.metrics.totalEvents) * 100.0
}

// ═══════════════════════════════════════════════════════════════════════════
// Pure utility functions
// ═══════════════════════════════════════════════════════════════════════════

func wildcardMatch(value, pattern string) bool {
	if pattern == "*" {
		return true
	}
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(value, strings.TrimSuffix(pattern, "*"))
	}
	return value == pattern
}

func statusPatternMatch(code, pattern string) bool {
	if len(pattern) == 3 && pattern[1] == 'x' && pattern[2] == 'x' {
		return len(code) > 0 && code[0] == pattern[0]
	}
	return code == pattern
}

func sliceContains(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}

func cloneMapSU64(m map[string]uint64) map[string]uint64 {
	out := make(map[string]uint64, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func calcAvg(vals []int64) float64 {
	if len(vals) == 0 {
		return 0
	}
	var s int64
	for _, v := range vals {
		s += v
	}
	return float64(s) / float64(len(vals))
}

func calcPct(vals []int64, pct float64) float64 {
	if len(vals) == 0 {
		return 0
	}
	cp := make([]int64, len(vals))
	copy(cp, vals)
	sort.Slice(cp, func(i, j int) bool { return cp[i] < cp[j] })
	idx := int(float64(len(cp)) * pct)
	if idx >= len(cp) {
		idx = len(cp) - 1
	}
	return float64(cp[idx])
}
