// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

// Package feeder: apiObserverService.go implements the gRPC streaming
// service for API observability events.

package feeder

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"

	pb "github.com/accuknox/SentryFlow/protobuf/golang"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	kg "github.com/kubearmor/KubeArmor/KubeArmor/log"
)

// ═══════════════════════════════════════════════════════════════════════════
// APIObserverService — gRPC service + internal event bus
// ═══════════════════════════════════════════════════════════════════════════

type APIObserverService struct {
	pb.UnimplementedAPIObserverServiceServer

	subscribers   map[string]*apiEventSubscriber
	subscribersMu sync.RWMutex

	// running is a pointer to the feeder's atomic Running flag so that
	// GetAPIEvents sees the live value set by DestroyFeeder.
	running *atomic.Bool
}

type apiEventSubscriber struct {
	id     string
	filter *pb.APIEventFilter
	ch     chan *pb.APIEvent
	ctx    context.Context
	cancel context.CancelFunc
}

func NewAPIObserverService(running *atomic.Bool) *APIObserverService {
	return &APIObserverService{
		subscribers: make(map[string]*apiEventSubscriber),
		running:     running,
	}
}

func (s *APIObserverService) GetAPIEvents(
	filter *pb.APIEventFilter,
	stream grpc.ServerStreamingServer[pb.APIEvent],
) error {
	if !s.running.Load() {
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

// ═══════════════════════════════════════════════════════════════════════════
// Internal API — called by feeder.PushAPIEvent
// ═══════════════════════════════════════════════════════════════════════════

func (s *APIObserverService) PublishEvent(event *pb.APIEvent) {
	s.subscribersMu.RLock()
	defer s.subscribersMu.RUnlock()

	for _, sub := range s.subscribers {
		select {
		case sub.ch <- event:
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
		if req := event.GetRequest(); req != nil {
			method = req.Method
		}
		if !sliceContains(f.Methods, method) {
			return false
		}
	}
	if len(f.StatusPatterns) > 0 {
		code := ""
		if res := event.GetResponse(); res != nil {
			code = fmt.Sprintf("%d", res.StatusCode)
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
		if int64(event.LatencyMs) < f.MinDurationMs {
			return false
		}
	}
	return true
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
