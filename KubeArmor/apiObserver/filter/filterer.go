// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

// Package filter implements request- and connection-level filtering for
// the API Observer pipeline.
//
// The Filterer decides which HTTP/gRPC events are emitted to the feeder
// and which are silently dropped (health probes, loopback traffic, excluded
// namespaces, etc.).
//
// TODO: make filter rules configurable via KubeArmorConfig or CRD annotation.

package filter

import "strings"

type Filterer struct {
	// TODO: populate from config (excluded paths, user-agents, namespaces).
}

// NewFilterer creates a Filterer with default (pass-everything) rules.
func NewFilterer() *Filterer {
	return &Filterer{}
}

// ShouldTraceRequest returns true when the request URL and User-Agent
// pass the path/UA exclusion list.
// TODO: add configurable path exclusions (e.g. /healthz, /readyz, /metrics).
func (f *Filterer) ShouldTraceRequest(url, userAgent string) bool {
	_ = url
	_ = userAgent
	return true
}

// IsHealthProbe returns true when the request appears to be a Kubernetes
// liveness/readiness probe.
func (f *Filterer) IsHealthProbe(url, userAgent, responseBody string) bool {
	for _, p := range []string{"/healthz", "/readyz", "/livez", "/health"} {
		if strings.HasPrefix(url, p) {
			return true
		}
	}
	for _, ua := range []string{"kube-probe/", "GoogleHC/"} {
		if strings.Contains(userAgent, ua) {
			return true
		}
	}
	if strings.Contains(responseBody, `"health":[`) {
		return true
	}
	return false
}

func (f *Filterer) IsLoopbackTraffic(srcIP, dstIP string) bool {
	return strings.HasPrefix(srcIP, "127.") && strings.HasPrefix(dstIP, "127.")
}

// ShouldTraceConnection returns true when the connection endpoints pass
// namespace/pod exclusion filters.
// TODO: add configurable namespace exclusions via KubeArmorConfig.
func (f *Filterer) ShouldTraceConnection(srcName, dstName, srcNS, dstNS string) bool {
	_ = srcName
	_ = dstName
	// Skip traffic entirely within kube-system.
	if srcNS == "kube-system" && dstNS == "kube-system" {
		return false
	}
	return true
}

// IsInternalHop returns true when both source and destination are known
// workloads (both have non-empty pod names), indicating this event is a
// service-to-service hop captured by kprobes on an intermediate node.
//
// Since we use sockptr-based keying, we filter multi-hop events here:
// if both sides are resolved pods, it's likely a duplicate observation
// of a request already captured at the ingress edge.
func (f *Filterer) IsInternalHop(srcName, dstName, srcNS, dstNS string) bool {
	if srcName != "" && dstName != "" && srcNS != "" && dstNS != "" {
		if srcNS != dstNS {
			return true
		}
	}
	return false
}
