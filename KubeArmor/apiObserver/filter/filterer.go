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

import (
	"fmt"
	"strings"
	"time"
)

type Filterer struct {
	dedup *DedupCache
}

// NewFilterer creates a Filterer with default (pass-everything) rules.
func NewFilterer() *Filterer {
	return &Filterer{
		dedup: NewDedupCache(100 * time.Millisecond),
	}
}

// IsDuplicate returns true if this event was already seen within the dedup
// window. The key is constructed from sorted IPs (so client/server
// observations hash identically), method, path, and status.
func (f *Filterer) IsDuplicate(srcIP, dstIP string, srcPort, dstPort int32, method, path, status string) bool {
	// The client's ephemeral port (higher number) uniquely identifies the
	// TCP connection.  It's constant regardless of whether we see the pod IP
	// or the service VIP as the server — only the server-side IP changes.
	// By keying on (clientIP, ephemeralPort, method, path, status) we dedup
	// pod-vs-service duplicates without losing any unique requests.
	var clientIP string
	var clientPort int32
	if srcPort > dstPort {
		clientIP = srcIP
		clientPort = srcPort
	} else {
		clientIP = dstIP
		clientPort = dstPort
	}
	key := clientIP + ":" + fmt.Sprint(clientPort) + "|" + method + "|" + path + "|" + status
	return f.dedup.IsDuplicate(key)
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
	return isNonRoutable(srcIP) || isNonRoutable(dstIP) ||
		isHostLAN(srcIP) || isHostLAN(dstIP)
}

// isHostLAN returns true for private LAN IPs that are NOT part of the
// cluster pod/service CIDR. This filters host traffic (Firefox, NetworkManager)
// while preserving pod-to-pod and pod-to-service traffic.
func isHostLAN(ip string) bool {
	return strings.HasPrefix(ip, "192.168.")
}

// isNonRoutable returns true for IPs that are never valid API traffic endpoints:
// loopback (127.x), multicast (224-239.x), link-local (169.254.x),
// broadcast (255.255.255.255), and unspecified (0.0.0.0).
func isNonRoutable(ip string) bool {
	if ip == "" || ip == "0.0.0.0" || ip == "255.255.255.255" {
		return true
	}
	return strings.HasPrefix(ip, "127.") ||
		strings.HasPrefix(ip, "224.") ||
		strings.HasPrefix(ip, "225.") ||
		strings.HasPrefix(ip, "226.") ||
		strings.HasPrefix(ip, "227.") ||
		strings.HasPrefix(ip, "228.") ||
		strings.HasPrefix(ip, "229.") ||
		strings.HasPrefix(ip, "230.") ||
		strings.HasPrefix(ip, "231.") ||
		strings.HasPrefix(ip, "232.") ||
		strings.HasPrefix(ip, "233.") ||
		strings.HasPrefix(ip, "234.") ||
		strings.HasPrefix(ip, "235.") ||
		strings.HasPrefix(ip, "236.") ||
		strings.HasPrefix(ip, "237.") ||
		strings.HasPrefix(ip, "238.") ||
		strings.HasPrefix(ip, "239.") ||
		strings.HasPrefix(ip, "169.254.")
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

