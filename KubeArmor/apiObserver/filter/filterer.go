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
	"strconv"
	"strings"
	"time"

	cfg "github.com/kubearmor/KubeArmor/KubeArmor/config"
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
	var b strings.Builder
	b.Grow(len(clientIP) + 20 + len(method) + len(path) + len(status))
	b.WriteString(clientIP)
	b.WriteByte(':')
	b.WriteString(strconv.FormatInt(int64(clientPort), 10))
	b.WriteByte('|')
	b.WriteString(method)
	b.WriteByte('|')
	b.WriteString(path)
	b.WriteByte('|')
	b.WriteString(status)
	return f.dedup.IsDuplicate(b.String())
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
	// Don't drop events with unresolved addresses (family=0 from BPF).
	// These are valid TLS events where the BPF address resolution chain
	// didn't populate the source/destination IPs. Let them through so
	// the correlator can still produce traces.
	if isUnresolved(srcIP) || isUnresolved(dstIP) {
		return false
	}
	return isNonRoutable(srcIP) || isNonRoutable(dstIP) ||
		isHostLAN(srcIP) || isHostLAN(dstIP)
}

// isHostLAN returns true for private LAN IPs that are NOT part of the
// cluster pod/service CIDR. This filters host traffic (Firefox, NetworkManager)
// while preserving pod-to-pod and pod-to-service traffic.
func isHostLAN(ip string) bool {
	return strings.HasPrefix(ip, "192.168.")
}

// isUnresolved returns true when the BPF layer didn't resolve an address.
// This happens when the ks_go_user_kernel_write_context map lookup fails
// (family=0 → SrcIPString() returns "" or uint32ToIP(0) → "0.0.0.0").
func isUnresolved(ip string) bool {
	return ip == "" || ip == "0.0.0.0"
}

// isNonRoutable returns true for IPs that are never valid API traffic endpoints:
// loopback (127.x), multicast (224-239.x), link-local (169.254.x),
// broadcast (255.255.255.255).
func isNonRoutable(ip string) bool {
	if ip == "255.255.255.255" {
		return true
	}
	if strings.HasPrefix(ip, "127.") || strings.HasPrefix(ip, "169.254.") {
		return true
	}
	// Multicast: 224.0.0.0 – 239.255.255.255
	dot := strings.IndexByte(ip, '.')
	if dot > 0 && dot <= 3 {
		if oct, err := strconv.Atoi(ip[:dot]); err == nil && oct >= 224 && oct <= 239 {
			return true
		}
	}
	return false
}

// ShouldTraceConnection returns true when the connection endpoints pass
// namespace/pod exclusion filters.
// Skips traffic where EITHER endpoint is in an untracked namespace
// (configured via ConfigUntrackedNs, default: kube-system, kubearmor, agents).
// This prevents KubeArmor from observing its own control-plane traffic.
// NOTE: currently we are not resolving IPs to namespace
func (f *Filterer) ShouldTraceConnection(srcName, dstName, srcNS, dstNS string) bool {
	_ = srcName
	_ = dstName

	// Load untracked namespaces from global config.
	untrackedNs := cfg.GlobalCfg.ConfigUntrackedNs.Load()
	if untrackedNs != nil {
		if nsList, ok := untrackedNs.([]string); ok {
			for _, ns := range nsList {
				if srcNS == ns || dstNS == ns {
					return false
				}
			}
		}
	}
	return true
}

// infraGRPCServices lists gRPC service prefixes that are internal infrastructure
// and should never appear in user-facing API event streams. Traffic matching
// these services is dropped early to reduce capture + processing overhead.
var infraGRPCServices = []string{
	"spire.api.server.",          // SPIRE server APIs (entry, bundle, agent, etc.)
	"spire.api.agent.",           // SPIRE agent APIs
	"spire.plugin.",              // SPIRE plugin interfaces (keymanager, nodeattestor, etc.)
	"envoy.service.discovery.",   // Envoy xDS (ADS, CDS, LDS, etc.)
	"envoy.service.ext_proc.",    // Envoy external processing
}

// infraAuthorities lists :authority header values (exact or prefix) that
// indicate infrastructure traffic. Matched against the resolved authority.
var infraAuthorities = []string{
	"spire.api.server.",
	"spire-server",
	"spire-agent",
	"agents-operator.agents.svc.",
	"kubearmor-controller-webhook-service.agents.svc.",
}

// IsInfrastructureTraffic returns true when the request targets a known
// infrastructure gRPC service or authority. This filters SPIRE, Envoy xDS,
// and other control-plane traffic that appears as noise in the API event stream.
// User-configured authorities (via ConfigApiBlockedAuthorities) are merged
// with the built-in defaults.
func (f *Filterer) IsInfrastructureTraffic(authority, grpcService string) bool {
	for _, prefix := range infraGRPCServices {
		if strings.HasPrefix(grpcService, prefix) {
			return true
		}
	}
	for _, prefix := range infraAuthorities {
		if strings.HasPrefix(authority, prefix) {
			return true
		}
	}
	// Check user-configured blocked authorities from config.
	if extra := cfg.GlobalCfg.ConfigApiBlockedAuthorities.Load(); extra != nil {
		if list, ok := extra.([]string); ok {
			for _, prefix := range list {
				prefix = strings.TrimSpace(prefix)
				if prefix != "" && strings.HasPrefix(authority, prefix) {
					return true
				}
			}
		}
	}
	return false
}

