// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package apiobserver

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	pb "github.com/accuknox/SentryFlow/protobuf/golang"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/kubearmor/KubeArmor/KubeArmor/apiObserver/cgroup"
	"github.com/kubearmor/KubeArmor/KubeArmor/apiObserver/dissector"
	"github.com/kubearmor/KubeArmor/KubeArmor/apiObserver/events"
	"github.com/kubearmor/KubeArmor/KubeArmor/apiObserver/filter"
	"github.com/kubearmor/KubeArmor/KubeArmor/apiObserver/goprobe"
	"github.com/kubearmor/KubeArmor/KubeArmor/apiObserver/grpcc"
	"github.com/kubearmor/KubeArmor/KubeArmor/apiObserver/poller"
	"github.com/kubearmor/KubeArmor/KubeArmor/apiObserver/procsocket"
	"github.com/kubearmor/KubeArmor/KubeArmor/apiObserver/ssl"
	cfg "github.com/kubearmor/KubeArmor/KubeArmor/config"
	fd "github.com/kubearmor/KubeArmor/KubeArmor/feeder"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
	probe "github.com/kubearmor/KubeArmor/KubeArmor/utils/bpflsmprobe"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64,arm64 -cc clang apiObserver ../BPF/api_observer.bpf.c

// ServiceResolver maps a ClusterIP to a K8s service FQDN (e.g.
// "cartservice.online-boutique.svc.cluster.local"). Returns empty
// string when no match found. Injected by the core daemon.
type ServiceResolver func(ip string) string

// APIObserver captures and processes network events via eBPF.
type APIObserver struct {
	Logger *fd.Feeder

	nodeName         string
	resolveServiceFn ServiceResolver
	resolvePodFn     PodResolver

	// BPF compiled objects and attached probe links.
	objs    apiObserverObjects
	links   []io.Closer // lifecycle-level links (kprobes, tracepoints, host SSL)
	linksMu sync.Mutex

	// Per-inode uprobe links for O(1) cleanup on container exit.
	linksByInode   map[uint64][]io.Closer
	linksByInodeMu sync.Mutex

	// Unified /proc scanner — replaces the three independent 30s walkers.
	procWalker *UnifiedProcWalker

	// execWatcher reads BPF ka_found_pid_events (sched_process_fork+sys_execve)
	// and attaches SSL uprobes immediately when a new process exec's.
	// Replaces the old 30s attachSSLUprobes polling goroutine.
	execWatcher *ExecWatcher

	// Dedup maps for scanner callbacks — prevent re-attaching uprobes
	// to binaries already probed. attachedMu guards concurrent access.
	attachedMu    sync.Mutex
	goAttached    map[string]bool
	grpcCAttached map[string]bool

	// =======================================================================
	// dual-path packet capture pipeline
	// =======================================================================

	// Path A: plain traffic via cgroup_skb packet sniffer.
	pktsPoller *poller.PacketsPoller // drains ka_pkts_buffer

	// Path B: TLS traffic via OpenSSL/Go uprobes.
	tlsPoller *poller.TlsPoller // drains ks_chunks_buffer

	// sockResolver resolves (PID, FD) → socket addresses for TLS chunks
	// that arrive with family==0 (tcp_kprobe missed this connection).
	// Uses per-process /proc/<pid>/net/tcp[6] with a 5s LRU cache.
	sockResolver *procsocket.Resolver

	// Dissector: protocol dissection for both paths.
	dissect *dissector.Dissector

	// Cgroup controller: manages pod targeting for packet sniffer.
	cgroupCtrl *cgroup.Controller

	// =======================================================================
	// Go HTTP/2 / gRPC header uprobes (ring buffers)
	// =======================================================================

	// Go gRPC request events ring buffer.
	goGRPCEvents  *ringbuf.Reader
	goGRPCChannel chan *events.GoGRPCRequestEvent
	grpccEvents   *ringbuf.Reader // ring buffer for gRPC-C header events
	grpccChannel  chan []byte     // gRPC-C uses perf-style raw bytes (small volume)

	goH2TransportEvents  *ringbuf.Reader
	goH2TransportChannel chan *events.GoH2TransportEvent

	// Per-field header events from hpack.WriteField / loopyWriter.writeHeader.
	goH2SingleHeaderEvents  *ringbuf.Reader
	goH2SingleHeaderChannel chan *events.GoH2SingleHeaderEvent

	// =======================================================================
	// Output and lifecycle
	// =======================================================================

	// Pipeline components.
	filterer *filter.Filterer

	// Event buffer: batches events and flushes periodically.
	eventBuf   []*pb.APIEvent
	eventBufMu sync.Mutex

	// K8s namespace filter configuration.
	nsFilterMode      uint8    // 0=disabled, 1=allowlist, 2=blocklist
	allowedNamespaces []string // K8s namespaces to trace (allowlist mode)
	blockedNamespaces []string // K8s namespaces to block (blocklist mode)
	nsCgroupCache     sync.Map // containerID → cgroupID (uint64) for removal cleanup

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// Debug pipeline counters (atomic, logged every 30s).
	dbgDissectorCalls int64 // events from dissector handler callback
	dbgFilterPassed   int64 // events that passed all filters
	dbgBuffered       int64 // events added to eventBuf
	dbgFlushed        int64 // events sent to PushAPIEvent
	dbgTlsChunks      int64 // raw TLS chunks received from BPF perf buffer
}

// PodResolver maps a pod IP address to its Kubernetes namespace and pod name.
// Returns empty strings when no match is found. Injected by the core daemon.
type PodResolver func(ip string) (string, string)

func NewAPIObserver(node tp.Node, pinpath string, logger *fd.Feeder, svcResolver ServiceResolver, podResolver PodResolver) (*APIObserver, error) {
	if svcResolver == nil {
		svcResolver = func(ip string) string { return "" }
	}
	if podResolver == nil {
		podResolver = func(ip string) (string, string) { return "", "" }
	}

	err := probe.CheckBPFLSMSupport()
	if err != nil {
		logger.Warnf("BPF LSM not supported %s\n", err.Error())
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())
	ao := &APIObserver{
		Logger:           logger,
		nodeName:         node.NodeName,
		resolveServiceFn: svcResolver,
		resolvePodFn:     podResolver,
		linksByInode:     make(map[uint64][]io.Closer),
		goAttached:       make(map[string]bool),
		grpcCAttached:    make(map[string]bool),
		sockResolver:     procsocket.New(ctx),
	}
	ao.ctx, ao.cancel = ctx, cancel
	ao.filterer = filter.NewFilterer()

	if err = rlimit.RemoveMemlock(); err != nil {
		ao.Logger.Errf("Error removing rlimit: %v", err)
		return nil, err
	}

	if err = loadApiObserverObjects(&ao.objs, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{PinPath: pinpath},
	}); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			ao.Logger.Errf("BPF verifier error: %v", ve)
		}
		ao.Logger.Errf("Error loading API Observer BPF objects: %v", err)
		return nil, err
	}
	ao.Logger.Print("API Observer eBPF objects loaded successfully")

	// Populate port exclusions and namespace filter (written to BPF maps).
	ao.populatePortExclusions()
	ao.populateNsFilter()

	// =========================================================================
	// Path A: plain traffic — cgroup_skb packet sniffer
	// =========================================================================
	// Attach FD resolution tracepoints, TCP kprobes, and connect/accept
	// tracepoints. These are REQUIRED for SSL capture — without them,
	// ks_ssl_info.fd stays at -1 and all SSL chunks are dropped.
	if err = ao.attachKsFdTracepoints(); err != nil {
		ao.Logger.Warnf("FD tracepoints partially failed (SSL capture degraded): %v", err)
	} else {
		ao.Logger.Print("FD tracepoints + TCP kprobes attached (SSL address resolution enabled)")
	}

	// Initialize the dissector (protocol parser → pb.APIEvent emitter).
	dissectCfg := dissector.Config{
		MaxBodySize: 16384,
		NodeName:    ao.nodeName,
	}
	ao.dissect = dissector.New(func(evt *pb.APIEvent) {
		atomic.AddInt64(&ao.dbgDissectorCalls, 1)
		ao.filterAndEmitFromDissector(evt)
	}, svcResolver, logger, dissectCfg)

	// Initialize the PacketsPoller for plain traffic.
	var firstPktLogged int32
	pktsPoller, pErr := poller.NewPacketsPoller(
		ao.objs.KaPktsBuffer,
		func(pkt *poller.RawPacket) {
			// Log the first packet received to confirm the BPF→Go pipeline is live.
			if atomic.CompareAndSwapInt32(&firstPktLogged, 0, 1) {
				ao.Logger.Debugf("[PIPELINE] First raw packet received! cgroupID=%d direction=%d iphdr=0x%04x len=%d",
					pkt.CgroupID, pkt.Direction, pkt.IPHdrType, len(pkt.Data))
			}
			ao.dissect.HandleRawPacket(pkt)
		},
		64*1024*1024,
	)
	if pErr != nil {
		ao.Logger.Warnf("PacketsPoller init failed (plain traffic disabled): %v", pErr)
	} else {
		ao.pktsPoller = pktsPoller
		pktsPoller.Start()
		ao.Logger.Print("PacketsPoller started (cgroup_skb plain traffic path)")
		// Log poller stats every 30s to trace the pipeline.
		go func() {
			t := time.NewTicker(30 * time.Second)
			defer t.Stop()
			for range t.C {
				s := pktsPoller.Stats()
				ao.Logger.Debugf("[STATS] PacketsPoller: chunks_got=%d chunks_handled=%d chunks_lost=%d packets_got=%d packets_err=%d",
					s.ChunksGot, s.ChunksHandled, s.ChunksLost, s.PacketsGot, s.PacketsError)
				ao.Logger.Debugf("[STATS] Pipeline: dissector_calls=%d filter_passed=%d buffered=%d flushed=%d",
					atomic.LoadInt64(&ao.dbgDissectorCalls),
					atomic.LoadInt64(&ao.dbgFilterPassed),
					atomic.LoadInt64(&ao.dbgBuffered),
					atomic.LoadInt64(&ao.dbgFlushed))
				if ao.tlsPoller != nil {
					ts := ao.tlsPoller.Stats()
					ao.Logger.Debugf("[STATS] TlsPoller: chunks_got=%d chunks_handled=%d chunks_lost=%d (total_tls_chunks_received=%d)",
						ts.ChunksGot, ts.ChunksHandled, ts.ChunksLost,
						atomic.LoadInt64(&ao.dbgTlsChunks))
				}
			}
		}()
	}

	// Initialize the CgroupController.
	ao.cgroupCtrl = cgroup.New(cgroup.Config{
		CgroupIDsMap:         ao.objs.KaCgroupIds,
		ExcludedCgroupIDsMap: ao.objs.KaExcludedCgroupIds,
		SettingsMap:          ao.objs.KaSettings,
		IngressProg:          ao.objs.KaFilterIngressPackets,
		EgressProg:           ao.objs.KaFilterEgressPackets,
	})

	// Attach cgroup_skb programs to the root cgroup so ALL traffic on the node
	// passes through our BPF filter. Without this attachment the programs are
	// loaded but never invoked — zero packets are intercepted.
	// We use the unified cgroup v2 root (/sys/fs/cgroup).
	if rootPath, err := ao.cgroupCtrl.AttachRoot(); err != nil {
		ao.Logger.Warnf("cgroup_skb: failed to attach to root cgroup (traffic capture disabled): %v", err)
	} else {
		ao.Logger.Printf("cgroup_skb: BPF programs attached to host root cgroup via %s", rootPath)
	}

	// Enable pass-all mode so the BPF filter passes packets from ALL cgroups
	// by default. OnContainerAdded/Removed will still call TargetCgroup to
	// populate ka_cgroup_ids, but those entries are only used in selective mode.
	// In pass-all mode the filter passes everything except ka_excluded_cgroup_ids.
	if err := ao.cgroupCtrl.SetPassAllMode(true); err != nil {
		ao.Logger.Warnf("cgroup_skb: failed to set pass-all mode: %v", err)
	} else {
		ao.Logger.Print("cgroup_skb: pass-all mode enabled (capturing all cgroup traffic)")
	}

	// =========================================================================
	// Path B: TLS traffic — ks_chunks_buffer TLS poller
	// =========================================================================
	// 16MB per-CPU perf buffer for TLS chunks.
	var firstTlsChunkLogged int32
	tlsPoller, err := poller.NewTlsPoller(
		ao.objs.KsChunksBuffer,
		func(chunk *events.TlsChunkEvent) {
			atomic.AddInt64(&ao.dbgTlsChunks, 1)
			if atomic.CompareAndSwapInt32(&firstTlsChunkLogged, 0, 1) {
				ao.Logger.Debugf("[PIPELINE] First TLS chunk received! pid=%d fd=%d len=%d",
					chunk.PID, chunk.FD, len(chunk.Data))
			}
			// Fix 3: If the BPF kprobe chain missed the address (family==0),
			// resolve via /proc/<pid>/net/tcp[6] using the socket inode.
			// This handles connections established before probe attachment
			// and cases where tcp_recvmsg doesn't fire (TLS buffer reuse).
			if chunk.Family == 0 && chunk.FD > 2 {
				if addr := ao.sockResolver.Resolve(chunk.PID, chunk.FD); addr != nil {
					chunk.Family = addr.Family
					if addr.Family == syscall.AF_INET {
						chunk.SrcIP4 = procsocket.IPToUint32(addr.SrcIP)
						chunk.DstIP4 = procsocket.IPToUint32(addr.DstIP)
					} else if addr.Family == syscall.AF_INET6 {
						copy(chunk.SrcIP6[:], addr.SrcIP.To16())
						copy(chunk.DstIP6[:], addr.DstIP.To16())
					}
					chunk.SrcPort = addr.SrcPort
					chunk.DstPort = addr.DstPort
					ao.Logger.Debugf("[PROC] Resolved pid=%d fd=%d → src=%s:%d dst=%s:%d family=%d",
						chunk.PID, chunk.FD,
						addr.SrcIP, addr.SrcPort,
						addr.DstIP, addr.DstPort, addr.Family)
				} else {
					ao.Logger.Debugf("[PROC] Unresolvable pid=%d fd=%d — chunk dropped", chunk.PID, chunk.FD)
					return
				}
			}
			ao.dissect.HandleTlsChunk(chunk)
		},
		64*1024*1024, // 64MB per-CPU perf buffer for TLS chunks (reduced loss probability)
	)
	if err != nil {
		ao.Logger.Warnf("TlsPoller init failed (TLS traffic disabled): %v", err)
	} else {
		ao.tlsPoller = tlsPoller
		tlsPoller.Start()
		ao.Logger.Print("TlsPoller started (ks_chunks_buffer TLS path)")
	}

	// =========================================================================
	// Output
	// =========================================================================
	ao.Logger.Debug("API Observer processing components initialized")

	// =========================================================================
	// Go HTTP/2 + gRPC header uprobe ring buffers
	// =========================================================================
	ao.goGRPCEvents, err = ringbuf.NewReader(ao.objs.GoHttp2Events)
	if err != nil {
		ao.Logger.Warnf("Go HTTP/2 header events ring buffer not available (uprobe headers disabled): %v", err)
	} else {
		ao.goGRPCChannel = make(chan *events.GoGRPCRequestEvent, 2048)
		ao.Logger.Debug("Go GRPC events ring buffer created")
	}
	ao.goH2TransportEvents, err = ringbuf.NewReader(ao.objs.GoH2TransportEvents)
	if err != nil {
		ao.Logger.Warnf("Go HTTP/2 transport events ring buffer not available (operateHeaders disabled): %v", err)
	} else {
		ao.goH2TransportChannel = make(chan *events.GoH2TransportEvent, 2048)
		ao.Logger.Debug("Go HTTP/2 transport events ring buffer created")
	}

	ao.goH2SingleHeaderEvents, err = ringbuf.NewReader(ao.objs.GoH2SingleHeaderEvents)
	if err != nil {
		ao.Logger.Warnf("Go HTTP/2 single-header events ring buffer not available (hpack probes disabled): %v", err)
	} else {
		ao.goH2SingleHeaderChannel = make(chan *events.GoH2SingleHeaderEvent, 4096)
		ao.Logger.Debug("Go HTTP/2 single-header events ring buffer created")
	}

	go ao.flushLoop()

	// Start drain goroutines for Go HTTP/2 uprobe events.
	go ao.drainGoHeaderEvents()
	go ao.drainGoH2TransportEvents()
	go ao.drainGoH2SingleHeaderEvents()

	ao.grpccEvents, err = ringbuf.NewReader(ao.objs.GrpccEvents)
	if err != nil {
		ao.Logger.Warnf("gRPC-C events ring buffer not available: %v", err)
	} else {
		ao.grpccChannel = make(chan []byte, 2048)
		ao.Logger.Debug("gRPC-C events ring buffer created")
	}
	go ao.drainGRPCCEvents()

	// =========================================================================
	// Unified /proc walker for uprobe attachment (SSL + Go HTTP/2 + gRPC-C)
	// =========================================================================
	// sslScannerFunc is registered alongside the other scanners so all three
	// run on every new PID in a single /proc walk. The walker does an
	// immediate initial scan at startup (stagger=0) covering all currently
	// running processes, then rescans every 20s for newly started pods.
	ao.procWalker = NewUnifiedProcWalker(
		20*time.Second,
		[]ScannerFunc{
			ao.sslScannerFunc,
			ao.goHTTP2ScannerFunc,
			ao.grpcCScannerFunc,
		},
		ao.onPIDGone,
	)
	go ao.runProcWalker()

	// =========================================================================
	// SSL uprobe attachment — exec-triggered (complements the proc walker)
	// =========================================================================
	// The proc walker covers startup scan + 20s periodic rescan for long-lived
	// processes. ExecWatcher covers ephemeral processes (curl, wget) that start
	// and finish between walker ticks — it fires on every execve() via BPF.
	//
	// ExecWatcher calls sslScannerFunc directly so both paths share identical
	// attachment logic, inode-based deduplication via appendLinkForInode,
	// and symaddrs writing.

	// Attach exec tracepoints (raw_tracepoint/sched_process_fork +
	// kretprobe/sys_execve) so BPF starts emitting events immediately.
	if err := ao.attachExecTracepoints(); err != nil {
		ao.Logger.Warnf("exec tracepoints unavailable (ephemeral SSL capture degraded): %v", err)
	} else {
		ao.Logger.Print("exec tracepoints attached (sched_process_fork + sys_execve)")
	}

	// Build ExecWatcher — reads ka_found_pid_events perf ring.
	if ao.objs.KaFoundPidEvents != nil {
		ew, ewErr := NewExecWatcher(
			ao.objs.KaFoundPidEvents,
			ao.sslScannerFunc,
			ao.Logger,
		)
		if ewErr != nil {
			ao.Logger.Warnf("ExecWatcher init failed (ephemeral SSL capture degraded): %v", ewErr)
		} else {
			ao.execWatcher = ew
			go ao.execWatcher.Start(ao.ctx)
			ao.Logger.Print("ExecWatcher started (exec-triggered SSL uprobe attachment)")
		}
	} else {
		ao.Logger.Warnf("ka_found_pid_events map not available — exec watcher disabled (rebuild BPF objects)")
	}

	return ao, nil
}

// attachTracepointOrFallback tries to attach a BPF program via tracepoint first
// (stable kernel ABI), falling back to kprobe if tracefs is unavailable. This
// handles the common case where /sys/kernel/tracing is not mounted in the container.
func (ao *APIObserver) attachTracepointOrFallback(group, name string, prog *ebpf.Program, kprobeFallbacks []string, isRet bool) error {
	// Try tracepoint first (preferred — stable ABI).
	l, err := link.Tracepoint(group, name, prog, nil)
	if err == nil {
		ao.links = append(ao.links, l)
		ao.Logger.Debugf("tracepoint %s/%s attached", group, name)
		return nil
	}
	ao.Logger.Debugf("Tracepoint %s/%s failed: %v — trying kprobe fallback", group, name, err)

	// Fallback to kprobe/kretprobe with multiple arch-specific names.
	for _, kpName := range kprobeFallbacks {
		var kl link.Link
		var kerr error
		if isRet {
			kl, kerr = link.Kretprobe(kpName, prog, nil)
		} else {
			kl, kerr = link.Kprobe(kpName, prog, nil)
		}
		if kerr == nil {
			ao.links = append(ao.links, kl)
			ao.Logger.Debugf("kprobe fallback %s attached (for %s)", kpName, name)
			return nil
		}
	}

	return fmt.Errorf("tracepoint %s/%s and all kprobe fallbacks failed: %w", group, name, err)
}

// attachKsFdTracepoints attaches the kubeshark-ported BPF programs that are
// required for SSL/TLS capture. Three categories:
//
//  1. FD tracepoints (ks_fd_tracepoints.h) — sys_enter_read/write/sendto/recvfrom
//     and sys_exit_read/write. These populate the FD field in ks_ssl_info when
//     SSL_write/SSL_read internally calls write()/read(). Without these, all
//     SSL chunks are dropped because info.fd == ks_invalid_fd.
//
//  2. Connect/accept tracepoints (ks_connect_tracepoints.h) — sys_enter/exit
//     for connect and accept4. These populate the ks_connection_context map
//     that tracks whether a connection is client or server side.
//
//  3. TCP kprobes (ks_tcp_kprobes.h) — tcp_sendmsg/tcp_recvmsg. These populate
//     the source/destination IP+port in ks_ssl_info from struct sock.
//
// Each tracepoint is tried first; on failure, we fall back to kprobe/kretprobe
// with arch-specific symbol names. This removes the hard dependency on tracefs.
func (ao *APIObserver) attachKsFdTracepoints() error {
	var firstErr error

	// FD resolution: entry tracepoints (sys_enter_*) → kprobe fallback.
	fdEntryProbes := []struct {
		group, name    string
		prog           *ebpf.Program
		kprobeFallback []string
	}{
		{
			"syscalls", "sys_enter_read", ao.objs.KsSysEnterRead,
			[]string{"__x64_sys_read", "ksys_read", "__arm64_sys_read"},
		},
		{
			"syscalls", "sys_enter_write", ao.objs.KsSysEnterWrite,
			[]string{"__x64_sys_write", "ksys_write", "__arm64_sys_write"},
		},
		{
			"syscalls", "sys_enter_recvfrom", ao.objs.KsSysEnterRecvfrom,
			[]string{"__x64_sys_recvfrom", "__arm64_sys_recvfrom"},
		},
		{
			"syscalls", "sys_enter_sendto", ao.objs.KsSysEnterSendto,
			[]string{"__x64_sys_sendto", "__arm64_sys_sendto"},
		},
		// sendmsg/recvmsg: required for Java NIO (SocketChannelImpl)
		// and gRPC-C which use these syscalls instead of write/read.
		{
			"syscalls", "sys_enter_sendmsg", ao.objs.KsSysEnterSendmsg,
			[]string{"__x64_sys_sendmsg", "__arm64_sys_sendmsg"},
		},
		{
			"syscalls", "sys_enter_recvmsg", ao.objs.KsSysEnterRecvmsg,
			[]string{"__x64_sys_recvmsg", "__arm64_sys_recvmsg"},
		},
		{
			"syscalls", "sys_enter_writev", ao.objs.KsSysEnterWritev,
			[]string{"__x64_sys_writev", "ksys_writev", "__arm64_sys_writev"},
		},
		{
			"syscalls", "sys_enter_readv", ao.objs.KsSysEnterReadv,
			[]string{"__x64_sys_readv", "ksys_readv", "__arm64_sys_readv"},
		},
	}

	for _, tp := range fdEntryProbes {
		if err := ao.attachTracepointOrFallback(tp.group, tp.name, tp.prog, tp.kprobeFallback, false); err != nil {
			ao.Logger.Warnf("FD entry %s failed: %v", tp.name, err)
			if firstErr == nil {
				firstErr = err
			}
		}
	}

	// FD resolution: exit tracepoints (sys_exit_*) → kretprobe fallback.
	fdExitProbes := []struct {
		group, name    string
		prog           *ebpf.Program
		kprobeFallback []string
	}{
		{
			"syscalls", "sys_exit_read", ao.objs.KsSysExitRead,
			[]string{"__x64_sys_read", "ksys_read", "__arm64_sys_read"},
		},
		{
			"syscalls", "sys_exit_write", ao.objs.KsSysExitWrite,
			[]string{"__x64_sys_write", "ksys_write", "__arm64_sys_write"},
		},
	}

	for _, tp := range fdExitProbes {
		if err := ao.attachTracepointOrFallback(tp.group, tp.name, tp.prog, tp.kprobeFallback, true); err != nil {
			ao.Logger.Warnf("FD exit %s failed: %v", tp.name, err)
			if firstErr == nil {
				firstErr = err
			}
		}
	}

	// Connect/accept: entry tracepoints → kprobe fallback.
	connEntryProbes := []struct {
		group, name    string
		prog           *ebpf.Program
		kprobeFallback []string
	}{
		{
			"syscalls", "sys_enter_accept4", ao.objs.KsSysEnterAccept4,
			[]string{"__x64_sys_accept4", "__sys_accept4", "__arm64_sys_accept4"},
		},
		{
			"syscalls", "sys_enter_connect", ao.objs.KsSysEnterConnect,
			[]string{"__x64_sys_connect", "__arm64_sys_connect"},
		},
	}

	for _, tp := range connEntryProbes {
		if err := ao.attachTracepointOrFallback(tp.group, tp.name, tp.prog, tp.kprobeFallback, false); err != nil {
			ao.Logger.Warnf("connect entry %s failed: %v", tp.name, err)
			if firstErr == nil {
				firstErr = err
			}
		}
	}

	// Connect/accept: exit tracepoints → kretprobe fallback.
	connExitProbes := []struct {
		group, name    string
		prog           *ebpf.Program
		kprobeFallback []string
	}{
		{
			"syscalls", "sys_exit_accept4", ao.objs.KsSysExitAccept4,
			[]string{"__x64_sys_accept4", "__sys_accept4", "do_accept", "__arm64_sys_accept4"},
		},
		{
			"syscalls", "sys_exit_connect", ao.objs.KsSysExitConnect,
			[]string{"__x64_sys_connect", "__arm64_sys_connect"},
		},
	}

	for _, tp := range connExitProbes {
		if err := ao.attachTracepointOrFallback(tp.group, tp.name, tp.prog, tp.kprobeFallback, true); err != nil {
			ao.Logger.Warnf("connect exit %s failed: %v", tp.name, err)
			if firstErr == nil {
				firstErr = err
			}
		}
	}

	// TCP kprobes for address resolution (always kprobes, no tracepoint equivalent).
	tcpKprobes := []struct {
		name string
		prog *ebpf.Program
	}{
		{"tcp_sendmsg", ao.objs.KsKprobeTcpSendmsg},
		{"tcp_recvmsg", ao.objs.KsKprobeTcpRecvmsg},
	}

	for _, kp := range tcpKprobes {
		l, err := link.Kprobe(kp.name, kp.prog, nil)
		if err != nil {
			ao.Logger.Warnf("TCP kprobe %s failed: %v", kp.name, err)
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		ao.links = append(ao.links, l)
		ao.Logger.Debugf("TCP kprobe %s attached", kp.name)
	}

	return firstErr
}

// Event loop
// Event loop — replaced by PacketsPoller and TlsPoller goroutines.
// This stub is kept for backwards compatibility with any external callers.
// DEPRECATED: will be removed in a future cleanup pass.

// drainGoGRPCEvents reads from the Go gRPC request events ring buffer
// and processes completed events into the correlator.
func (ao *APIObserver) drainGoHeaderEvents() {
	ao.wg.Add(1)
	defer ao.wg.Done()

	if ao.goGRPCEvents == nil {
		return
	}

	ao.Logger.Debug("Starting Go gRPC events reader")

	// Ring buffer reader goroutine — uses ReadInto to avoid per-event allocs.
	// Tracked in ao.wg so DestroyAPIObserver's ao.wg.Wait() blocks until it exits.
	ao.wg.Add(1)
	go func() {
		defer ao.wg.Done()
		var rec ringbuf.Record
		for {
			if err := ao.goGRPCEvents.ReadInto(&rec); err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					return
				}
				ao.Logger.Warnf("Go header ringbuf read error: %v", err)
				continue
			}
			ev, err := events.ParseGoGRPCRequestEvent(rec.RawSample)
			if err != nil {
				ao.Logger.Debugf("ParseGoGRPCRequestEvent error: %v", err)
				continue
			}
			select {
			case ao.goGRPCChannel <- ev:
			case <-ao.ctx.Done():
				return
			default:
				ao.Logger.Debug("Dropping Go gRPC event due to load")
			}
		}
	}()

	// Processing loop.
	for {
		select {
		case <-ao.ctx.Done():
			return
		case ev := <-ao.goGRPCChannel:
			ao.processGoGRPCEvent(ev)
		}
	}
}

// processGoGRPCEvent handles a complete gRPC request event from the BPF uprobe.
func (ao *APIObserver) processGoGRPCEvent(ev *events.GoGRPCRequestEvent) {
	if ev.Path == "" {
		ao.Logger.Debugf("Go uprobe: ignoring event with empty path pid=%d type=%d", ev.PID, ev.EventType)
		return
	}

	direction := "server"
	if ev.EventType == events.GoGRPCEventClientRequest {
		direction = "client"
	}

	// Go uprobe header events are consumed by the dissector's HTTP/2 handler
	// via drainGoHeaderEvents. Since the correlator no longer exists, log only.
	ao.Logger.Debugf("Go uprobe: gRPC %s event pid=%d path=%s status=%d latency=%dns",
		direction, ev.PID, ev.Path, ev.Status, ev.LatencyNs())
}

// filterAndEmitFromDissector bridges pb.APIEvent objects produced by the
// dissector pipeline into the existing filter + buffer pipeline.
// It mirrors the final stages of the old enrichAndEmit without needing a
// CorrelatedTrace or DataEvent (those are specific to the old stream pipeline).
func (ao *APIObserver) filterAndEmitFromDissector(evt *pb.APIEvent) {
	if evt == nil {
		return
	}

	// Loopback filter.
	srcIP := ""
	dstIP := ""
	if evt.Source != nil {
		srcIP = evt.Source.Ip
	}
	if evt.Destination != nil {
		dstIP = evt.Destination.Ip
	}
	if ao.filterer.IsLoopbackTraffic(srcIP, dstIP) {
		ao.Logger.Debugf("[FILTER] DROP loopback src=%s dst=%s", srcIP, dstIP)
		return
	}

	// Path + method filters. Cache GetRequest() to avoid repeated proto traversal.
	path := ""
	method := ""
	ua := ""
	grpcService := ""
	authority := ""
	if req := evt.GetRequest(); req != nil {
		path = req.Path
		method = req.Method
		ua = req.Headers["user-agent"]
		grpcService = req.GrpcService
		authority = req.Headers[":authority"]
	}
	if !ao.filterer.ShouldTraceRequest(path, ua) {
		ao.Logger.Debugf("[FILTER] DROP ShouldTraceRequest=false src=%s dst=%s method=%s path=%s ua=%q",
			srcIP, dstIP, method, path, ua)
		return
	}
	respBody := ""
	if res := evt.GetResponse(); res != nil {
		respBody = res.Body
	}
	if ao.filterer.IsHealthProbe(path, ua, respBody) {
		ao.Logger.Debugf("[FILTER] DROP health probe src=%s dst=%s method=%s path=%s",
			srcIP, dstIP, method, path)
		return
	}

	// Infrastructure traffic filter.
	if ao.filterer.IsInfrastructureTraffic(authority, grpcService) {
		ao.Logger.Debugf("[FILTER] DROP infra traffic src=%s dst=%s authority=%q grpcService=%q",
			srcIP, dstIP, authority, grpcService)
		return
	}

	// Deduplication.
	respStatus := ""
	if res := evt.GetResponse(); res != nil {
		respStatus = strconv.FormatInt(int64(res.StatusCode), 10)
	}
	srcPort := int32(0)
	dstPort := int32(0)
	if evt.Source != nil {
		srcPort = evt.Source.Port
	}
	if evt.Destination != nil {
		dstPort = evt.Destination.Port
	}
	if ao.filterer.IsDuplicate(srcIP, dstIP, srcPort, dstPort, method, path, respStatus) {
		ao.Logger.Debugf("[FILTER] DROP duplicate src=%s:%d dst=%s:%d method=%s path=%s status=%s",
			srcIP, srcPort, dstIP, dstPort, method, path, respStatus)
		return
	}

	// Ensure metadata is always set.
	if evt.Metadata == nil {
		evt.Metadata = &pb.Metadata{
			Timestamp:    uint64(time.Now().Unix()),
			NodeName:     ao.nodeName,
			ReceiverName: "KubeArmor",
		}
	}

	if evt.Source != nil && ao.resolvePodFn != nil {
		ns, name := ao.resolvePodFn(evt.Source.Ip)
		if ns != "" {
			evt.Source.Namespace = ns
			evt.Source.Name = name
		}
	}
	if evt.Destination != nil && ao.resolvePodFn != nil {
		ns, name := ao.resolvePodFn(evt.Destination.Ip)
		if ns != "" {
			evt.Destination.Namespace = ns
			evt.Destination.Name = name
		}
	}

	ao.Logger.Debugf("[FILTER] PASS src=%s:%d dst=%s:%d method=%s path=%s status=%s protocol=%s",
		srcIP, srcPort, dstIP, dstPort, method, path, respStatus, evt.Protocol)

	atomic.AddInt64(&ao.dbgFilterPassed, 1)
	ao.bufferEvent(evt)
}

// Emit path

func sanitizeUTF8(s string) string {
	return strings.ToValidUTF8(s, "")
}

// sanitizeBody returns a clean body string. Non-printable bodies (raw protobuf
// that wasn't decoded) are replaced with a placeholder to avoid emitting
// binary data to downstream consumers.
// Protobuf bodies use high bytes (0x80+) for field tags and varints which
// form invalid UTF-8 sequences — we detect both cases.
func sanitizeBody(s string) string {
	if s == "" {
		return ""
	}
	// Check if body has non-printable or high bytes (binary indicator).
	// Control chars (< 0x20, excluding tab/LF/CR) or high bytes (>= 0x80)
	// indicate binary content (protobuf, compressed data, etc.).
	for _, b := range []byte(s) {
		if (b < 0x20 && b != '\t' && b != '\n' && b != '\r') || b >= 0x80 {
			return fmt.Sprintf("[binary, %d bytes]", len(s))
		}
	}
	return sanitizeUTF8(s)
}

func sanitizeHeaders(m map[string]string) map[string]string {
	if m == nil {
		return nil
	}
	res := make(map[string]string, len(m))
	for k, v := range m {
		res[sanitizeUTF8(k)] = sanitizeUTF8(v)
	}
	return res
}

// enrichAndEmit — REMOVED.
// Event enrichment and emission is now handled by filterAndEmitFromDissector,
// which bridges pb.APIEvent objects from the dissector to the feeder.

// maxAPIBodyBytes caps the request/response body size in emitted APIEvents.
// Bodies exceeding this limit are truncated at the protobuf serialization
// layer to prevent oversized gRPC messages to downstream consumers.
const maxAPIBodyBytes = 16384

const eventBufCap = 500

// bufferEvent appends an event to the buffer and triggers a flush if full.
func (ao *APIObserver) bufferEvent(ev *pb.APIEvent) {
	atomic.AddInt64(&ao.dbgBuffered, 1)
	ao.eventBufMu.Lock()
	ao.eventBuf = append(ao.eventBuf, ev)
	flush := len(ao.eventBuf) >= eventBufCap
	ao.eventBufMu.Unlock()
	if flush {
		ao.flushEvents()
	}
}

// deepSanitizeEvent ensures every string field in a pb.APIEvent is valid UTF-8.
// This is a last-ditch guard before the gRPC marshal layer, which panics/errors
// on invalid UTF-8 in protobuf string fields.
//
// pb.Request.Headers and pb.Response.Headers are map[string]string.
func deepSanitizeEvent(ev *pb.APIEvent) {
	if ev == nil {
		return
	}
	ev.Protocol = sanitizeUTF8(ev.Protocol)
	if req := ev.GetRequest(); req != nil {
		r := req
		r.Method = sanitizeUTF8(r.Method)
		r.Path = sanitizeUTF8(r.Path)
		r.Body = sanitizeBody(r.Body)
		r.GrpcService = sanitizeUTF8(r.GrpcService)
		r.GrpcMethod = sanitizeUTF8(r.GrpcMethod)
		r.ContentType = sanitizeUTF8(r.ContentType)
		if len(r.Headers) > 0 {
			clean := make(map[string]string, len(r.Headers))
			for k, v := range r.Headers {
				clean[sanitizeUTF8(k)] = sanitizeUTF8(v)
			}
			r.Headers = clean
		}
	}
	if res := ev.GetResponse(); res != nil {
		r := res
		r.Body = sanitizeBody(r.Body)
		r.GrpcStatusMessage = sanitizeUTF8(r.GrpcStatusMessage)
		if len(r.Headers) > 0 {
			clean := make(map[string]string, len(r.Headers))
			for k, v := range r.Headers {
				clean[sanitizeUTF8(k)] = sanitizeUTF8(v)
			}
			r.Headers = clean
		}
	}
	if ev.Source != nil {
		ev.Source.Ip = sanitizeUTF8(ev.Source.Ip)
	}
	if ev.Destination != nil {
		ev.Destination.Ip = sanitizeUTF8(ev.Destination.Ip)
	}
}

// flushEvents drains the buffer and pushes all events to the feeder.
func (ao *APIObserver) flushEvents() {
	ao.eventBufMu.Lock()
	batch := ao.eventBuf
	ao.eventBuf = nil
	ao.eventBufMu.Unlock()

	for _, ev := range batch {
		// Final UTF-8 sanitization pass before gRPC serialization.
		// Any binary data (gRPC protobuf bodies, corrupted HPACK values, etc.)
		// that slipped through earlier sanitization is caught here.
		deepSanitizeEvent(ev)
		atomic.AddInt64(&ao.dbgFlushed, 1)
		ao.Logger.PushAPIEvent(ev)
	}
}

// flushLoop periodically flushes buffered events every 5 seconds.
func (ao *APIObserver) flushLoop() {
	ao.wg.Add(1)
	defer ao.wg.Done()

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			ao.flushEvents()
		case <-ao.ctx.Done():
			ao.flushEvents() // Final drain.
			return
		}
	}
}

// K8s metadata resolution

// appendLink is a thread-safe helper for adding probe links.
// Must be used for all link appends from goroutines (SSL scanner, Go probe scanner, etc.).
func (ao *APIObserver) appendLink(l io.Closer) {
	ao.linksMu.Lock()
	ao.links = append(ao.links, l)
	ao.linksMu.Unlock()
}

// appendLinkForInode stores a probe link indexed by binary inode.
// Used for uprobe links that need per-inode lifecycle management
// (cleanup on container exit via the unified proc walker).
func (ao *APIObserver) appendLinkForInode(inode uint64, l io.Closer) {
	ao.linksByInodeMu.Lock()
	ao.linksByInode[inode] = append(ao.linksByInode[inode], l)
	ao.linksByInodeMu.Unlock()
}

// ---------------------------------------------------------------------------
// Unified proc walker: scanner callbacks + lifecycle
// ---------------------------------------------------------------------------

// runProcWalker starts the unified /proc walker as a goroutine.
// Participates in the wg for graceful shutdown.
func (ao *APIObserver) runProcWalker() {
	ao.wg.Add(1)
	defer ao.wg.Done()
	ao.procWalker.Run(ao.ctx)
}

// sslScannerFunc is the unified walker callback for SSL uprobe attachment.
// Called only for genuinely new PIDs (binary inode not seen before).
// Reads /proc/<pid>/cgroup (container check) and /proc/<pid>/maps (SSL lib
// discovery) only for new PIDs — not on every tick.
//
// IMPORTANT: ssl_symaddrs is keyed by TGID (per-process), so we MUST write
// symaddrs for every container PID that uses an SSL library — even if the
// uprobe links for that library's binary are already installed (from a
// previously discovered PID sharing the same inode). Without this, the BPF
// SSL entry handler cannot do the rbio→num FD walk for any process whose
// TGID is not in ssl_symaddrs.
func (ao *APIObserver) sslScannerFunc(snap ProcSnapshot) error {
	pid := int(snap.PID)

	// Container check: read cgroup only for new PIDs.
	cgroupPath := fmt.Sprintf("%s/%d/cgroup", ssl.ProcRoot, pid)
	data, err := os.ReadFile(cgroupPath) // #nosec G304 -- path is ProcRoot + validated integer PID
	if err != nil {
		ao.Logger.Debugf("[sslScanner] pid=%d: cgroup read failed (%v) — skipping", pid, err)
		return nil // process may have exited
	}
	cgroup := string(data)
	if !strings.Contains(cgroup, "kubepods") &&
		!strings.Contains(cgroup, "docker") &&
		!strings.Contains(cgroup, "containerd") {
		return nil // not a container PID — skip silently
	}

	ao.Logger.Debugf("[sslScanner] pid=%d: container cgroup detected — scanning for SSL libs", pid)

	// Discover SSL libraries in this PID's address space.
	matches := ssl.DiscoverSSLLibsForPID(pid)
	if len(matches) == 0 {
		// This is the KEY diagnostic: if nginx is here but has no SSL libs found,
		// we know the problem is in /proc/<pid>/maps parsing, not in BPF.
		ao.Logger.Debugf("[sslScanner] pid=%d (container) — no SSL libraries found in /proc/%d/maps", pid, pid)
		return nil
	}
	ao.Logger.Debugf("[SSL] pid=%d — found %d SSL lib(s): %v", pid, len(matches),
		func() []string {
			paths := make([]string, len(matches))
			for i, m := range matches {
				paths[i] = m.CanonicalPath
				if paths[i] == "" {
					paths[i] = m.LibSSLPath
				}
			}
			return paths
		}())

	for _, m := range matches {
		// Allow fast exit during shutdown.
		select {
		case <-ao.ctx.Done():
			return nil
		default:
		}

		inode := ao.getFileInode(m.LibSSLPath)
		if inode == 0 {
			ao.Logger.Warnf("[SSL] pid=%d — cannot get inode for %s (file gone?)", pid, m.LibSSLPath)
			continue
		}

		// Always write symaddrs for this PID — this MUST happen regardless of
		// whether the uprobe was already installed. The ssl_symaddrs BPF map is
		// keyed by TGID, so every process needs its own entry.
		// Use CanonicalPath for version detection — LibSSLPath may be a
		// map_files address-range that OffsetsForLib can't parse by filename.
		offsetPath := m.CanonicalPath
		if offsetPath == "" {
			offsetPath = m.LibSSLPath
		}
		symAddrs, symErr := ssl.OffsetsForLib(offsetPath)
		if symErr == nil {
			type bpfSSLSymaddrs struct {
				SSLRBIOOffset int32
				BIONumOffset  int32
			}
			bpfOffsets := bpfSSLSymaddrs{
				SSLRBIOOffset: symAddrs.SSLRBIOOffset,
				BIONumOffset:  symAddrs.BIONumOffset,
			}
			if putErr := ao.objs.SslSymaddrs.Put(uint32(pid), bpfOffsets); putErr != nil {
				ao.Logger.Warnf("SSL: failed to write symaddrs for PID %d: %v", pid, putErr)
			} else {
				ao.Logger.Debugf("SSL symaddrs populated for PID %d (rbio=0x%x bio_num=0x%x lib=%s)",
					pid, symAddrs.SSLRBIOOffset, symAddrs.BIONumOffset, offsetPath)
			}
		} else {
			// Symaddr lookup failure is expected for MatchExecutable matchers
			// (Node.js, Envoy) that use memory BIO (rbio→num = -1). The BPF
			// uprobe gracefully falls back to syscall-based FD capture.
			// Only WARN for dynamic shared libraries where offsets are required.
			if m.Matcher.SearchType == ssl.MatchExecutable {
				ao.Logger.Debugf("SSL: symaddrs not needed for %s (PID %d, memory-BIO path): %v", offsetPath, pid, symErr)
			} else {
				ao.Logger.Warnf("SSL: cannot get offsets for %s (PID %d): %v", offsetPath, pid, symErr)
			}
		}

		// Try to attach uprobe links. This will be a no-op (0 links) if the
		// same library binary was already probed via a previously seen PID —
		// that is fine. The uprobes fire for all processes using that binary.
		links := ao.attachSSLProbesForMatch(m)
		if len(links) > 0 {
			for _, l := range links {
				ao.appendLinkForInode(inode, l)
			}
			// Promoted from Debugf: visible in production logs to confirm uprobe attachment.
			ao.Logger.Debugf("SSL uprobes attached to %s (PID %d, %d probes)",
				m.LibSSLPath, pid, len(links))
		} else {
			ao.Logger.Debugf("SSL: %s (PID %d) — library already probed (no new uprobes needed)",
				m.LibSSLPath, pid)
		}
	}
	return nil
}

// goHTTP2ScannerFunc is the unified walker callback for Go HTTP/2 uprobe attachment.
// Called only for genuinely new PIDs (binary inode not seen before).
// Uses ScanBinary for O(1) cache lookup — no /proc walk.
func (ao *APIObserver) goHTTP2ScannerFunc(snap ProcSnapshot) error {
	// Use the snapshot's hostPath/inode directly — the walker already did the
	// /proc walk for us. ScanBinary checks the inode cache and only parses
	// ELF if this is a genuinely new binary.
	target := goprobe.ScanBinary(uint32(snap.PID), snap.HostPath, snap.Inode)
	if target == nil {
		return nil // not a Go gRPC/HTTP2 binary
	}

	ao.attachedMu.Lock()
	if ao.goAttached[target.BinaryPath] {
		ao.attachedMu.Unlock()
		// Already probed this binary — just ensure BPF maps are populated.
		ao.populateGoBPFMaps(*target)
		return nil
	}
	ao.attachedMu.Unlock()

	// Exclude Docker and Containerd from being uprobed to prevent crashes
	// during initialization (hpack.init() / map init races with uprobe attach).
	if strings.Contains(target.BinaryPath, "dockerd") || strings.Contains(target.BinaryPath, "containerd") {
		return nil
	}

	// Populate BPF maps with offsets for this PID.
	ao.populateGoBPFMaps(*target)

	// Open the executable for uprobe attachment.
	ex, err := link.OpenExecutable(target.BinaryPath)
	if err != nil {
		ao.Logger.Warnf("Failed to open Go binary %s: %v", target.BinaryPath, err)
		return nil
	}

	// probeMap maps uprobe short IDs → BPF programs.
	probeMap := map[string]*ebpf.Program{
		"server_handleStream":       ao.objs.KaUprobeServerHandleStream,
		"server_handleStream_ret":   ao.objs.KaUretprobeServerHandleStream,
		"transport_writeStatus":     ao.objs.KaUprobeTransportWriteStatus,
		"ClientConn_Invoke":         ao.objs.KaUprobeClientConnInvoke,
		"ClientConn_Invoke_ret":     ao.objs.KaUretprobeClientConnInvoke,
		"ClientConn_NewStream":      ao.objs.KaUprobeClientConnNewStream,
		"clientStream_RecvMsg_ret":  ao.objs.KaUretprobeClientStreamRecvMsg,
		"operate_headers_server":    ao.objs.KaUprobeOperateHeadersServer,
		"operate_headers_client":    ao.objs.KaUprobeOperateHeadersClient,
		"net_http_processHeaders":   ao.objs.KaUprobeNetHttpProcessHeaders,
		"loopy_writer_write_header": ao.objs.KaUprobeLoopyWriterWriteHeader,
		"hpack_write_field":         ao.objs.KaUprobeHpackWriteField,
		"http2_write_res_headers":   ao.objs.KaUprobeHttp2WriteResHeaders,
		"go_tls_write":              ao.objs.KaUprobeGoTlsWrite,
		"go_tls_read":               ao.objs.KaUprobeGoTlsRead,
	}

	probeCount := 0
	for shortID, addr := range target.Symbols {
		// Allow fast exit during shutdown.
		select {
		case <-ao.ctx.Done():
			return nil
		default:
		}

		// Attach entry uprobe.
		if prog, ok := probeMap[shortID]; ok {
			l, err := attachUprobeWithFallback(ex, "", prog, addr)
			if err != nil {
				ao.Logger.Warnf("Failed to attach uprobe %s at 0x%x on %s: %v",
					shortID, addr, target.BinaryPath, err)
			} else {
				ao.appendLinkForInode(target.Inode, l)
				probeCount++
			}
		}

		// Attach return uprobe (uretprobe) if it exists.
		retKey := shortID + "_ret"
		if retProg, ok := probeMap[retKey]; ok {
			l, err := attachUprobeWithFallback(ex, "", retProg, addr)
			if err != nil {
				ao.Logger.Warnf("Failed to attach uretprobe %s at 0x%x on %s: %v",
					retKey, addr, target.BinaryPath, err)
			} else {
				ao.appendLinkForInode(target.Inode, l)
				probeCount++
			}
		}
	}

	// Attach Go TLS ret-probes at disassembled ret instruction offsets.
	if target.GoTlsOffsets != nil {
		probeCount += ao.attachGoTlsRetProbes(ex, *target)
	}

	if probeCount > 0 {
		ao.attachedMu.Lock()
		ao.goAttached[target.BinaryPath] = true
		ao.attachedMu.Unlock()
		ao.Logger.Debugf("Attached %d Go HTTP/2 uprobes on %s (PID %d)",
			probeCount, target.BinaryPath, target.PID)
	}
	return nil
}

// grpcCScannerFunc is the unified walker callback for gRPC-C uprobe attachment.
// Called only for genuinely new PIDs (binary inode not seen before).
func (ao *APIObserver) grpcCScannerFunc(snap ProcSnapshot) error {
	targets, err := grpcc.ScanProc()
	if err != nil {
		ao.Logger.Warnf("gRPC-C proc scan error: %v", err)
		return nil
	}

	for _, target := range targets {
		// Allow fast exit during shutdown.
		select {
		case <-ao.ctx.Done():
			return nil
		default:
		}

		ao.attachedMu.Lock()
		if ao.grpcCAttached[target.LibPath] {
			ao.attachedMu.Unlock()
			continue
		}
		ao.attachedMu.Unlock()

		offsets, err := grpcc.OffsetsForLib(target.LibPath)
		if err != nil {
			ao.Logger.Warnf("gRPC-C: %v", err)
			continue
		}
		// Array map (max_entries=1) — key is always 0.
		if err := ao.objs.GrpccSymaddrsMap.Put(uint32(0), offsets); err != nil {
			ao.Logger.Warnf("gRPC-C: failed to write symaddrs for %s: %v", target.LibPath, err)
			continue
		}
		ex, err := link.OpenExecutable(target.LibPath)
		if err != nil {
			ao.Logger.Warnf("gRPC-C: failed to open %s: %v", target.LibPath, err)
			continue
		}
		l, err := ex.Uprobe(
			"grpc_chttp2_maybe_complete_recv_initial_metadata",
			ao.objs.KaUprobeGrpcC_recvInitialMetadataEntry,
			nil,
		)
		if err != nil {
			ao.Logger.Warnf("gRPC-C: uprobe attach failed on %s: %v", target.LibPath, err)
			continue
		}

		// Resolve inode for lifecycle tracking.
		inode := ao.getFileInode(target.LibPath)
		if inode != 0 {
			ao.appendLinkForInode(inode, l)
		} else {
			ao.appendLink(l) // fallback: no inode, use lifecycle-level links
		}
		ao.attachedMu.Lock()
		ao.grpcCAttached[target.LibPath] = true
		ao.attachedMu.Unlock()
		ao.Logger.Debugf("gRPC-C uprobe attached to %s (PID %d)", target.LibPath, target.PID)
	}
	return nil
}

// onPIDGone is called by the unified proc walker when a previously cached PID
// no longer exists (container exited). Closes uprobe links for that PID's
// binary inode and removes the BPF map entry.
func (ao *APIObserver) onPIDGone(pid uint32, snap ProcSnapshot) {
	// Close uprobe links associated with this binary inode.
	ao.linksByInodeMu.Lock()
	links := ao.linksByInode[snap.Inode]
	delete(ao.linksByInode, snap.Inode)
	ao.linksByInodeMu.Unlock()

	for _, l := range links {
		if err := l.Close(); err != nil {
			ao.Logger.Warnf("onPIDGone: failed to close link for PID %d inode %d: %v",
				pid, snap.Inode, err)
		}
	}

	// Remove per-TGID BPF map entries.
	_ = ao.objs.SslSymaddrs.Delete(pid)
	// Also remove Go TLS FD offsets written by populateGoBPFMaps to prevent
	// stale entries accumulating as processes come and go.
	_ = ao.objs.KsGoTlsFdOffsets.Delete(pid)

	if len(links) > 0 {
		ao.Logger.Debugf("onPIDGone: cleaned up %d links for PID %d (inode %d)",
			len(links), pid, snap.Inode)
	}
}

// attachExecTracepoints attaches the two BPF programs from exec_trace.h:
//   - raw_tracepoint/sched_process_fork  (ka_sched_process_fork)
//   - kretprobe/sys_execve               (ka_kretprobe_sys_execve)
//
// These fire when any process exec's on the host and emit a ka_found_pid_events
// record so ExecWatcher can immediately attach SSL uprobes.
func (ao *APIObserver) attachExecTracepoints() error {
	var firstErr error

	// raw_tracepoint/sched_process_fork — no tracepoint fallback needed;
	// raw tracepoints are available on all kernels ≥ 4.17.
	if l, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "sched_process_fork",
		Program: ao.objs.KaSchedProcessFork,
	}); err != nil {
		ao.Logger.Warnf("exec: raw_tracepoint/sched_process_fork failed: %v", err)
		firstErr = err
	} else {
		ao.links = append(ao.links, l)
		ao.Logger.Debugf("exec: raw_tracepoint/sched_process_fork attached")
	}

	// kretprobe/sys_execve — try arch-specific syscall wrapper names.
	execveKretprobeNames := []string{
		"__x64_sys_execve",   // x86_64
		"__arm64_sys_execve", // aarch64
		"sys_execve",         // generic fallback
	}
	attached := false
	for _, name := range execveKretprobeNames {
		l, err := link.Kretprobe(name, ao.objs.KaKretprobeSysExecve, nil)
		if err == nil {
			ao.links = append(ao.links, l)
			ao.Logger.Debugf("exec: kretprobe/%s attached", name)
			attached = true
			break
		}
		ao.Logger.Debugf("exec: kretprobe/%s failed: %v", name, err)
	}
	if !attached {
		err := fmt.Errorf("kretprobe/sys_execve: all arch names failed")
		ao.Logger.Warnf("exec: %v", err)
		if firstErr == nil {
			firstErr = err
		}
	}

	return firstErr
}

// attachSSLProbesForMatch attaches the appropriate SSL uprobe/uretprobe pairs
// for a given library match, choosing the correct BPF programs based on the
// FD access strategy.
func (ao *APIObserver) attachSSLProbesForMatch(m ssl.SSLLibMatch) []link.Link {
	ex, err := link.OpenExecutable(m.LibSSLPath)
	if err != nil {
		ao.Logger.Warnf("SSL: failed to open %s: %v", m.LibSSLPath, err)
		return nil
	}

	var links []link.Link
	isStaticSSL := m.Matcher.SearchType == ssl.MatchExecutable
	// BoringSSL (Netty tcnative, Conscrypt): always try address-based
	// fallback because JNI libraries may not expose standard ELF symbol
	// names that cilium/ebpf can resolve via .dynsym.
	resolveAddr := isStaticSSL || m.Matcher.SocketFDAccess == ssl.SSLFDUserSpaceOffsets

	// Populate per-TGID ssl_symaddrs so the BPF entry handler can attempt
	// the ssl->rbio->num struct walk to extract FD directly from the SSL struct.
	// This works for standard OpenSSL with SSL_set_fd (rbio->num holds the fd).
	// For memory BIO apps (Node.js, Python asyncio), rbio->num is -1 and the
	// BPF code gracefully falls through to the syscall/cache fallback path.
	if m.PID > 0 {
		// Use CanonicalPath for version detection — LibSSLPath may be a
		// /proc/<pid>/map_files/<range> path whose basename is an address range,
		// not a recognizable library filename.
		offsetPath := m.CanonicalPath
		if offsetPath == "" {
			offsetPath = m.LibSSLPath
		}
		offsets, err := ssl.OffsetsForLib(offsetPath)
		if err != nil {
			ao.Logger.Debugf("SSL symaddrs: cannot determine offsets for %s: %v", offsetPath, err)
		} else {
			tgid := uint32(m.PID)
			// The BPF struct ssl_symaddrs must match ssl.SymAddrs layout.
			type bpfSSLSymaddrs struct {
				SSLRBIOOffset int32
				BIONumOffset  int32
			}
			bpfOffsets := bpfSSLSymaddrs{
				SSLRBIOOffset: offsets.SSLRBIOOffset,
				BIONumOffset:  offsets.BIONumOffset,
			}
			if err := ao.objs.SslSymaddrs.Put(tgid, bpfOffsets); err != nil {
				ao.Logger.Warnf("SSL symaddrs: failed to write ssl_symaddrs[%d]: %v", tgid, err)
			} else {
				ao.Logger.Debugf("SSL symaddrs: populated ssl_symaddrs[%d] rbio=0x%x num=0x%x for %s",
					tgid, offsets.SSLRBIOOffset, offsets.BIONumOffset, offsetPath)
			}
		}
	}

	// clean entry/return pattern with FD resolution
	// via syscalltracepoints + address via tcp kprobes.
	links = append(links, ao.attachSSLProbePair(ex, m.LibSSLPath,
		"SSL_write", ao.objs.KsSslWrite, ao.objs.KsSslRetWrite, resolveAddr)...)
	links = append(links, ao.attachSSLProbePair(ex, m.LibSSLPath,
		"SSL_read", ao.objs.KsSslRead, ao.objs.KsSslRetRead, resolveAddr)...)
	links = append(links, ao.attachSSLProbePair(ex, m.LibSSLPath,
		"SSL_write_ex", ao.objs.KsSslWriteEx, ao.objs.KsSslRetWriteEx, resolveAddr)...)
	links = append(links, ao.attachSSLProbePair(ex, m.LibSSLPath,
		"SSL_read_ex", ao.objs.KsSslReadEx, ao.objs.KsSslRetReadEx, resolveAddr)...)

	// SSL_pending — proactive context capture for double-read pattern.
	if l, err := attachUprobeWithFallback(ex, "SSL_pending", ao.objs.KsSslPending, 0); err == nil {
		links = append(links, l)
	} else if isStaticSSL {
		if addr, ok := ssl.ELFSymbolAddress(m.LibSSLPath, "SSL_pending"); ok {
			if l, err := ex.Uprobe("", ao.objs.KsSslPending, &link.UprobeOptions{Address: addr}); err == nil {
				links = append(links, l)
			}
		}
	}

	return links
}

// attachSSLProbePair attaches a uprobe+uretprobe pair for a given symbol.
// If resolveAddr is true, falls back to ELF symbol address resolution for
// statically-linked binaries (e.g. Node.js) where cilium/ebpf can't resolve
// symbols by name.
// Returns attached links (0-2). Failures are logged but not fatal.
func (ao *APIObserver) attachSSLProbePair(
	ex *link.Executable, libPath, sym string,
	entryProg, retProg *ebpf.Program,
	resolveAddr bool,
) []link.Link {
	var links []link.Link

	if entryProg != nil {
		if l, err := attachUprobeWithFallback(ex, sym, entryProg, 0); err == nil {
			links = append(links, l)
		} else if resolveAddr {
			// Try address-based attachment for static symbols
			if addr, ok := ssl.ELFSymbolAddress(libPath, sym); ok {
				if l, err := ex.Uprobe("", entryProg, &link.UprobeOptions{Address: addr}); err == nil {
					links = append(links, l)
					ao.Logger.Debugf("SSL: uprobe/%s on %s via address 0x%x", sym, libPath, addr)
				} else {
					ao.Logger.Debugf("SSL: uprobe/%s on %s via address 0x%x failed: %v", sym, libPath, addr, err)
				}
			}
		} else {
			ao.Logger.Debugf("SSL: uprobe/%s on %s: %v", sym, libPath, err)
		}
	}
	if retProg != nil {
		l, err := ex.Uretprobe(sym, retProg, nil)
		if err == nil {
			links = append(links, l)
		} else if resolveAddr {
			// Try address-based uretprobe for static symbols
			if addr, ok := ssl.ELFSymbolAddress(libPath, sym); ok {
				if l, err := ex.Uretprobe("", retProg, &link.UprobeOptions{Address: addr}); err == nil {
					links = append(links, l)
					ao.Logger.Debugf("SSL: uretprobe/%s on %s via address 0x%x", sym, libPath, addr)
				} else {
					ao.Logger.Debugf("SSL: uretprobe/%s on %s via address 0x%x failed: %v", sym, libPath, addr, err)
				}
			}
		} else {
			ao.Logger.Debugf("SSL: uretprobe/%s on %s: %v", sym, libPath, err)
		}
	}

	return links
}

// getFileInode returns the inode of a file, or 0 on error.
func (ao *APIObserver) getFileInode(path string) uint64 {
	var stat syscall.Stat_t
	if err := syscall.Stat(path, &stat); err != nil {
		return 0
	}
	return stat.Ino
}

// attachGoHTTP2Uprobes, attachGRPCCUprobes, and scanAndAttachGRPCC were
// removed. Their logic is now handled by goHTTP2ScannerFunc and
// grpcCScannerFunc via the unified UnifiedProcWalker.

// attachGoTlsRetProbes attaches uprobe-at-ret probes for Go crypto/tls.
// For each ret instruction offset found by go_tls_offsets.go, a regular
// uprobe is placed using the _ex BPF programs. This avoids the uretprobe
// crash that occurs when Go relocates a goroutine's stack.
func (ao *APIObserver) attachGoTlsRetProbes(ex *link.Executable, target goprobe.GoUProbeTarget) int {
	offsets := target.GoTlsOffsets
	if offsets == nil {
		return 0
	}

	probeCount := 0

	// Attach write return probes.
	if offsets.GoWriteOffset != nil {
		for _, exitOff := range offsets.GoWriteOffset.Exits {
			l, err := attachUprobeWithFallback(ex, "", ao.objs.KaUprobeGoTlsWriteEx, exitOff)
			if err != nil {
				ao.Logger.Warnf("Go TLS write_ex at 0x%x on %s: %v", exitOff, target.BinaryPath, err)
				continue
			}
			ao.appendLink(l)
			probeCount++
		}
		ao.Logger.Debugf("Go TLS write_ex: %d ret probes attached", probeCount)
	}

	// Attach read return probes.
	readCount := 0
	if offsets.GoReadOffset != nil {
		for _, exitOff := range offsets.GoReadOffset.Exits {
			l, err := attachUprobeWithFallback(ex, "", ao.objs.KaUprobeGoTlsReadEx, exitOff)
			if err != nil {
				ao.Logger.Warnf("Go TLS read_ex at 0x%x on %s: %v", exitOff, target.BinaryPath, err)
				continue
			}
			ao.appendLink(l)
			readCount++
		}
		ao.Logger.Debugf("Go TLS read_ex: %d ret probes attached", readCount)
	}

	return probeCount + readCount
}

// drainTlsChunks reads the TLS chunk perf buffer.
// Each chunk contains decrypted plaintext data + source/dest addresses.
// Chunks are parsed into DataEvents and fed into the correlator pipeline.
// drainTlsChunks — REMOVED.
// TLS chunk processing is now handled by TlsPoller, which is initialized
// in NewAPIObserver and delivers TlsChunkEvents directly to the Dissector.

// drainGRPCCEvents reads the gRPC-C ring buffer and processes path events.
func (ao *APIObserver) drainGRPCCEvents() {
	ao.wg.Add(1)
	defer ao.wg.Done()

	if ao.grpccEvents == nil {
		return
	}

	// Ring buffer reader goroutine — tracked in ao.wg.
	ao.wg.Add(1)
	go func() {
		defer ao.wg.Done()
		var rec ringbuf.Record
		for {
			if err := ao.grpccEvents.ReadInto(&rec); err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					return
				}
				continue
			}
			// Copy raw sample — ReadInto reuses buffer.
			raw := make([]byte, len(rec.RawSample))
			copy(raw, rec.RawSample)
			select {
			case ao.grpccChannel <- raw:
			case <-ao.ctx.Done():
				return
			}
		}
	}()

	// Outer processing loop — tracked in wg; exits on ctx.Done().
	for {
		select {
		case <-ao.ctx.Done():
			return
		case raw := <-ao.grpccChannel:
			ao.processGRPCCEvent(raw)
		}
	}
}

// drainGoH2TransportEvents reads transport-level header events from the
// operateHeaders uprobes and injects them into the correlator staging map.
// These events carry post-HPACK decoded headers and arrive BEFORE the
// matching kprobe syscall event, allowing AddHTTP2Request to merge them.
func (ao *APIObserver) drainGoH2TransportEvents() {
	ao.wg.Add(1)
	defer ao.wg.Done()

	if ao.goH2TransportEvents == nil {
		return
	}

	ao.Logger.Print("Starting Go HTTP/2 transport events reader")

	// Ring buffer reader goroutine — tracked in ao.wg.
	ao.wg.Add(1)
	go func() {
		defer ao.wg.Done()
		var rec ringbuf.Record
		for {
			if err := ao.goH2TransportEvents.ReadInto(&rec); err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					return
				}
				ao.Logger.Warnf("Go H2 transport ringbuf read error: %v", err)
				continue
			}
			ev, err := events.ParseGoH2TransportEvent(rec.RawSample)
			if err != nil {
				ao.Logger.Debugf("ParseGoH2TransportEvent error: %v", err)
				continue
			}
			select {
			case ao.goH2TransportChannel <- ev:
			case <-ao.ctx.Done():
				return
			default:
				ao.Logger.Debug("Dropping Go H2 transport event due to load")
			}
		}
	}()

	for {
		select {
		case <-ao.ctx.Done():
			return
		case ev := <-ao.goH2TransportChannel:
			ao.Logger.Debugf("Go H2 transport headers: pid=%d stream=%d method=%q path=%q (correlator removed)",
				ev.PID, ev.StreamID, ev.Headers()[":method"], ev.Headers()[":path"])
		}
	}
}

// drainGoH2SingleHeaderEvents reads per-field header events emitted by
// hpack.WriteField and loopyWriter.writeHeader probes, and accumulates
// them into the correlator's transport header staging map.
func (ao *APIObserver) drainGoH2SingleHeaderEvents() {
	ao.wg.Add(1)
	defer ao.wg.Done()

	if ao.goH2SingleHeaderEvents == nil {
		return
	}

	ao.Logger.Debug("Starting Go HTTP/2 single-header events reader")

	// Ring buffer reader goroutine — tracked in ao.wg.
	ao.wg.Add(1)
	go func() {
		defer ao.wg.Done()
		var rec ringbuf.Record
		for {
			if err := ao.goH2SingleHeaderEvents.ReadInto(&rec); err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					return
				}
				ao.Logger.Warnf("Go H2 single-header ringbuf read error: %v", err)
				continue
			}
			ev, err := events.ParseGoH2SingleHeaderEvent(rec.RawSample)
			if err != nil {
				ao.Logger.Debugf("ParseGoH2SingleHeaderEvent error: %v", err)
				continue
			}
			select {
			case ao.goH2SingleHeaderChannel <- ev:
			case <-ao.ctx.Done():
				return
			default:
				ao.Logger.Debug("Dropping Go H2 single-header event due to load")
			}
		}
	}()

	for {
		select {
		case <-ao.ctx.Done():
			return
		case ev := <-ao.goH2SingleHeaderChannel:
			name := ev.HeaderName()
			value := ev.HeaderValue()
			if name == "" {
				continue
			}
			ao.Logger.Debugf("Go H2 single-header: pid=%d stream_id=%d %s=%s (correlator removed)",
				ev.PID, ev.StreamID, name, value)
		}
	}
}

// processGRPCCEvent decodes one ring-buffer sample and injects the
// captured gRPC-C method path into the correlator.
func (ao *APIObserver) processGRPCCEvent(raw []byte) {
	ev, err := events.ParseGRPCCHeaderEvent(raw)
	if err != nil {
		ao.Logger.Debugf("ParseGRPCCHeaderEvent error: %v", err)
		return
	}
	path := ev.PathString()
	if path == "" {
		ao.Logger.Debugf("gRPC-C uprobe: ignoring event with empty method pid=%d", ev.PID)
		return
	}
	ao.Logger.Debugf("gRPC-C uprobe: method path=%s pid=%d fd=%d stream_id=%d (correlator removed)",
		path, ev.PID, ev.FD, ev.StreamID)
}

// populateGoBPFMaps writes the offset table and Go TLS FD offsets into the
// BPF maps for a given target binary.
//
// Two maps are written:
//  1. go_offsets_map[inode] — gRPC/HTTP2 struct field offsets used by
//     the header uprobes.
//  2. ks_go_tls_fd_offsets[tgid] — per-process Go TLS conn layout offsets
//     used by go_tls_get_fd() to extract the socket FD from *tls.Conn.
//     The standard Go stdlib values are used as defaults (correct for all
//     Go >= 1.17); future DWARF-derived values can be placed here.
func (ao *APIObserver) populateGoBPFMaps(target goprobe.GoUProbeTarget) {
	if target.Inode == 0 {
		ao.Logger.Warnf("populateGoBPFMaps: no inode for %s, skipping", target.BinaryPath)
		return
	}

	ao.Logger.Debugf("populateGoBPFMaps: pushing offset table for inode %d (binary %s)",
		target.Inode, target.BinaryPath)

	// Map 1: gRPC/HTTP2 offset table (keyed by binary inode).
	if err := ao.objs.GoOffsetsMap.Put(target.Inode, target.OffsetTable); err != nil {
		ao.Logger.Warnf("Failed to update go_offsets_map for inode %d: %v", target.Inode, err)
	}

	// Map 2: Go TLS FD offsets (keyed by TGID = pid).
	// BPF struct ks_go_tls_symaddrs { u64 conn_data_offset; u64 netfd_sysfd_offset; }
	// Standard Go stdlib layout (all Go >= 1.17):
	//   tls.Conn.conn data pointer: offset 8 (iface second word)
	//   netFD.pfd.Sysfd:           offset 16 (0x10) — after 16-byte fdMutex
	type bpfGoTlsSymaddrs struct {
		ConnDataOffset   uint64
		NetfdSysFdOffset uint64
	}
	tlsOffsets := bpfGoTlsSymaddrs{
		ConnDataOffset:   8,  // tls.Conn.conn iface data ptr at +8
		NetfdSysFdOffset: 16, // netFD.pfd.Sysfd at +0x10
	}
	tgid := uint32(target.PID)
	if err := ao.objs.KsGoTlsFdOffsets.Put(tgid, tlsOffsets); err != nil {
		ao.Logger.Warnf("Failed to update ks_go_tls_fd_offsets for TGID %d: %v", tgid, err)
	} else {
		ao.Logger.Debugf("populateGoBPFMaps: Go TLS fd offsets set for TGID %d (conn_data=8, sysfd=16)", tgid)
	}
}

// populatePortExclusions writes user-configured excluded ports into the BPF
// port_exclusion_map. By default no ports are excluded — only ports explicitly
// passed via the apiExcludedPorts flag/config are filtered.
func (ao *APIObserver) populatePortExclusions() {
	excluded := uint8(1)
	count := 0

	if extra := cfg.GlobalCfg.ConfigApiExcludedPorts.Load(); extra != nil {
		if list, ok := extra.([]string); ok {
			for _, s := range list {
				s = strings.TrimSpace(s)
				if s == "" {
					continue
				}
				port, err := strconv.ParseUint(s, 10, 16)
				if err != nil {
					ao.Logger.Warnf("Invalid port in apiExcludedPorts: %q", s)
					continue
				}
				if err := ao.objs.PortExclusionMap.Put(uint16(port), excluded); err != nil {
					ao.Logger.Warnf("Failed to set port_exclusion_map[%d]: %v", port, err)
				} else {
					count++
				}
			}
		}
	}

	ao.Logger.Printf("Port exclusion map populated: %d ports excluded", count)
}

// SyncPortExclusions clears the BPF port_exclusion_map and connection_filter_cache,
// then re-populates the exclusion map from the current runtime config. This allows
// port exclusions to be changed at runtime without restarting KubeArmor.
func (ao *APIObserver) SyncPortExclusions() {
	if ao == nil {
		return
	}

	// Collect all existing keys first, then delete in a second pass.
	// Mutating a BPF hash map while iterating via NextKey can skip entries.
	var keys []uint16
	iter := ao.objs.PortExclusionMap.Iterate()
	var key uint16
	var val uint8
	for iter.Next(&key, &val) {
		keys = append(keys, key)
	}
	for _, k := range keys {
		_ = ao.objs.PortExclusionMap.Delete(k)
	}
	// Re-populate from current config.
	ao.populatePortExclusions()
	ao.Logger.Print("Port exclusion map re-synced from runtime config")
}

// Namespace filter constants (must match BPF defines in filter_helpers.h).
const (
	nsFilterDisabled  = 0
	nsFilterAllowlist = 1
	nsFilterBlocklist = 2
)

// populateNsFilter sets up the BPF namespace filter based on config flags.
// The filter mode and any static entries (e.g. "host" → cgroup ID 1) are
// written at startup. Dynamic entries are added/removed via OnContainerAdded
// and OnContainerRemoved as containers come and go.
func (ao *APIObserver) populateNsFilter() {
	allow := strings.Trim(strings.TrimSpace(cfg.GlobalCfg.ApiAllowNamespaces), "\"'")
	block := strings.Trim(strings.TrimSpace(cfg.GlobalCfg.ApiBlockNamespaces), "\"'")

	ao.Logger.Printf("Namespace filter: raw config allow=%q block=%q", cfg.GlobalCfg.ApiAllowNamespaces, cfg.GlobalCfg.ApiBlockNamespaces)
	ao.Logger.Printf("Namespace filter: cleaned config allow=%q block=%q", allow, block)

	if allow == "" && block == "" {
		ao.Logger.Print("Namespace filter: disabled (both apiAllowNamespaces and apiBlockNamespaces empty)")
		return
	}

	if allow != "" && block != "" {
		ao.Logger.Warnf("Namespace filter: both apiAllowNamespaces=%q and apiBlockNamespaces=%q set — they are mutually exclusive; disabling filter", allow, block)
		return
	}

	if allow != "" {
		ao.nsFilterMode = nsFilterAllowlist
		for _, ns := range strings.Split(allow, ",") {
			ns = strings.TrimSpace(ns)
			ns = strings.Trim(ns, "\"'") // strip surrounding quotes from config values
			if ns != "" {
				ao.allowedNamespaces = append(ao.allowedNamespaces, ns)
			}
		}
		if err := ao.objs.NsFilterConfig.Put(uint32(0), uint8(nsFilterAllowlist)); err != nil {
			ao.Logger.Warnf("Namespace filter: failed to set allowlist mode: %v", err)
			return
		}
		ao.Logger.Printf("Namespace filter: ALLOWLIST mode — tracing namespaces: %v", ao.allowedNamespaces)
	} else {
		ao.nsFilterMode = nsFilterBlocklist
		for _, ns := range strings.Split(block, ",") {
			ns = strings.TrimSpace(ns)
			ns = strings.Trim(ns, "\"'") // strip surrounding quotes from config values
			if ns != "" {
				ao.blockedNamespaces = append(ao.blockedNamespaces, ns)
			}
		}
		if err := ao.objs.NsFilterConfig.Put(uint32(0), uint8(nsFilterBlocklist)); err != nil {
			ao.Logger.Warnf("Namespace filter: failed to set blocklist mode: %v", err)
			return
		}
		ao.Logger.Printf("Namespace filter: BLOCKLIST mode — blocking namespaces: %v", ao.blockedNamespaces)

		// Always block host cgroup (ID 1) in blocklist mode.
		// In K3s, the API server, kubelet, and other infrastructure components
		// run as host processes with root cgroup ID 1. Without this, host-level
		// SSL uprobes capture all K8s API traffic (metrics-server, controller-manager, etc.).
		marker := uint8(1)
		if err := ao.objs.NsCgroupMap.Put(uint64(1), marker); err != nil {
			ao.Logger.Warnf("Namespace filter: failed to auto-block host cgroup ID 1: %v", err)
		} else {
			ao.Logger.Print("Namespace filter: auto-blocked host cgroup (root cgroup ID 1)")
		}
	}
}

// OnContainerAdded is called by the core daemon when a container is created.
// It always registers the container's cgroup with the cgroup_skb packet sniffer
// (ka_cgroup_ids map) so traffic capture works. If a namespace filter is also
// configured, it additionally populates the ns_cgroup_map for TLS-level filtering.
func (ao *APIObserver) OnContainerAdded(containerID, k8sNamespace string, pidNS uint32) {
	ao.Logger.Printf("OnContainerAdded called (cid=%.12s, ns=%s, pidNS=%d, nsFilterMode=%d)",
		containerID, k8sNamespace, pidNS, ao.nsFilterMode)

	// Always resolve the cgroup ID — needed for cgroup_skb packet capture.
	cgroupID, err := resolveCgroupIDFromPidNS(pidNS, ao.Logger)
	if err != nil {
		ao.Logger.Warnf("FAILED to resolve cgroup ID for pidNS %d (ns=%s, cid=%.12s): %v", pidNS, k8sNamespace, containerID, err)
		return
	}

	ao.Logger.Printf("Resolved cgroupID=%d for pidNS=%d (ns=%s)", cgroupID, pidNS, k8sNamespace)

	// ── cgroup_skb packet sniffer targeting (always runs) ──
	// Register with the cgroup controller so ka_cgroup_ids BPF map is populated
	// and the cgroup_skb programs actually capture traffic for this container.
	if ao.cgroupCtrl != nil {
		if err := ao.cgroupCtrl.TargetCgroup(cgroupID); err != nil {
			ao.Logger.Warnf("cgroup_skb: failed to target cgroup %d (ns=%s, cid=%.12s): %v", cgroupID, k8sNamespace, containerID, err)
		} else {
			ao.Logger.Debugf("cgroup_skb: targeting cgroup %d for packet capture (ns=%s, cid=%.12s)", cgroupID, k8sNamespace, containerID)
		}
	}

	// Cache containerID → cgroupID for cleanup on removal (always needed).
	ao.nsCgroupCache.Store(containerID, cgroupID)

	// ── Namespace filter (optional, for NsCgroupMap / TLS filtering) ──
	if ao.nsFilterMode != nsFilterDisabled {
		tracked := ao.shouldAddToNsBPFMap(k8sNamespace)
		ao.Logger.Printf("Namespace filter: shouldAddToNsBPFMap(%s) = %v (mode=%d, allow=%v, block=%v)",
			k8sNamespace, tracked, ao.nsFilterMode, ao.allowedNamespaces, ao.blockedNamespaces)
		if tracked {
			marker := uint8(1)
			if err := ao.objs.NsCgroupMap.Put(cgroupID, marker); err != nil {
				ao.Logger.Warnf("Namespace filter: FAILED BPF map Put cgroup %d for ns %s: %v", cgroupID, k8sNamespace, err)
			}
		}
	}

	ao.Logger.Printf("SUCCESS added cgroup %d (ns=%s, pidNS=%d, cid=%.12s)", cgroupID, k8sNamespace, pidNS, containerID)
}

// OnContainerRemoved is called by the core daemon when a container is removed.
// Its cgroup ID is removed from ka_cgroup_ids and optionally from ns_cgroup_map.
func (ao *APIObserver) OnContainerRemoved(containerID string) {
	val, ok := ao.nsCgroupCache.LoadAndDelete(containerID)
	if !ok {
		// Container wasn't tracked.
		return
	}
	cgroupID := val.(uint64)

	// Always remove from cgroup_skb sniffer targeting.
	if ao.cgroupCtrl != nil {
		if err := ao.cgroupCtrl.UntargetCgroup(cgroupID); err != nil {
			ao.Logger.Debugf("cgroup_skb: failed to untarget cgroup %d (cid=%.12s): %v", cgroupID, containerID, err)
		}
	}

	// Remove from namespace filter map if applicable.
	if ao.nsFilterMode != nsFilterDisabled {
		if err := ao.objs.NsCgroupMap.Delete(cgroupID); err != nil {
			ao.Logger.Debugf("Namespace filter: failed to remove cgroup %d (cid=%.12s): %v", cgroupID, containerID, err)
		} else {
			ao.Logger.Debugf("Namespace filter: removed cgroup %d (cid=%.12s)", cgroupID, containerID)
		}
	}
}

// shouldAddToNsBPFMap returns true when the given namespace should have its
// cgroup ID inserted into the BPF namespace filter map.
// In allowlist mode: insert when the namespace IS in the allowed list.
// In blocklist mode: insert when the namespace IS in the blocked list (to block it).
// The naming is intentionally direction-neutral — the BPF map meaning
// changes depending on the filter mode set in NsFilterConfig.
func (ao *APIObserver) shouldAddToNsBPFMap(k8sNamespace string) bool {
	if ao.nsFilterMode == nsFilterAllowlist {
		return slices.Contains(ao.allowedNamespaces, k8sNamespace)
	}
	if ao.nsFilterMode == nsFilterBlocklist {
		return slices.Contains(ao.blockedNamespaces, k8sNamespace)
	}
	return false
}

// resolveCgroupIDFromPidNS finds a running process in the given PID namespace
// and gets its cgroup ID by statting the cgroup root through the process's
// mount namespace.
//
// The key insight: /proc/<pid>/root/sys/fs/cgroup traverses the process's
// mount namespace. In K8s, each container's /sys/fs/cgroup IS its own cgroup
// directory (the cgroup namespace root). Statting it gives us the directory's
// inode, which equals what bpf_get_current_cgroup_id() returns in the kernel.
//
// This avoids the cgroup path parsing problem entirely — cgroup paths from
// /proc/<pid>/cgroup contain relative "../.." components due to cgroup
// namespacing, and the host's cgroup filesystem isn't visible from inside
// the KubeArmor container.
func resolveCgroupIDFromPidNS(pidNS uint32, logger *fd.Feeder) (uint64, error) {
	if pidNS == 0 {
		return 0, fmt.Errorf("pidNS is 0")
	}

	procRoot := cfg.GlobalCfg.ProcFsMount // e.g. "/host/procfs" or "/proc"
	target := fmt.Sprintf("pid:[%d]", pidNS)

	logger.Debugf("Namespace filter [resolve]: scanning procRoot=%s for target=%s", procRoot, target)

	// Scan the host procfs for a process in the target PID namespace.
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return 0, fmt.Errorf("readdir %s: %w", procRoot, err)
	}

	pidCount := 0
	checkedCount := 0
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		// Only consider numeric directories (PIDs).
		pid := entry.Name()
		if pid[0] < '1' || pid[0] > '9' {
			continue
		}
		pidCount++

		// Check if this process is in our target PID namespace.
		nsPath := filepath.Join(procRoot, pid, "ns", "pid")
		nsLink, err := os.Readlink(nsPath)
		if err != nil {
			continue // process may have exited
		}
		checkedCount++

		if nsLink != target {
			continue
		}

		logger.Debugf("Namespace filter [resolve]: MATCH pid=%s nsLink=%s", pid, nsLink)

		// Stat the cgroup root through the process's mount namespace.
		// /proc/<pid>/root/sys/fs/cgroup enters the process's filesystem view
		// where /sys/fs/cgroup is the container's own cgroup directory.
		cgroupDir := filepath.Join(procRoot, pid, "root", "sys", "fs", "cgroup")
		var stat syscall.Stat_t
		if err := syscall.Stat(cgroupDir, &stat); err != nil {
			logger.Debugf("Namespace filter [resolve]: stat(%s) FAILED: %v", cgroupDir, err)
			continue // try next process in the same pidNS
		}
		logger.Debugf("Namespace filter [resolve]: stat(%s) => inode=%d", cgroupDir, stat.Ino)
		return stat.Ino, nil
	}

	return 0, fmt.Errorf("no process found in pidNS %d (scanned %s, %d PIDs found, %d checked)", pidNS, procRoot, pidCount, checkedCount)
}

// Lifecycle
func (ao *APIObserver) DestroyAPIObserver() error {
	if ao == nil {
		return nil
	}
	var cleanupErr error

	// 1. Cancel context — signals all goroutines to exit.
	if ao.cancel != nil {
		ao.cancel()
	}

	// Stop filter resources (DedupCache cleanup goroutine).
	if ao.filterer != nil {
		ao.filterer.Stop()
	}

	// 2. Stop new-pipeline pollers and cgroup controller.
	if ao.tlsPoller != nil {
		if err := ao.tlsPoller.Stop(); err != nil {
			ao.Logger.Err(err.Error())
			cleanupErr = errors.Join(cleanupErr, err)
		}
	}
	if ao.pktsPoller != nil {
		if err := ao.pktsPoller.Stop(); err != nil {
			ao.Logger.Err(err.Error())
			cleanupErr = errors.Join(cleanupErr, err)
		}
	}
	if ao.cgroupCtrl != nil {
		ao.cgroupCtrl.Close()
	}

	// 3. Close ring buffer readers — unblocks drain goroutines.
	for _, rb := range []*ringbuf.Reader{
		ao.goGRPCEvents,
		ao.goH2TransportEvents,
		ao.goH2SingleHeaderEvents,
		ao.grpccEvents,
	} {
		if rb != nil {
			if err := rb.Close(); err != nil {
				ao.Logger.Err(err.Error())
				cleanupErr = errors.Join(cleanupErr, err)
			}
		}
	}

	// Since KubeArmor relies on DaemonSet restarts for API Observability toggling,
	// we do not need to manually close every BPF link (the Linux kernel will
	// automatically detach eBPF programs when the process exits). We DO need to
	// wait for all ao.wg goroutines to drain so that they stop accessing feeder
	// state before DestroyFeeder is called by the caller.
	ao.wg.Wait()

	return cleanupErr
}

// eNOTSUPP is errno 524 — the Linux kernel's internal "not supported" error
// returned by uprobe_register when the target address contains a trap instruction.
// It is not exported by golang.org/x/sys/unix so we define it directly.
const eNOTSUPP = syscall.Errno(524)

func attachUprobeWithFallback(
	ex *link.Executable,
	sym string,
	prog *ebpf.Program,
	addr uint64,
) (link.Link, error) {
	var opts *link.UprobeOptions
	if addr != 0 {
		opts = &link.UprobeOptions{Address: addr}
	}

	l, err := ex.Uprobe(sym, prog, opts)
	if err == nil {
		return l, nil
	}

	// Retry at addr+1 only when:
	//   (a) we have an explicit address to offset from (addr != 0), AND
	//   (b) the kernel rejected the address as a trap/NOP sled (errno 524).
	// When addr==0, cilium/ebpf resolves by symbol name; we have no known
	// base address to offset from, so retrying makes no sense.
	isNotSupp := errors.Is(err, eNOTSUPP) ||
		strings.Contains(err.Error(), "errno 524")

	if addr != 0 && isNotSupp {
		l2, err2 := ex.Uprobe(sym, prog, &link.UprobeOptions{Address: addr + 1})
		if err2 == nil {
			return l2, nil
		}
		// Return the original error — it's more informative than addr+1 failure.
	}

	return nil, err
}
