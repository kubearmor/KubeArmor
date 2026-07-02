// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package apiobserver

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	pb "github.com/accuknox/SentryFlow/protobuf/golang"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/kubearmor/KubeArmor/KubeArmor/apiObserver/events"
	"github.com/kubearmor/KubeArmor/KubeArmor/apiObserver/events/conn"
	"github.com/kubearmor/KubeArmor/KubeArmor/apiObserver/filter"
	"github.com/kubearmor/KubeArmor/KubeArmor/apiObserver/goprobe"
	"github.com/kubearmor/KubeArmor/KubeArmor/apiObserver/grpcc"
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

	// BPF compiled objects and attached probe links.
	objs    apiObserverObjects
	links   []io.Closer    // lifecycle-level links (kprobes, tracepoints, host SSL)
	linksMu sync.Mutex

	// Per-inode uprobe links for O(1) cleanup on container exit.
	// Keyed by binary inode; each entry holds all uprobe links attached
	// to that binary. Used by the unified proc walker's onPIDGone callback.
	linksByInode   map[uint64][]io.Closer
	linksByInodeMu sync.Mutex

	// Unified /proc scanner — replaces the three independent 30s walkers.
	procWalker *UnifiedProcWalker

	// Dedup maps for scanner callbacks — prevent re-attaching uprobes
	// to binaries already probed. Keyed by binary path (Go HTTP/2) or
	// library path (gRPC-C).
	goAttached    map[string]bool
	grpcCAttached map[string]bool

	// Ring buffer: BPF emits samples here; we drain into EventsChannel.
	Events        *ringbuf.Reader
	EventsChannel chan events.DataEvent

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

	// TLS chunk perf reader (ks_chunks_buffer).
	ksTlsChunksReader *perf.Reader

	// Pipeline components.
	filterer    *filter.Filterer
	correlator  events.Correlator
	connManager *conn.ConnectionManager

	// Event buffer: batches events and flushes periodically.
	eventBuf   []*pb.APIEvent
	eventBufMu sync.Mutex

	// Per-PID first-chunk diagnostic tracker (single-goroutine access in drainKsTlsChunks).
	tlsPidSeen map[uint32]bool

	// K8s namespace filter configuration.
	nsFilterMode      uint8    // 0=disabled, 1=allowlist, 2=blocklist
	allowedNamespaces []string // K8s namespaces to trace (allowlist mode)
	blockedNamespaces []string // K8s namespaces to block (blocklist mode)
	nsCgroupCache     sync.Map // containerID → cgroupID (uint64) for removal cleanup

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func NewAPIObserver(node tp.Node, pinpath string, logger *fd.Feeder, svcResolver ServiceResolver) (*APIObserver, error) {
	if svcResolver == nil {
		svcResolver = func(ip string) string { return "" }
	}

	err := probe.CheckBPFLSMSupport()
	if err != nil {
		logger.Warnf("BPF LSM not supported %s\n", err.Error())
		return nil, err
	}

	ao := &APIObserver{
		Logger:           logger,
		nodeName:         node.NodeName,
		resolveServiceFn: svcResolver,
		linksByInode:     make(map[uint64][]io.Closer),
		goAttached:       make(map[string]bool),
		grpcCAttached:    make(map[string]bool),
	}
	ao.ctx, ao.cancel = context.WithCancel(context.Background())

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

	// Populate protocol-aware capture size limits.
	ao.populateProtocolConfig()
	ao.populatePortExclusions()
	ao.populateNsFilter()

	if err = ao.attachTracepoint(); err != nil {
		ao.Logger.Warnf("Failed to attach tracepoint (connection tracking degraded): %v", err)
	}

	if err = ao.attachKprobes(); err != nil {
		ao.Logger.Warnf("Failed to initialize system api observer: %s", err.Error())
		return nil, err
	}

	// Attach FD resolution tracepoints, TCP kprobes, and
	// connect/accept tracepoints. These are REQUIRED for SSL capture —
	// without them, ks_ssl_info.fd stays at -1 and all chunks are dropped.
	if err = ao.attachKsFdTracepoints(); err != nil {
		ao.Logger.Warnf("FD tracepoints partially failed (SSL capture degraded): %v", err)
	}

	ao.Events, err = ringbuf.NewReader(ao.objs.ApiobserverEvents)
	if err != nil {
		ao.Logger.Errf("Error creating ring buffer reader: %v", err)
		return nil, err
	}

	ao.EventsChannel = make(chan events.DataEvent, 4096)
	ao.Logger.Debug("Ring buffer reader created")

	ao.filterer = filter.NewFilterer()
	cor := events.NewCorrelator(30 * time.Second)
	ao.correlator = cor
	ao.connManager = conn.NewManager(cor, conn.DefaultConfig())
	ao.connManager.Start()
	ao.Logger.Debug("API Observer processing components initialized")

	// Start the Go gRPC events ring buffer.
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

	go ao.TraceEvents()
	go ao.flushLoop()

	// Start drain goroutines immediately after BPF load — these consume from
	// ring buffers that exist independently of whether uprobes are attached.
	// Previously these were inside attachGoHTTP2Uprobes, causing events from
	// the first 10s to be silently dropped.
	go ao.drainGoHeaderEvents()
	go ao.drainGoH2TransportEvents()
	go ao.drainGoH2SingleHeaderEvents()

	// Kubeshark-style TLS chunks perf reader.
	ksPerfReader, err := perf.NewReader(ao.objs.KsChunksBuffer, 4096*128)
	if err != nil {
		ao.Logger.Warnf("TLS perf reader not available: %v", err)
	} else {
		ao.ksTlsChunksReader = ksPerfReader
		ao.Logger.Debug("TLS chunk perf reader created")
		go ao.drainTlsChunks()
	}

	ao.grpccEvents, err = ringbuf.NewReader(ao.objs.GrpccEvents)
	if err != nil {
		ao.Logger.Warnf("gRPC-C events ring buffer not available: %v", err)
	} else {
		ao.grpccChannel = make(chan []byte, 2048)
		ao.Logger.Debug("gRPC-C events ring buffer created")
	}
	go ao.drainGRPCCEvents()

	// Unified /proc walker — replaces three independent 30s goroutines
	// (attachSSLUprobes, attachGoHTTP2Uprobes, attachGRPCCUprobes) with
	// a single walker that diffs against a ProcCache. Steady-state ticks
	// are near-zero-cost no-ops.
	//
	// Host-level SSL uprobes are attached immediately (not via the walker)
	// because they cover ephemeral processes (curl, wget) and don't need
	// per-PID /proc scanning.
	ao.attachHostSSLUprobes(make(map[sslProbeKey]bool))

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

	return ao, nil
}

func (ao *APIObserver) attachTracepoint() error {
	tpLink, err := link.Tracepoint("sock", "inet_sock_set_state",
		ao.objs.TracepointInetSockSetState, nil)
	if err != nil {
		return fmt.Errorf("attaching tracepoint: %w", err)
	}
	ao.links = append(ao.links, tpLink)
	ao.Logger.Debug("Tracepoint inet_sock_set_state attached")
	return nil
}

func (ao *APIObserver) attachKprobes() error {
	// Egress: write + writev + sendto + sendmsg
	ao.attachSyscallKprobe("__x64_sys_write", "ksys_write", ao.objs.KprobeSysWrite)
	ao.attachSyscallKprobe("__x64_sys_writev", "sys_writev", ao.objs.KprobeSysWritev)
	ao.attachSyscallKprobe("__x64_sys_sendto", "sys_sendto", ao.objs.KprobeSysSendto)
	ao.attachSyscallKprobe("__x64_sys_sendmsg", "sys_sendmsg", ao.objs.KprobeSysSendmsg)

	// Ingress: read + readv + recvfrom + recvmsg (entry + return)
	ao.attachSyscallKprobe("__x64_sys_read", "ksys_read", ao.objs.KprobeSysRead)
	ao.attachSyscallKretprobe("__x64_sys_read", "ksys_read", ao.objs.KretprobeSysRead)
	ao.attachSyscallKprobe("__x64_sys_readv", "sys_readv", ao.objs.KprobeSysReadv)
	ao.attachSyscallKretprobe("__x64_sys_readv", "sys_readv", ao.objs.KretprobeSysReadv)
	ao.attachSyscallKprobe("__x64_sys_recvfrom", "sys_recvfrom", ao.objs.KprobeSysRecvfrom)
	ao.attachSyscallKretprobe("__x64_sys_recvfrom", "sys_recvfrom", ao.objs.KretprobeSysRecvfrom)
	ao.attachSyscallKprobe("__x64_sys_recvmsg", "sys_recvmsg", ao.objs.KprobeSysRecvmsg)
	ao.attachSyscallKretprobe("__x64_sys_recvmsg", "sys_recvmsg", ao.objs.KretprobeSysRecvmsg)

	// FD lifecycle
	ao.attachSyscallKprobe("__x64_sys_connect", "sys_connect", ao.objs.KprobeSysConnect)
	ao.attachSyscallKretprobe("__x64_sys_connect", "sys_connect", ao.objs.KretprobeSysConnect)
	ao.attachSyscallKretprobe("__x64_sys_accept", "sys_accept", ao.objs.KretprobeSysAccept)
	ao.attachSyscallKretprobe("__x64_sys_accept4", "sys_accept4", ao.objs.KretprobeSysAccept4)
	ao.attachSyscallKprobe("__x64_sys_close", "sys_close", ao.objs.KprobeSysClose)
	return nil
}

func (ao *APIObserver) attachSyscallKprobe(x64name, fallback string, prog *ebpf.Program) {
	kp, err := link.Kprobe(x64name, prog, nil)
	if err != nil {
		kp, err = link.Kprobe(fallback, prog, nil)
		if err != nil {
			ao.Logger.Warnf("Failed to attach kprobe %s (FD tracking degraded): %v", fallback, err)
			return
		}
	}
	ao.links = append(ao.links, kp)
	ao.Logger.Debugf("Kprobe %s attached (FD lifecycle)", fallback)
}

func (ao *APIObserver) attachSyscallKretprobe(x64name, fallback string, prog *ebpf.Program) {
	kp, err := link.Kretprobe(x64name, prog, nil)
	if err != nil {
		kp, err = link.Kretprobe(fallback, prog, nil)
		if err != nil {
			ao.Logger.Warnf("Failed to attach kretprobe %s (FD tracking degraded): %v", fallback, err)
			return
		}
	}
	ao.links = append(ao.links, kp)
	ao.Logger.Debugf("Kretprobe %s attached (FD lifecycle)", fallback)
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
func (ao *APIObserver) TraceEvents() {
	ao.wg.Add(1)
	defer ao.wg.Done()

	if ao.Events == nil {
		ao.Logger.Err("Ring buffer reader is nil — exiting TraceEvents")
		return
	}
	ao.Logger.Print("Starting TraceEvents from API Observer")

	// Reader goroutine: uses ReadInto with a reusable record to avoid
	// allocating a new []byte for every BPF event (~37GB of allocation
	// churn eliminated). Parsing happens synchronously before the next
	// ReadInto overwrites the buffer.
	go func() {
		var rec ringbuf.Record
		for {
			if err := ao.Events.ReadInto(&rec); err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					return
				}
				ao.Logger.Warnf("Ringbuf read error: %v", err)
				continue
			}
			// Parse synchronously — ReadInto reuses the buffer, so we
			// must copy the data into a parsed struct before the next read.
			ev, err := events.ParseDataEvent(rec.RawSample)
			if err != nil {
				ao.Logger.Debugf("ParseDataEvent error: %v", err)
				continue
			}
			select {
			case ao.EventsChannel <- *ev:
			case <-ao.ctx.Done():
				return
			default:
				// Drop on overload rather than blocking the BPF reader.
				ao.Logger.Warn("Dropping API Log due to load")
			}
		}
	}()

	for {
		select {
		case <-ao.ctx.Done():
			ao.Logger.Print("API Observer context cancelled — stopping")
			return
		case ev := <-ao.EventsChannel:
			ao.processEvent(ev)
		}
	}
}

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
	go func() {
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

	ao.Logger.Debugf("Go uprobe: gRPC %s event pid=%d path=%s status=%d latency=%dns",
		direction, ev.PID, ev.Path, ev.Status, ev.LatencyNs())

	// Inject into correlator so future kprobe events for this PID
	// can match the path.
	ao.correlator.InjectGoGRPCEvent(ev.PID, ev.Path, ev.Status, ev.StartNs, ev.EndNs)
}

func (ao *APIObserver) processEvent(ev events.DataEvent) {
	// Handle connection close notifications from BPF (TCP_CLOSE).
	// Immediately free the tracker to prevent FD reuse collisions and
	// reduce memory pressure — don't wait for the 60s eviction loop.
	if ev.IsConnClose() {
		ao.connManager.Close(ev.ConnectionKey)
		return
	}
	traces := ao.connManager.Route(&ev)
	for _, trace := range traces {
		ao.enrichAndEmit(trace, &ev)
	}
}

// Emit path

func sanitizeUTF8(s string) string {
	return strings.ToValidUTF8(s, "")
}

// sanitizeBody returns a clean body string. Non-printable bodies (raw protobuf
// that wasn't decoded) are replaced with a placeholder to avoid emitting
// binary data to downstream consumers.
func sanitizeBody(s string) string {
	if s == "" {
		return ""
	}
	// Check if body has non-printable characters (control chars excluding
	// tab/newline/carriage-return). If so, replace with a placeholder.
	for _, b := range []byte(s) {
		if b < 0x20 && b != '\t' && b != '\n' && b != '\r' {
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

func (ao *APIObserver) enrichAndEmit(trace *events.CorrelatedTrace, ev *events.DataEvent) {
	// Non-routable IP filter (loopback, multicast, broadcast).
	if ao.filterer.IsLoopbackTraffic(ev.SrcIPString(), ev.DstIPString()) {
		return
	}

	// Request-level filters.
	ua := trace.RequestHeaders["user-agent"]
	if !ao.filterer.ShouldTraceRequest(trace.URL, ua) {
		return
	}
	if ao.filterer.IsHealthProbe(trace.URL, ua, trace.ResponseBody) {
		return
	}

	// Infrastructure traffic filter: drop known control-plane gRPC services
	// (SPIRE, Envoy xDS, etc.) based on :authority header and gRPC service name.
	// This avoids emitting noise from kubearmor and agents namespaces.
	authority := ao.resolveAuthority(trace, ev)
	if ao.filterer.IsInfrastructureTraffic(authority, trace.GRPCService) {
		return
	}
	// Deduplication: both client and server perspectives of the same call
	// produce events within microseconds. IsDuplicate uses sorted IPs so
	// both perspectives hash to the same key.
	if ao.filterer.IsDuplicate(ev.SrcIPString(), ev.DstIPString(),
		int32(ev.SrcPort), int32(ev.DstPort),
		trace.Method, trace.URL, trace.Status) {
		return
	}

	var statusCode int32
	if n, err := strconv.Atoi(trace.Status); err == nil && n >= math.MinInt32 && n <= math.MaxInt32 {
		statusCode = int32(n) // #nosec G109 -- overflow guarded by MinInt32/MaxInt32 check above
	}

	// Build pb.APIEvent.
	latencyMs := uint32(trace.DurationNs / 1_000_000)

	// Ensure method and path are always populated.
	method := sanitizeUTF8(trace.Method)
	if method == "" {
		method = "UNKNOWN"
	}
	path := sanitizeUTF8(trace.URL)
	if path == "" {
		path = "*"
	}

	// Build request headers with HTTP/2 pseudo-headers.
	reqHeaders := sanitizeHeaders(trace.RequestHeaders)
	if reqHeaders == nil {
		reqHeaders = make(map[string]string)
	}
	reqHeaders[":method"] = method
	reqHeaders[":path"] = path
	reqHeaders[":scheme"] = "http"

	if trace.IsEncrypted {
		reqHeaders[":scheme"] = "https"
	}
	reqHeaders[":authority"] = authority

	isGRPC := ev.ProtocolString() == "gRPC" || strings.HasPrefix(trace.ContentType, "application/grpc") || trace.ResponseHeaders["grpc-status"] != "" || trace.GRPCStatus != 0

	if isGRPC {
		reqHeaders[":scheme"] = "gRPC"
		if trace.GRPCService != "" {
			reqHeaders[":authority"] = trace.GRPCService
		}
	}

	// Build response headers with :status pseudo-header.
	respHeaders := sanitizeHeaders(trace.ResponseHeaders)
	if respHeaders == nil {
		respHeaders = make(map[string]string)
	}
	respHeaders[":status"] = trace.Status

	apiEvent := &pb.APIEvent{
		Metadata: &pb.Metadata{
			Timestamp:    uint64(time.Now().Unix()),
			NodeName:     ao.nodeName,
			ReceiverName: "KubeArmor",
		},
		Source: &pb.Workload{
			Ip:   ev.SrcIPString(),
			Port: int32(ev.SrcPort),
		},
		Destination: &pb.Workload{
			Ip:   ev.DstIPString(),
			Port: int32(ev.DstPort),
		},
		Request: &pb.Request{
			Method:      method,
			Path:        path,
			Headers:     reqHeaders,
			Body:        sanitizeBody(trace.RequestBody),
			GrpcService: sanitizeUTF8(trace.GRPCService),
			GrpcMethod:  sanitizeUTF8(trace.GRPCMethod),
			ContentType: sanitizeUTF8(trace.ContentType),
		},
		Response: &pb.Response{
			StatusCode:        statusCode,
			Headers:           respHeaders,
			Body:              sanitizeBody(trace.ResponseBody),
			GrpcStatusCode:    trace.GRPCStatus,
			GrpcStatusMessage: sanitizeUTF8(trace.GRPCMessage),
		},
		Protocol:  ev.ProtocolString(),
		LatencyMs: latencyMs,
	}

	// BUG 5 fix: Override protocol to "gRPC" when content-type or response
	// headers indicate gRPC traffic, regardless of BPF-level classification.
	if strings.HasPrefix(trace.ContentType, "application/grpc") ||
		trace.ResponseHeaders["grpc-status"] != "" {
		apiEvent.Protocol = "gRPC"
	}

	// BUG 8 fix: Default grpc-message to "OK" when grpc-status is 0 (success)
	// and grpc-message is empty. Go gRPC servers omit grpc-message on success.
	if apiEvent.Response.GrpcStatusCode == 0 && apiEvent.Response.GrpcStatusMessage == "" {
		if trace.ResponseHeaders["grpc-status"] == "0" || trace.ContentType == "application/grpc" {
			apiEvent.Response.GrpcStatusMessage = "OK"
		}
	}

	// BUG 3 fix: Truncate oversized bodies at the userspace serialization layer.
	if len(apiEvent.Request.Body) > maxAPIBodyBytes {
		apiEvent.Request.Body = apiEvent.Request.Body[:maxAPIBodyBytes] + "... [truncated]"
	}
	if len(apiEvent.Response.Body) > maxAPIBodyBytes {
		apiEvent.Response.Body = apiEvent.Response.Body[:maxAPIBodyBytes] + "... [truncated]"
	}

	// Buffer the event for batched flushing.
	ao.bufferEvent(apiEvent)
}

// maxAPIBodyBytes caps the request/response body size in emitted APIEvents.
// Bodies exceeding this limit are truncated at the protobuf serialization
// layer to prevent oversized gRPC messages to downstream consumers.
const maxAPIBodyBytes = 16384

const eventBufCap = 500

// bufferEvent appends an event to the buffer and triggers a flush if full.
func (ao *APIObserver) bufferEvent(ev *pb.APIEvent) {
	ao.eventBufMu.Lock()
	ao.eventBuf = append(ao.eventBuf, ev)
	flush := len(ao.eventBuf) >= eventBufCap
	ao.eventBufMu.Unlock()
	if flush {
		ao.flushEvents()
	}
}

// flushEvents drains the buffer and pushes all events to the feeder.
func (ao *APIObserver) flushEvents() {
	ao.eventBufMu.Lock()
	batch := ao.eventBuf
	ao.eventBuf = nil
	ao.eventBufMu.Unlock()

	for _, ev := range batch {
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
func (ao *APIObserver) sslScannerFunc(snap ProcSnapshot) error {
	pid := int(snap.PID)

	// Container check: read cgroup only for new PIDs.
	cgroupPath := fmt.Sprintf("%s/%d/cgroup", ssl.ProcRoot, pid)
	data, err := os.ReadFile(cgroupPath) // #nosec G304 -- path is ProcRoot + validated integer PID
	if err != nil {
		return nil // process may have exited
	}
	cgroup := string(data)
	if !strings.Contains(cgroup, "kubepods") &&
		!strings.Contains(cgroup, "docker") &&
		!strings.Contains(cgroup, "containerd") {
		return nil // not a container PID
	}

	// Discover SSL libraries in this PID's address space.
	matches := ssl.DiscoverSSLLibsForPID(pid)
	for _, m := range matches {
		// Allow fast exit during shutdown.
		select {
		case <-ao.ctx.Done():
			return nil
		default:
		}

		inode := ao.getFileInode(m.LibSSLPath)
		if inode == 0 {
			continue
		}

		links := ao.attachSSLProbesForMatch(m)
		if len(links) == 0 {
			continue
		}

		// Write symaddrs for this PID.
		symAddrs, symErr := ssl.OffsetsForLib(m.LibSSLPath)
		if symErr == nil {
			if putErr := ao.objs.SslSymaddrs.Put(uint32(pid), symAddrs); putErr != nil {
				ao.Logger.Warnf("SSL: failed to write symaddrs for PID %d: %v", pid, putErr)
			}
		}

		for _, l := range links {
			ao.appendLinkForInode(inode, l)
		}
		ao.Logger.Debugf("SSL uprobes attached to %s (PID %d, %d probes)",
			m.LibSSLPath, pid, len(links))
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

	if ao.goAttached[target.BinaryPath] {
		// Already probed — just ensure BPF maps are populated for this PID.
		ao.populateGoBPFMaps(*target)
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
		ao.goAttached[target.BinaryPath] = true
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

		if ao.grpcCAttached[target.LibPath] {
			continue
		}

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
		ao.grpcCAttached[target.LibPath] = true
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

	if len(links) > 0 {
		ao.Logger.Debugf("onPIDGone: cleaned up %d links for PID %d (inode %d)",
			len(links), pid, snap.Inode)
	}
}

// resolveAuthority determines the :authority pseudo-header value.
// Priority: host header > :authority header > K8s service name > ip:port.
func (ao *APIObserver) resolveAuthority(trace *events.CorrelatedTrace, ev *events.DataEvent) string {
	// 1. Use explicitly set host header (client-provided FQDN).
	if h := trace.RequestHeaders["host"]; h != "" {
		return h
	}
	// 2. Use :authority if already a hostname (not an IP).
	if auth := trace.RequestHeaders[":authority"]; auth != "" {
		authHost, _, err := net.SplitHostPort(auth)
		if err != nil {
			authHost = auth // no port in authority
		}
		if net.ParseIP(authHost) == nil {
			// Already a hostname, use as-is.
			return auth
		}
	}
	// 3. Resolve destination IP to K8s service name.
	if svcName := ao.resolveServiceFn(ev.DstIPString()); svcName != "" {
		return svcName
	}
	// 4. Fallback: ip:port.
	return fmt.Sprintf("%s:%d", ev.DstIPString(), ev.DstPort)
}

// sslProbeKey tracks probed SSL libraries by (path, inode) to avoid re-probing.
type sslProbeKey struct {
	inode uint64 // eBPF uprobes are per-inode; dedup by inode only (like kubeshark)
}

// sslPidInfo tracks per-PID lifecycle state for SSL uprobe cleanup.
type sslPidInfo struct {
	pid       int
	startTime uint64
	links     []link.Link
}

// SSL uprobes — per-PID library discovery with dual FD strategies.
// Runs as a background goroutine, scanning /proc for SSL libraries every 30s.
func (ao *APIObserver) attachSSLUprobes() {
	ao.wg.Add(1)
	defer ao.wg.Done()

	probed := make(map[sslProbeKey]bool)
	tracked := make(map[uint64]*sslPidInfo) // keyed by (pid<<16 | startTime&0xFFFF)

	// Ensure all per-PID uprobe links are closed when this goroutine exits.
	defer func() {
		for _, info := range tracked {
			for _, l := range info.links {
				if err := l.Close(); err != nil {
					ao.Logger.Err(err.Error())
				}
			}
		}
	}()

	// Also pre-attach host-level libssl for ephemeral processes (curl etc).
	ao.attachHostSSLUprobes(probed)

	scanAndAttach := func() {
		pids, err := ssl.ListContainerPIDs()
		if err != nil {
			ao.Logger.Warnf("SSL: container PID scan error: %v", err)
			return
		}

		ao.Logger.Debugf("SSL scanner: found %d container PIDs", len(pids))

		for _, pid := range pids {
			// Allow fast exit during shutdown.
			select {
			case <-ao.ctx.Done():
				return
			default:
			}

			matches := ssl.DiscoverSSLLibsForPID(pid)
			if len(matches) > 0 {
				ao.Logger.Debugf("SSL scanner: PID %d has %d SSL lib matches", pid, len(matches))
			}
			for _, m := range matches {
				inode := ao.getFileInode(m.LibSSLPath)
				if inode == 0 {
					ao.Logger.Debugf("SSL scanner: could not get inode for %s (PID %d)", m.LibSSLPath, pid)
					continue
				}
				key := sslProbeKey{inode: inode}
				if probed[key] {
					continue
				}

				ao.Logger.Debugf("SSL scanner: attaching probes to %s (PID %d, matcher=%q, strategy=%d)",
					m.LibSSLPath, pid, m.Matcher.LibSSL, m.Matcher.SocketFDAccess)

				links := ao.attachSSLProbesForMatch(m)
				if len(links) == 0 {
					ao.Logger.Debugf("SSL scanner: no probes attached for %s (PID %d) — symbols not found?",
						m.LibSSLPath, pid)
					continue
				}

				ao.Logger.Debugf("SSL scanner: attached %d probes for %s (PID %d)", len(links), m.LibSSLPath, pid)

				probed[key] = true

				// Track for lifecycle management.
				startTime, _ := ssl.GetProcStartTime(pid)
				pidKey := (uint64(pid) << 16) | (startTime & 0xFFFF)
				info, ok := tracked[pidKey]
				if !ok {
					info = &sslPidInfo{pid: pid, startTime: startTime}
					tracked[pidKey] = info
				}
				for _, l := range links {
					info.links = append(info.links, l)
				}

				ao.Logger.Debugf("SSL uprobes attached to %s (PID %d, strategy=%d, %d probes)",
					m.LibSSLPath, pid, m.Matcher.SocketFDAccess, len(links))
			}
		}

		// Cleanup dead PIDs.
		ao.cleanupDeadSSLPIDs(tracked)
	}

	// Initial scan.
	scanAndAttach()

	// Periodic rescan.
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ao.ctx.Done():
			return
		case <-ticker.C:
			scanAndAttach()
		}
	}
}

// attachHostSSLUprobes pre-attaches SSL uprobes to host-level libssl libraries.
// This captures traffic from ephemeral processes (curl, wget) that exit before
// the per-PID scanner runs.
func (ao *APIObserver) attachHostSSLUprobes(probed map[sslProbeKey]bool) {
	// glob-based host library search
	libSSLGlobs := []string{
		"/usr/lib/x86_64-linux-gnu/libssl.so.*",
		"/usr/lib/aarch64-linux-gnu/libssl.so.*",
		"/usr/lib64/libssl.so.*",
		"/usr/lib/libssl.so.*",
		"/lib/x86_64-linux-gnu/libssl.so.*",
		"/lib64/libssl.so.*",
		"/usr/local/lib/libssl.so.*",
		"/usr/local/lib64/libssl.so.*",
	}

	for _, pattern := range libSSLGlobs {
		globMatches, _ := filepath.Glob(pattern)
		for _, libPath := range globMatches {
			inode := ao.getFileInode(libPath)
			if inode == 0 {
				continue
			}
			key := sslProbeKey{inode: inode}
			if probed[key] {
				continue
			}

			match := ssl.SSLLibMatch{
				LibSSLPath: libPath,
				PID:        0, // host-level
				Matcher: ssl.SSLLibMatcher{
					SocketFDAccess: ssl.SSLFDNestedSyscall, // host OpenSSL uses nested syscalls
				},
			}
			links := ao.attachSSLProbesForMatch(match)
			if len(links) > 0 {
				probed[key] = true
				// Host-level links are added directly to ao.links for lifecycle.
				for _, l := range links {
					ao.appendLink(l)
				}
				ao.Logger.Printf("Host SSL uprobes attached to %s (%d probes)", libPath, len(links))
			}
		}
	}
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

	// Strategy B (userspace offsets): for Java/Netty BoringSSL, populate
	// the per-TGID ssl_symaddrs BPF map so the uprobe entry handler can
	// walk ssl->rbio->num to extract the FD directly from the SSL struct.
	if m.Matcher.SocketFDAccess == ssl.SSLFDUserSpaceOffsets && m.PID > 0 {
		offsets, err := ssl.OffsetsForLib(m.LibSSLPath)
		if err != nil {
			ao.Logger.Warnf("SSL Strategy B: cannot determine offsets for %s: %v", m.LibSSLPath, err)
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
				ao.Logger.Warnf("SSL Strategy B: failed to write ssl_symaddrs[%d]: %v", tgid, err)
			} else {
				ao.Logger.Debugf("SSL Strategy B: populated ssl_symaddrs[%d] rbio=0x%x num=0x%x for %s",
					tgid, offsets.SSLRBIOOffset, offsets.BIONumOffset, m.LibSSLPath)
			}
		}
	}

	// Kubeshark-style probes: clean entry/return pattern with
	// FD resolution via syscall tracepoints + address via tcp kprobes.
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

	// SSL_shutdown — always attach for cleanup.
	if l, err := attachUprobeWithFallback(ex, "SSL_shutdown", ao.objs.UprobeSslShutdown, 0); err == nil {
		links = append(links, l)
	} else if isStaticSSL {
		if addr, ok := ssl.ELFSymbolAddress(m.LibSSLPath, "SSL_shutdown"); ok {
			if l, err := ex.Uprobe("", ao.objs.UprobeSslShutdown, &link.UprobeOptions{Address: addr}); err == nil {
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

// cleanupDeadSSLPIDs removes uprobe links and BPF map entries for dead processes.
func (ao *APIObserver) cleanupDeadSSLPIDs(tracked map[uint64]*sslPidInfo) {
	for key, info := range tracked {
		if ssl.PidExists(info.pid) {
			continue
		}
		// Process is dead — close uprobe links.
		for _, l := range info.links {
			if err := l.Close(); err != nil {
				ao.Logger.Err(err.Error())
			}
		}
		// Remove per-TGID BPF map entries.
		err := ao.objs.SslSymaddrs.Delete(uint32(info.pid))
		if err != nil {
			ao.Logger.Err("Failed to delete SSL SymAddrs")
		}
		delete(tracked, key)
		ao.Logger.Printf("SSL: cleaned up dead PID %d", info.pid)
	}
}

// getFileInode returns the inode of a file, or 0 on error.
func (ao *APIObserver) getFileInode(path string) uint64 {
	var stat syscall.Stat_t
	if err := syscall.Stat(path, &stat); err != nil {
		return 0
	}
	return stat.Ino
}

// attachGoHTTP2Uprobes scans for Go HTTP/2 binaries and attaches uprobes.
// Runs as a background goroutine, rescanning periodically for new processes.
func (ao *APIObserver) attachGoHTTP2Uprobes() {
	ao.wg.Add(1)
	defer ao.wg.Done()

	// Map of uprobe short IDs → BPF programs.
	// For uretprobes (non-Go functions only), the key gets a "_ret" suffix.
	// Go TLS ret probes use a separate path — see GoTlsOffsets below.
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
		// Go crypto/tls — entry probes only (attached via symbol loop).
		// Return probes use ret-instruction offsets via GoTlsOffsets below.
		"go_tls_write": ao.objs.KaUprobeGoTlsWrite,
		"go_tls_read":  ao.objs.KaUprobeGoTlsRead,
	}

	// Track attached binaries to avoid re-probing.
	attached := make(map[string]bool)

	scanAndAttach := func() {
		targets, err := goprobe.ScanProc()
		if err != nil {
			ao.Logger.Warnf("Go HTTP/2 binary scan error: %v", err)
			return
		}

		for _, target := range targets {
			// Allow fast exit during shutdown.
			select {
			case <-ao.ctx.Done():
				return
			default:
			}

			if attached[target.BinaryPath] {
				// Already probed this binary — just ensure BPF maps are populated.
				ao.populateGoBPFMaps(target)
				continue
			}

			ao.Logger.Debugf("Attaching Go HTTP/2 uprobes to %s (PID %d, %d symbols)",
				target.BinaryPath, target.PID, len(target.Symbols))

			// Populate BPF maps with offsets for this PID.
			ao.populateGoBPFMaps(target)

			// Open the executable for uprobe attachment.
			ex, err := link.OpenExecutable(target.BinaryPath)
			if err != nil {
				ao.Logger.Warnf("Failed to open Go binary %s: %v", target.BinaryPath, err)
				continue
			}

			probeCount := 0
			for shortID, addr := range target.Symbols {
				// Attach entry uprobe.
				if prog, ok := probeMap[shortID]; ok {
					l, err := attachUprobeWithFallback(ex, "", prog, addr)
					if err != nil {
						ao.Logger.Warnf("Failed to attach uprobe %s at 0x%x on %s: %v",
							shortID, addr, target.BinaryPath, err)
					} else {
						ao.appendLink(l)
						probeCount++
						ao.Logger.Debugf("uprobe/%s attached at 0x%x on %s", shortID, addr, target.BinaryPath)
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
						ao.appendLink(l)
						probeCount++
						ao.Logger.Debugf("uretprobe/%s attached at 0x%x", retKey, addr)
					}
				}
			}

			// Attach Go TLS ret-probes at disassembled ret instruction offsets.
			// This replaces uretprobes which crash Go programs.
			if target.GoTlsOffsets != nil {
				probeCount += ao.attachGoTlsRetProbes(ex, target)
			}

			if probeCount > 0 {
				attached[target.BinaryPath] = true
				ao.Logger.Debugf("Attached %d Go HTTP/2 uprobes on %s",
					probeCount, target.BinaryPath)
			}
		}
	}

	// Initial scan.
	scanAndAttach()

	go ao.drainGoHeaderEvents()
	go ao.drainGoH2TransportEvents()
	go ao.drainGoH2SingleHeaderEvents()

	// Periodic rescan for new Go binaries (every 30 seconds).
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ao.ctx.Done():
			return
		case <-ticker.C:
			scanAndAttach()
		}
	}
}

// attachGRPCCUprobes scans for gRPC-C (libgrpc.so) binaries and attaches
// the grpc_chttp2_maybe_complete_recv_initial_metadata uprobe.
// Runs as a background goroutine; never returns an error.
func (ao *APIObserver) attachGRPCCUprobes() {
	ao.wg.Add(1)
	defer ao.wg.Done()

	attached := make(map[string]bool)

	// Trigger first scan immediately without blocking the select.
	doScan := make(chan struct{}, 1)
	doScan <- struct{}{}

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ao.ctx.Done():
			return
		case <-doScan:
			ao.scanAndAttachGRPCC(attached)
		case <-ticker.C:
			ao.scanAndAttachGRPCC(attached)
		}
	}
}

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
		ao.Logger.Printf("Go TLS read_ex: %d ret probes attached", readCount)
	}

	return probeCount + readCount
}

// drainTlsChunks reads the TLS chunk perf buffer.
// Each chunk contains decrypted plaintext data + source/dest addresses.
// Chunks are parsed into DataEvents and fed into the correlator pipeline.
func (ao *APIObserver) drainTlsChunks() {
	ao.wg.Add(1)
	defer ao.wg.Done()

	if ao.ksTlsChunksReader == nil {
		return
	}

	ao.Logger.Print("Starting TLS chunk perf reader")

	chunkCount := uint64(0)
	for {
		record, err := ao.ksTlsChunksReader.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				ao.Logger.Print("TLS perf reader closed")
				return
			}
			continue
		}
		if record.LostSamples != 0 {
			ao.Logger.Warnf("TLS perf: lost %d samples", record.LostSamples)
			continue
		}

		raw := record.RawSample
		chunkCount++
		if chunkCount <= 5 || chunkCount%100 == 0 {
			ao.Logger.Debugf("TLS chunk received #%d (rawLen=%d)", chunkCount, len(raw))
		}

		// Parse the TLS chunk into a structured event.
		chunk, err := events.ParseTlsChunkEvent(raw)
		if err != nil {
			ao.Logger.Debugf("ParseTlsChunkEvent error: %v", err)
			continue
		}

		// Diagnostic: log first chunk from each PID at INFO level to
		// expose address resolution status without flooding logs.
		if ao.tlsPidSeen == nil {
			ao.tlsPidSeen = make(map[uint32]bool)
		}
		if !ao.tlsPidSeen[chunk.PID] {
			ao.tlsPidSeen[chunk.PID] = true
			dataPreview := ""
			if len(chunk.Data) > 0 {
				previewLen := len(chunk.Data)
				if previewLen > 80 {
					previewLen = 80
				}
				dataPreview = string(chunk.Data[:previewLen])
			}
			ao.Logger.Debugf("TLS first chunk from pid=%d fd=%d family=%d src=%s:%d dst=%s:%d flags=0x%x len=%d recorded=%d data=%q",
				chunk.PID, chunk.FD, chunk.Family,
				chunk.SrcIPString(), chunk.SrcPort,
				chunk.DstIPString(), chunk.DstPort,
				chunk.Flags, chunk.Len, chunk.Recorded, dataPreview)
		}

		// Skip empty chunks (start > 0 means continuation — for now,
		// we only process the first chunk of each TLS operation).
		if chunk.Start > 0 || chunk.Recorded == 0 {
			continue
		}

		// Convert to DataEvent and feed into the correlator pipeline.
		ev := chunk.ToDataEvent()
		ao.Logger.Debugf("TLS → DataEvent: pid=%d fd=%d src=%s:%d dst=%s:%d dir=%d flags=0x%x payloadLen=%d",
			ev.PID, ev.FD, ev.SrcIPString(), ev.SrcPort, ev.DstIPString(), ev.DstPort,
			ev.Direction, ev.Flags, len(ev.Payload))
		ao.processEvent(*ev)
	}
}

// drainGRPCCEvents reads the gRPC-C ring buffer and processes path events.
func (ao *APIObserver) drainGRPCCEvents() {
	ao.wg.Add(1)
	defer ao.wg.Done()

	if ao.grpccEvents == nil {
		return
	}

	go func() {
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

	go func() {
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
			ao.Logger.Debugf("Go H2 transport event: pid=%d stream=%d is_server=%d method=%q path=%q",
				ev.PID, ev.StreamID, ev.IsServer, ev.Headers()[":method"], ev.Headers()[":path"])
			ao.correlator.InjectGoHTTP2TransportHeaders(ev.PID, ev.StreamID, ev.Headers())
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

	go func() {
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
			ao.Logger.Debugf("Go H2 single-header event pid=%d stream_id=%d name=%s value=%s",
				ev.PID, ev.StreamID, name, value)
			ao.correlator.InjectGoH2SingleHeader(ev.PID, ev.StreamID, name, value)
		}
	}
}

// scanAndAttachGRPCC is the inner scan body, called from attachGRPCCUprobes.
func (ao *APIObserver) scanAndAttachGRPCC(attached map[string]bool) {
	targets, err := grpcc.ScanProc()
	if err != nil {
		ao.Logger.Warnf("gRPC-C proc scan error: %v", err)
		return
	}
	for _, target := range targets {
		// Allow fast exit during shutdown.
		select {
		case <-ao.ctx.Done():
			return
		default:
		}

		if attached[target.LibPath] {
			continue
		}
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
		ao.appendLink(l)
		attached[target.LibPath] = true
		ao.Logger.Debugf("gRPC-C uprobe attached to %s (PID %d)", target.LibPath, target.PID)
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
	ao.correlator.InjectGRPCCEvent(ev.PID, ev.FD, ev.StreamID, path)
}

// populateGoBPFMaps writes the offset table into the BPF map for a given target.
func (ao *APIObserver) populateGoBPFMaps(target goprobe.GoUProbeTarget) {
	if target.Inode == 0 {
		ao.Logger.Warnf("populateGoBPFMaps: no inode for %s, skipping", target.BinaryPath)
		return
	}

	ao.Logger.Debugf("populateGoBPFMaps: pushing offset table for inode %d (binary %s)",
		target.Inode, target.BinaryPath)

	// Push offset table keyed by inode (matches BPF go_offsets_map).
	// NOTE: GoOffsetsMap field will exist on apiObserverObjects after BPF
	// recompilation with bpf2go. If it doesn't compile, regenerate with:
	//   cd KubeArmor/BPF && make
	if err := ao.objs.GoOffsetsMap.Put(target.Inode, target.OffsetTable); err != nil {
		ao.Logger.Warnf("Failed to update go_offsets_map for inode %d: %v", target.Inode, err)
	}
}

// Protocol config map key indices — must match PROTO_CONFIG_* in macros.h.
const (
	protoConfigHTTP1 uint32 = 0
	protoConfigHTTP2 uint32 = 1
	protoConfigGRPC  uint32 = 2
)

// protocolConfig matches BPF struct protocol_config.
type protocolConfig struct {
	MaxCaptureSize uint32
}

// populateProtocolConfig writes per-protocol capture size limits into the
// BPF protocol_config_map. Called once at startup.
func (ao *APIObserver) populateProtocolConfig() {
	configs := []struct {
		key uint32
		cfg protocolConfig
	}{
		{protoConfigHTTP1, protocolConfig{MaxCaptureSize: 8192}}, // full payload for HTTP/1
		{protoConfigHTTP2, protocolConfig{MaxCaptureSize: 4096}}, // smaller for HTTP/2 frames
		{protoConfigGRPC, protocolConfig{MaxCaptureSize: 4096}},  // smaller for gRPC frames
	}

	for _, c := range configs {
		if err := ao.objs.ProtocolConfigMap.Put(c.key, c.cfg); err != nil {
			ao.Logger.Warnf("Failed to set protocol_config_map[%d]: %v", c.key, err)
		}
	}
	ao.Logger.Print("Protocol-aware capture config populated")
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

	// Clear the existing port exclusion map.
	var key uint16
	for {
		if err := ao.objs.PortExclusionMap.NextKey(nil, &key); err != nil {
			break
		}
		_ = ao.objs.PortExclusionMap.Delete(key)
	}

	// Clear the connection filter cache so existing connections are
	// re-evaluated against the new exclusion set on their next packet.
	var sockKey uint64
	for {
		if err := ao.objs.ConnectionFilterCache.NextKey(nil, &sockKey); err != nil {
			break
		}
		_ = ao.objs.ConnectionFilterCache.Delete(sockKey)
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

		// Handle "host" special value: host processes run in the root cgroup (ID 1).
		if slices.Contains(ao.blockedNamespaces, "host") {
			marker := uint8(1)
			if err := ao.objs.NsCgroupMap.Put(uint64(1), marker); err != nil {
				ao.Logger.Warnf("Namespace filter: failed to block host cgroup ID 1: %v", err)
			} else {
				ao.Logger.Print("Namespace filter: blocked 'host' (root cgroup ID 1)")
			}
		}
	}
}

// OnContainerAdded is called by the core daemon when a container is created.
// If the container's K8s namespace matches the filter configuration, its
// cgroup ID is resolved via the PID namespace and added to the BPF ns_cgroup_map.
func (ao *APIObserver) OnContainerAdded(containerID, k8sNamespace string, pidNS uint32) {
	ao.Logger.Printf("Namespace filter: OnContainerAdded called (cid=%.12s, ns=%s, pidNS=%d, mode=%d)",
		containerID, k8sNamespace, pidNS, ao.nsFilterMode)

	if ao.nsFilterMode == nsFilterDisabled {
		ao.Logger.Printf("Namespace filter: SKIP — filter disabled")
		return
	}

	tracked := ao.shouldTrackContainer(k8sNamespace)
	ao.Logger.Printf("Namespace filter: shouldTrackContainer(%s) = %v (mode=%d, allow=%v, block=%v)",
		k8sNamespace, tracked, ao.nsFilterMode, ao.allowedNamespaces, ao.blockedNamespaces)
	if !tracked {
		return
	}

	cgroupID, err := resolveCgroupIDFromPidNS(pidNS, ao.Logger)
	if err != nil {
		ao.Logger.Warnf("Namespace filter: FAILED to resolve cgroup ID for pidNS %d (ns=%s, cid=%.12s): %v", pidNS, k8sNamespace, containerID, err)
		return
	}

	ao.Logger.Printf("Namespace filter: resolved cgroupID=%d for pidNS=%d", cgroupID, pidNS)

	marker := uint8(1)
	if err := ao.objs.NsCgroupMap.Put(cgroupID, marker); err != nil {
		ao.Logger.Warnf("Namespace filter: FAILED BPF map Put cgroup %d for ns %s: %v", cgroupID, k8sNamespace, err)
		return
	}

	// Cache containerID → cgroupID for cleanup on removal.
	ao.nsCgroupCache.Store(containerID, cgroupID)
	ao.Logger.Printf("Namespace filter: SUCCESS added cgroup %d (ns=%s, pidNS=%d, cid=%.12s, procfs=%s)", cgroupID, k8sNamespace, pidNS, containerID, cfg.GlobalCfg.ProcFsMount)
}

// OnContainerRemoved is called by the core daemon when a container is removed.
// Its cgroup ID is removed from the BPF ns_cgroup_map using the cached mapping.
func (ao *APIObserver) OnContainerRemoved(containerID string) {
	if ao.nsFilterMode == nsFilterDisabled {
		return
	}

	val, ok := ao.nsCgroupCache.LoadAndDelete(containerID)
	if !ok {
		// Container wasn't tracked (namespace didn't match filter).
		return
	}
	cgroupID := val.(uint64)

	if err := ao.objs.NsCgroupMap.Delete(cgroupID); err != nil {
		ao.Logger.Debugf("Namespace filter: failed to remove cgroup %d (cid=%.12s): %v", cgroupID, containerID, err)
	} else {
		ao.Logger.Debugf("Namespace filter: removed cgroup %d (cid=%.12s)", cgroupID, containerID)
	}
}

// shouldTrackContainer returns true if the container's K8s namespace should
// be added to the BPF map based on the current filter mode.
func (ao *APIObserver) shouldTrackContainer(k8sNamespace string) bool {
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

	logger.Printf("Namespace filter [resolve]: scanning procRoot=%s for target=%s", procRoot, target)

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

		logger.Printf("Namespace filter [resolve]: MATCH pid=%s nsLink=%s", pid, nsLink)

		// Stat the cgroup root through the process's mount namespace.
		// /proc/<pid>/root/sys/fs/cgroup enters the process's filesystem view
		// where /sys/fs/cgroup is the container's own cgroup directory.
		cgroupDir := filepath.Join(procRoot, pid, "root", "sys", "fs", "cgroup")
		var stat syscall.Stat_t
		if err := syscall.Stat(cgroupDir, &stat); err != nil {
			logger.Printf("Namespace filter [resolve]: stat(%s) FAILED: %v", cgroupDir, err)
			continue // try next process in the same pidNS
		}
		logger.Printf("Namespace filter [resolve]: stat(%s) => inode=%d", cgroupDir, stat.Ino)
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

	// 2. Close all perf/ring buffer readers — unblocks drain goroutines.
	if ao.Events != nil {
		if err := ao.Events.Close(); err != nil {
			ao.Logger.Err(err.Error())
			cleanupErr = errors.Join(cleanupErr, err)
		}
	}
	if ao.goGRPCEvents != nil {
		if err := ao.goGRPCEvents.Close(); err != nil {
			ao.Logger.Err(err.Error())
			cleanupErr = errors.Join(cleanupErr, err)
		}
	}
	if ao.goH2TransportEvents != nil {
		if err := ao.goH2TransportEvents.Close(); err != nil {
			ao.Logger.Err(err.Error())
			cleanupErr = errors.Join(cleanupErr, err)
		}
	}
	if ao.goH2SingleHeaderEvents != nil {
		if err := ao.goH2SingleHeaderEvents.Close(); err != nil {
			ao.Logger.Err(err.Error())
			cleanupErr = errors.Join(cleanupErr, err)
		}
	}
	if ao.grpccEvents != nil {
		if err := ao.grpccEvents.Close(); err != nil {
			ao.Logger.Err(err.Error())
			cleanupErr = errors.Join(cleanupErr, err)
		}
	}
	if ao.ksTlsChunksReader != nil {
		if err := ao.ksTlsChunksReader.Close(); err != nil {
			ao.Logger.Err(err.Error())
			cleanupErr = errors.Join(cleanupErr, err)
		}
	}

	// Wait for goroutines to finish BEFORE closing BPF objects.
	wgDone := make(chan struct{})
	go func() {
		ao.wg.Wait()
		close(wgDone)
	}()
	select {
	case <-wgDone:
		ao.Logger.Print("All API Observer goroutines stopped")
	case <-time.After(10 * time.Second):
		ao.Logger.Warnf("API Observer goroutines did not stop within 10s — forcing cleanup")
	}

	if ao.correlator != nil {
		ao.correlator.Stop()
	}
	if ao.connManager != nil {
		ao.connManager.Stop()
	}

	// 4. Close probe links BEFORE closing BPF objects — programs must outlive
	// the links that reference them.
	ao.linksMu.Lock()
	links := ao.links
	ao.links = nil
	ao.linksMu.Unlock()
	for _, l := range links {
		if l == nil {
			continue
		}
		if err := l.Close(); err != nil {
			ao.Logger.Err(err.Error())
			cleanupErr = errors.Join(cleanupErr, err)
		}
	}

	// Close per-inode uprobe links.
	ao.linksByInodeMu.Lock()
	for inode, ilinks := range ao.linksByInode {
		for _, l := range ilinks {
			if err := l.Close(); err != nil {
				ao.Logger.Warnf("Failed to close link for inode %d: %v", inode, err)
				cleanupErr = errors.Join(cleanupErr, err)
			}
		}
	}
	ao.linksByInode = nil
	ao.linksByInodeMu.Unlock()

	// 5. Close BPF objects last.
	if err := ao.objs.Close(); err != nil {
		ao.Logger.Err(err.Error())
		cleanupErr = errors.Join(cleanupErr, err)
	}

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
