// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package apiobserver

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"path/filepath"
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
	fd "github.com/kubearmor/KubeArmor/KubeArmor/feeder"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64,arm64 -cc clang apiObserver ../BPF/api_observer.bpf.c

// ServiceResolver maps a ClusterIP to a K8s service FQDN (e.g.
// "cartservice.online-boutique.svc.cluster.local"). Returns empty
// string when no match found. Injected by the core daemon.
type ServiceResolver func(ip string) string

// APIObserver captures and processes network events via eBPF.
type APIObserver struct {
	Logger fd.Feeder

	nodeName         string
	resolveServiceFn ServiceResolver

	// BPF compiled objects and attached probe links.
	objs  apiObserverObjects
	links []io.Closer

	// Ring buffer: BPF emits samples here; we drain into EventsChannel.
	Events        *ringbuf.Reader
	EventsChannel chan []byte

	// Go HTTP/2 header events ring buffer.
	goHeaderEvents  *ringbuf.Reader
	goHeaderChannel chan []byte
	grpccEvents     *ringbuf.Reader // ring buffer for gRPC-C header events
	grpccChannel    chan []byte

	goH2TransportEvents  *ringbuf.Reader
	goH2TransportChannel chan []byte

	// Per-field header events from hpack.WriteField / loopyWriter.writeHeader.
	goH2SingleHeaderEvents  *ringbuf.Reader
	goH2SingleHeaderChannel chan []byte

	// Kubeshark-style TLS chunk perf reader (ks_chunks_buffer).
	ksTlsChunksReader *perf.Reader

	// Pipeline components.
	filterer    *filter.Filterer
	correlator  events.Correlator
	connManager *conn.ConnectionManager

	// Event buffer: batches events and flushes periodically.
	eventBuf   []*pb.APIEvent
	eventBufMu sync.Mutex

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func NewAPIObserver(node tp.Node, pinpath string, logger fd.Feeder, svcResolver ServiceResolver) (*APIObserver, error) {
	if svcResolver == nil {
		svcResolver = func(ip string) string { return "" }
	}
	ao := &APIObserver{
		Logger:           logger,
		nodeName:         node.NodeName,
		resolveServiceFn: svcResolver,
	}
	ao.ctx, ao.cancel = context.WithCancel(context.Background())

	var err error
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

	if err = ao.attachTracepoint(); err != nil {
		ao.Logger.Warnf("Failed to attach tracepoint (connection tracking degraded): %v", err)
	}

	if err = ao.attachKprobes(); err != nil {
		ao.Logger.Warnf("Failed to initialize system api observer: %s", err.Error())
		return nil, err
	}

	// Attach kubeshark-style FD resolution tracepoints, TCP kprobes, and
	// connect/accept tracepoints. These are REQUIRED for SSL capture —
	// without them, ks_ssl_info.fd stays at -1 and all chunks are dropped.
	if err = ao.attachKsFdTracepoints(); err != nil {
		ao.Logger.Warnf("KS FD tracepoints partially failed (SSL capture degraded): %v", err)
	}

	ao.Events, err = ringbuf.NewReader(ao.objs.ApiobserverEvents)
	if err != nil {
		ao.Logger.Errf("Error creating ring buffer reader: %v", err)
		return nil, err
	}

	ao.EventsChannel = make(chan []byte, 4096)
	ao.Logger.Print("Ring buffer reader created")

	ao.filterer = filter.NewFilterer()
	cor := events.NewCorrelator(30 * time.Second)
	ao.correlator = cor
	ao.connManager = conn.NewManager(cor, conn.DefaultConfig())
	ao.Logger.Print("API Observer processing components initialized")

	// Start the Go HTTP/2 header events ring buffer.
	ao.goHeaderEvents, err = ringbuf.NewReader(ao.objs.GoHttp2Events)
	if err != nil {
		ao.Logger.Warnf("Go HTTP/2 header events ring buffer not available (uprobe headers disabled): %v", err)
	} else {
		ao.goHeaderChannel = make(chan []byte, 2048)
		ao.Logger.Print("Go HTTP/2 header events ring buffer created")
	}
	ao.goH2TransportEvents, err = ringbuf.NewReader(ao.objs.GoH2TransportEvents)
	if err != nil {
		ao.Logger.Warnf("Go HTTP/2 transport events ring buffer not available (operateHeaders disabled): %v", err)
	} else {
		ao.goH2TransportChannel = make(chan []byte, 2048)
		ao.Logger.Print("Go HTTP/2 transport events ring buffer created")
	}

	ao.goH2SingleHeaderEvents, err = ringbuf.NewReader(ao.objs.GoH2SingleHeaderEvents)
	if err != nil {
		ao.Logger.Warnf("Go HTTP/2 single-header events ring buffer not available (hpack probes disabled): %v", err)
	} else {
		ao.goH2SingleHeaderChannel = make(chan []byte, 4096)
		ao.Logger.Print("Go HTTP/2 single-header events ring buffer created")
	}

	go ao.TraceEvents()
	go ao.flushLoop()

	// Start background Go HTTP/2 uprobe scanner.
	go ao.attachGoHTTP2Uprobes()

	// Start background SSL uprobe scanner for HTTPS traffic capture.
	go ao.attachSSLUprobes()

	// Kubeshark-style TLS chunks perf reader.
	ksPerfReader, err := perf.NewReader(ao.objs.KsChunksBuffer, 4096*128)
	if err != nil {
		ao.Logger.Warnf("KS TLS perf reader not available: %v", err)
	} else {
		ao.ksTlsChunksReader = ksPerfReader
		ao.Logger.Print("Kubeshark-style TLS chunk perf reader created")
		go ao.drainKsTlsChunks()
	}

	ao.grpccEvents, err = ringbuf.NewReader(ao.objs.GrpccEvents)
	if err != nil {
		ao.Logger.Warnf("gRPC-C events ring buffer not available: %v", err)
	} else {
		ao.grpccChannel = make(chan []byte, 1024)
		ao.Logger.Print("gRPC-C events ring buffer created")
	}

	go ao.attachGRPCCUprobes()
	go ao.drainGRPCCEvents()

	return ao, nil
}

func (ao *APIObserver) attachTracepoint() error {
	tpLink, err := link.Tracepoint("sock", "inet_sock_set_state",
		ao.objs.TracepointInetSockSetState, nil)
	if err != nil {
		return fmt.Errorf("attaching tracepoint: %w", err)
	}
	ao.links = append(ao.links, tpLink)
	ao.Logger.Print("Tracepoint inet_sock_set_state attached")
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
	ao.Logger.Printf("Kprobe %s attached (FD lifecycle)", fallback)
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
	ao.Logger.Printf("Kretprobe %s attached (FD lifecycle)", fallback)
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
func (ao *APIObserver) attachKsFdTracepoints() error {
	var firstErr error

	// FD resolution tracepoints.
	fdTracepoints := []struct {
		group, name string
		prog        *ebpf.Program
	}{
		{"syscalls", "sys_enter_read", ao.objs.KsSysEnterRead},
		{"syscalls", "sys_enter_write", ao.objs.KsSysEnterWrite},
		{"syscalls", "sys_enter_recvfrom", ao.objs.KsSysEnterRecvfrom},
		{"syscalls", "sys_enter_sendto", ao.objs.KsSysEnterSendto},
		{"syscalls", "sys_exit_read", ao.objs.KsSysExitRead},
		{"syscalls", "sys_exit_write", ao.objs.KsSysExitWrite},
	}

	for _, tp := range fdTracepoints {
		l, err := link.Tracepoint(tp.group, tp.name, tp.prog, nil)
		if err != nil {
			ao.Logger.Warnf("KS FD tracepoint %s/%s failed: %v", tp.group, tp.name, err)
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		ao.links = append(ao.links, l)
		ao.Logger.Printf("KS FD tracepoint %s attached", tp.name)
	}

	// Connect/accept tracepoints.
	connTracepoints := []struct {
		group, name string
		prog        *ebpf.Program
	}{
		{"syscalls", "sys_enter_accept4", ao.objs.KsSysEnterAccept4},
		{"syscalls", "sys_exit_accept4", ao.objs.KsSysExitAccept4},
		{"syscalls", "sys_enter_connect", ao.objs.KsSysEnterConnect},
		{"syscalls", "sys_exit_connect", ao.objs.KsSysExitConnect},
	}

	for _, tp := range connTracepoints {
		l, err := link.Tracepoint(tp.group, tp.name, tp.prog, nil)
		if err != nil {
			ao.Logger.Warnf("KS connect tracepoint %s/%s failed: %v", tp.group, tp.name, err)
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		ao.links = append(ao.links, l)
		ao.Logger.Printf("KS connect tracepoint %s attached", tp.name)
	}

	// TCP kprobes for address resolution.
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
			ao.Logger.Warnf("KS TCP kprobe %s failed: %v", kp.name, err)
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		ao.links = append(ao.links, l)
		ao.Logger.Printf("KS TCP kprobe %s attached", kp.name)
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

	go func() {
		for {
			record, err := ao.Events.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					return
				}
				ao.Logger.Warnf("Ringbuf read error: %v", err)
				continue
			}
			select {
			case ao.EventsChannel <- record.RawSample:
			case <-ao.ctx.Done():
				return
			default:
				// Drop on overload rather than blocking the BPF reader.
				slog.Debug("Dropping API Log due to load")
			}
		}
	}()

	for {
		select {
		case <-ao.ctx.Done():
			ao.Logger.Print("API Observer context cancelled — stopping")
			return
		case dataRaw := <-ao.EventsChannel:
			ev, err := events.ParseDataEvent(dataRaw)
			if err != nil {
				ao.Logger.Debugf("ParseDataEvent error: %v", err)
				continue
			}
			ao.processEvent(*ev)
		}
	}
}

// drainGoHeaderEvents reads from the Go HTTP/2 header events ring buffer
// and processes completed header blocks into the correlator.
func (ao *APIObserver) drainGoHeaderEvents() {
	ao.wg.Add(1)
	defer ao.wg.Done()

	if ao.goHeaderEvents == nil {
		return
	}

	ao.Logger.Print("Starting Go HTTP/2 header events reader")

	// Ring buffer reader goroutine.
	go func() {
		for {
			record, err := ao.goHeaderEvents.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					return
				}
				ao.Logger.Warnf("Go header ringbuf read error: %v", err)
				continue
			}
			select {
			case ao.goHeaderChannel <- record.RawSample:
			case <-ao.ctx.Done():
				return
			default:
				slog.Debug("Dropping Go header event due to load")
			}
		}
	}()

	// Processing loop.
	for {
		select {
		case <-ao.ctx.Done():
			return
		case raw := <-ao.goHeaderChannel:
			ev, err := events.ParseGoGRPCRequestEvent(raw)
			if err != nil {
				ao.Logger.Debugf("ParseGoGRPCRequestEvent error: %v", err)
				continue
			}
			ao.processGoGRPCEvent(ev)
		}
	}
}

// processGoGRPCEvent handles a complete gRPC request event from the BPF uprobe.
// Each event contains a full path and latency — no accumulation needed.
func (ao *APIObserver) processGoGRPCEvent(ev *events.GoGRPCRequestEvent) {
	if ev.Path == "" {
		slog.Debug("Go uprobe: ignoring event with empty path",
			"pid", ev.PID, "type", ev.EventType)
		return
	}

	direction := "server"
	if ev.EventType == events.GoGRPCEventClientRequest {
		direction = "client"
	}

	ao.Logger.Printf("Go uprobe: gRPC %s event pid=%d path=%s status=%d latency=%dns",
		direction, ev.PID, ev.Path, ev.Status, ev.LatencyNs())

	// Inject into correlator so future kprobe events for this PID
	// can match the path.
	ao.correlator.InjectGoGRPCEvent(ev.PID, ev.Path, ev.Status, ev.StartNs, ev.EndNs)
}

func (ao *APIObserver) processEvent(ev events.DataEvent) {
	traces := ao.connManager.Route(&ev)
	for _, trace := range traces {
		ao.enrichAndEmit(trace, &ev)
	}
}

// Emit path

func sanitizeUTF8(s string) string {
	return strings.ToValidUTF8(s, "")
}

// sanitizeBody returns a clean body string. If the body contains non-printable
// bytes (raw protobuf that wasn't decoded), base64-encode it with a prefix
// so downstream consumers know it's encoded.
func sanitizeBody(s string) string {
	if s == "" {
		return ""
	}
	// Check if body has non-printable characters (control chars excluding
	// tab/newline/carriage-return).
	for _, b := range []byte(s) {
		if b < 0x20 && b != '\t' && b != '\n' && b != '\r' {
			return "[base64]" + base64.StdEncoding.EncodeToString([]byte(s))
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

	srcName, srcNS := ao.resolveWorkload(ev.SrcIPString())
	dstName, dstNS := ao.resolveWorkload(ev.DstIPString())

	if !ao.filterer.ShouldTraceConnection(srcName, dstName, srcNS, dstNS) {
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
	if n, err := fmt.Sscanf(trace.Status, "%d", &statusCode); n == 0 || err != nil {
		statusCode = 0
	}

	// Build pb.APIEvent.
	latencyMs := uint32(trace.DurationNs / 1_000_000)

	// Resolve :authority — prefer host header, then :authority, then
	// resolve destination IP to K8s service name, fallback to ip:port.
	authority := ao.resolveAuthority(trace, ev)

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

	apiEvent := pb.APIEvent{
		Metadata: &pb.Metadata{
			Timestamp:    uint64(time.Now().Unix()),
			NodeName:     ao.nodeName,
			ReceiverName: "KubeArmor",
		},
		Source: &pb.Workload{
			Name:      srcName,
			Namespace: srcNS,
			Ip:        ev.SrcIPString(),
			Port:      int32(ev.SrcPort),
		},
		Destination: &pb.Workload{
			Name:      dstName,
			Namespace: dstNS,
			Ip:        ev.DstIPString(),
			Port:      int32(ev.DstPort),
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
	ao.bufferEvent(&apiEvent)
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
		ao.Logger.PushAPIEvent(*ev)
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

func (ao *APIObserver) resolveWorkload(ip string) (name, namespace string) {
	return "", ""
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
		authHost := auth
		if idx := strings.LastIndex(authHost, ":"); idx > 0 {
			authHost = authHost[:idx]
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
				l.Close()
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

				ao.Logger.Printf("SSL uprobes attached to %s (PID %d, strategy=%d, %d probes)",
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
					ao.links = append(ao.links, l)
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

	// Kubeshark-style probes: clean entry/return pattern with
	// FD resolution via syscall tracepoints + address via tcp kprobes.
	links = append(links, ao.attachSSLProbePair(ex, m.LibSSLPath,
		"SSL_write", ao.objs.KsSslWrite, ao.objs.KsSslRetWrite, isStaticSSL)...)
	links = append(links, ao.attachSSLProbePair(ex, m.LibSSLPath,
		"SSL_read", ao.objs.KsSslRead, ao.objs.KsSslRetRead, isStaticSSL)...)
	links = append(links, ao.attachSSLProbePair(ex, m.LibSSLPath,
		"SSL_write_ex", ao.objs.KsSslWriteEx, ao.objs.KsSslRetWriteEx, isStaticSSL)...)
	links = append(links, ao.attachSSLProbePair(ex, m.LibSSLPath,
		"SSL_read_ex", ao.objs.KsSslReadEx, ao.objs.KsSslRetReadEx, isStaticSSL)...)

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
			l.Close()
		}
		// Remove per-TGID BPF map entries.
		ao.objs.SslSymaddrs.Delete(uint32(info.pid))
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
			if attached[target.BinaryPath] {
				// Already probed this binary — just ensure BPF maps are populated.
				ao.populateGoBPFMaps(target)
				continue
			}

			ao.Logger.Printf("Attaching Go HTTP/2 uprobes to %s (PID %d, %d symbols)",
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
						ao.links = append(ao.links, l)
						probeCount++
						ao.Logger.Printf("  uprobe/%s attached at 0x%x", shortID, addr)
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
						ao.links = append(ao.links, l)
						probeCount++
						ao.Logger.Printf("  uretprobe/%s attached at 0x%x", retKey, addr)
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
				ao.Logger.Printf("Attached %d Go HTTP/2 uprobes on %s",
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
				ao.Logger.Debugf("Go TLS write_ex at 0x%x on %s: %v", exitOff, target.BinaryPath, err)
				continue
			}
			ao.links = append(ao.links, l)
			probeCount++
		}
		ao.Logger.Printf("  Go TLS write_ex: %d ret probes attached", probeCount)
	}

	// Attach read return probes.
	readCount := 0
	if offsets.GoReadOffset != nil {
		for _, exitOff := range offsets.GoReadOffset.Exits {
			l, err := attachUprobeWithFallback(ex, "", ao.objs.KaUprobeGoTlsReadEx, exitOff)
			if err != nil {
				ao.Logger.Debugf("Go TLS read_ex at 0x%x on %s: %v", exitOff, target.BinaryPath, err)
				continue
			}
			ao.links = append(ao.links, l)
			readCount++
		}
		ao.Logger.Printf("  Go TLS read_ex: %d ret probes attached", readCount)
	}

	return probeCount + readCount
}

// drainKsTlsChunks reads the kubeshark-style TLS chunk perf buffer.
// Each chunk contains decrypted plaintext data + source/dest addresses.
// Chunks are parsed into DataEvents and fed into the correlator pipeline.
func (ao *APIObserver) drainKsTlsChunks() {
	ao.wg.Add(1)
	defer ao.wg.Done()

	if ao.ksTlsChunksReader == nil {
		return
	}

	ao.Logger.Print("Starting kubeshark TLS chunk perf reader")

	chunkCount := uint64(0)
	for {
		record, err := ao.ksTlsChunksReader.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				ao.Logger.Print("KS TLS perf reader closed")
				return
			}
			continue
		}
		if record.LostSamples != 0 {
			ao.Logger.Warnf("KS TLS perf: lost %d samples", record.LostSamples)
			continue
		}

		raw := record.RawSample
		chunkCount++

		// Parse the TLS chunk into a structured event.
		chunk, err := events.ParseTlsChunkEvent(raw)
		if err != nil {
			ao.Logger.Debugf("ParseTlsChunkEvent error: %v", err)
			continue
		}

		// Diagnostic: log every chunk received from BPF.
		dataPreview := ""
		if len(chunk.Data) > 0 {
			previewLen := len(chunk.Data)
			if previewLen > 80 {
				previewLen = 80
			}
			dataPreview = string(chunk.Data[:previewLen])
		}
		ao.Logger.Debugf("KS TLS chunk #%d: pid=%d fd=%d flags=0x%x len=%d start=%d recorded=%d family=%d src=%s:%d dst=%s:%d data=%q",
			chunkCount, chunk.PID, chunk.FD, chunk.Flags, chunk.Len, chunk.Start, chunk.Recorded,
			chunk.Family, chunk.SrcIPString(), chunk.SrcPort, chunk.DstIPString(), chunk.DstPort,
			dataPreview)

		// Skip empty chunks (start > 0 means continuation — for now,
		// we only process the first chunk of each TLS operation).
		if chunk.Start > 0 || chunk.Recorded == 0 {
			continue
		}

		// Convert to DataEvent and feed into the correlator pipeline.
		ev := chunk.ToDataEvent()
		ao.Logger.Debugf("KS TLS → DataEvent: pid=%d fd=%d src=%s:%d dst=%s:%d dir=%d flags=0x%x payloadLen=%d",
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

	// Inner reader goroutine — NOT tracked in wg; exits via ErrClosed
	// when DestroyAPIObserver calls ao.grpccEvents.Close().
	go func() {
		for {
			record, err := ao.grpccEvents.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					return
				}
				continue
			}
			select {
			case ao.grpccChannel <- record.RawSample:
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
		for {
			record, err := ao.goH2TransportEvents.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					return
				}
				ao.Logger.Warnf("Go H2 transport ringbuf read error: %v", err)
				continue
			}
			select {
			case ao.goH2TransportChannel <- record.RawSample:
			case <-ao.ctx.Done():
				return
			default:
				slog.Debug("Dropping Go H2 transport event due to load")
			}
		}
	}()

	for {
		select {
		case <-ao.ctx.Done():
			return
		case raw := <-ao.goH2TransportChannel:
			ev, err := events.ParseGoH2TransportEvent(raw)
			if err != nil {
				ao.Logger.Debugf("ParseGoH2TransportEvent error: %v", err)
				continue
			}
			ao.Logger.Printf("Go H2 transport event: pid=%d stream=%d is_server=%d method=%q path=%q",
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

	ao.Logger.Print("Starting Go HTTP/2 single-header events reader")

	go func() {
		for {
			record, err := ao.goH2SingleHeaderEvents.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					return
				}
				ao.Logger.Warnf("Go H2 single-header ringbuf read error: %v", err)
				continue
			}
			select {
			case ao.goH2SingleHeaderChannel <- record.RawSample:
			case <-ao.ctx.Done():
				return
			default:
				slog.Debug("Dropping Go H2 single-header event due to load")
			}
		}
	}()

	for {
		select {
		case <-ao.ctx.Done():
			return
		case raw := <-ao.goH2SingleHeaderChannel:
			ev, err := events.ParseGoH2SingleHeaderEvent(raw)
			if err != nil {
				ao.Logger.Debugf("ParseGoH2SingleHeaderEvent error: %v", err)
				continue
			}
			name := ev.HeaderName()
			value := ev.HeaderValue()
			if name == "" {
				continue
			}
			slog.Debug("Go H2 single-header event",
				"pid", ev.PID,
				"stream_id", ev.StreamID,
				"name", name,
				"value", value,
			)
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
		ao.links = append(ao.links, l)
		attached[target.LibPath] = true
		ao.Logger.Printf("gRPC-C uprobe attached to %s (PID %d)", target.LibPath, target.PID)
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
	method := ev.MethodString()
	if method == "" {
		slog.Debug("gRPC-C uprobe: ignoring event with empty method", "pid", ev.PID)
		return
	}
	ao.correlator.InjectGRPCCEvent(ev.PID, ev.FD, ev.StreamID, method)
}

// populateGoBPFMaps writes the offset table into the BPF map for a given target.
func (ao *APIObserver) populateGoBPFMaps(target goprobe.GoUProbeTarget) {
	if target.Inode == 0 {
		ao.Logger.Warnf("populateGoBPFMaps: no inode for %s, skipping", target.BinaryPath)
		return
	}

	ao.Logger.Printf("populateGoBPFMaps: pushing offset table for inode %d (binary %s)",
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

// defaultExcludedPorts lists Kubernetes control-plane and infrastructure ports
// that should not be traced. Populated into BPF port_exclusion_map at startup.
var defaultExcludedPorts = []uint16{
	6443,  // kube-apiserver
	2379,  // etcd client
	2380,  // etcd peer
	10250, // kubelet API
	10255, // kubelet read-only
	10256, // kube-proxy health
	9091,  // prometheus pushgateway
	9099,  // calico felix
	9100,  // node-exporter
}

// populatePortExclusions writes default + user-configured excluded ports into
// BPF port_exclusion_map. Called once at startup.
func (ao *APIObserver) populatePortExclusions() {
	excluded := uint8(1)
	count := 0
	for _, port := range defaultExcludedPorts {
		if err := ao.objs.PortExclusionMap.Put(port, excluded); err != nil {
			ao.Logger.Warnf("Failed to set port_exclusion_map[%d]: %v", port, err)
		} else {
			count++
		}
	}
	ao.Logger.Printf("Port exclusion map populated: %d ports excluded", count)
}

// Lifecycle
func (ao *APIObserver) DestroyAPIObserver() error {
	if ao == nil {
		return nil
	}
	var cleanupErr error
	if ao.cancel != nil {
		ao.cancel()
	}
	if ao.Events != nil {
		if err := ao.Events.Close(); err != nil {
			ao.Logger.Err(err.Error())
			cleanupErr = errors.Join(cleanupErr, err)
		}
	}
	if ao.goHeaderEvents != nil {
		if err := ao.goHeaderEvents.Close(); err != nil {
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
	// Close probe links BEFORE closing BPF objects — programs must outlive
	// the links that reference them.
	for _, l := range ao.links {
		if l == nil {
			continue
		}
		if err := l.Close(); err != nil {
			ao.Logger.Err(err.Error())
			cleanupErr = errors.Join(cleanupErr, err)
		}
	}
	if err := ao.objs.Close(); err != nil {
		ao.Logger.Err(err.Error())
		cleanupErr = errors.Join(cleanupErr, err)
	}
	if ao.correlator != nil {
		ao.correlator.Stop()
	}
	if ao.connManager != nil {
		ao.connManager.Stop()
	}
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
