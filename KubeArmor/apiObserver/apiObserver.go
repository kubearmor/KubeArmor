// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package apiobserver

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"time"

	pb "github.com/accuknox/SentryFlow/protobuf/golang"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/kubearmor/KubeArmor/KubeArmor/apiObserver/events"
	"github.com/kubearmor/KubeArmor/KubeArmor/apiObserver/events/conn"
	"github.com/kubearmor/KubeArmor/KubeArmor/apiObserver/filter"
	"github.com/kubearmor/KubeArmor/KubeArmor/apiObserver/ssl"
	fd "github.com/kubearmor/KubeArmor/KubeArmor/feeder"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -cc clang apiObserver ../BPF/api_observer.bpf.c

// APIObserver captures and processes network events via eBPF.
type APIObserver struct {
	Logger fd.Feeder

	nodeName string

	watcher *Watcher

	// BPF compiled objects and attached probe links.
	objs  apiObserverObjects
	links []io.Closer

	// Ring buffer: BPF emits samples here; we drain into EventsChannel.
	Events        *ringbuf.Reader
	EventsChannel chan []byte

	// Pipeline components.
	filterer    *filter.Filterer
	correlator  events.Correlator
	connManager *conn.ConnectionManager

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func NewAPIObserver(node tp.Node, pinpath string, logger fd.Feeder) (*APIObserver, error) {
	ao := &APIObserver{
		Logger:   logger,
		nodeName: node.NodeName,
	}
	ao.ctx, ao.cancel = context.WithCancel(context.Background())

	var err error
	ao.watcher, err = NewWatcher()
	if err != nil {
		ao.Logger.Warnf("Failed to create K8s watcher (running without enrichment): %v", err)
	} else if err = ao.watcher.Start(ao.ctx); err != nil {
		ao.Logger.Warnf("Failed to start K8s watcher: %v", err)
		ao.watcher = nil
	} else {
		ao.Logger.Print("Kubernetes watcher started successfully")
	}

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

	if err = ao.attachTracepoint(); err != nil {
		ao.Logger.Warnf("Failed to attach tracepoint (connection tracking degraded): %v", err)
	}

	if err = ao.attachKprobes(); err != nil {
		ao.Logger.Errf("Failed to attach kprobes: %v", err)
		return nil, err
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
	go ao.TraceEvents()
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
	// Request filter.
	ua := trace.RequestHeaders["user-agent"]
	if !ao.filterer.ShouldTraceRequest(trace.URL, ua) {
		return
	}
	if ao.filterer.IsHealthProbe(trace.URL, ua, trace.ResponseBody) {
		return
	}
	if ao.filterer.IsLoopbackTraffic(ev.SrcIPString(), ev.DstIPString()) {
		return
	}

	srcName, srcNS := ao.resolveWorkload(ev.SrcIPString())
	dstName, dstNS := ao.resolveWorkload(ev.DstIPString())

	if !ao.filterer.ShouldTraceConnection(srcName, dstName, srcNS, dstNS) {
		return
	}
	if ao.filterer.IsInternalHop(srcName, dstName, srcNS, dstNS) {
		slog.Debug("Filtered internal cross-namespace hop",
			"src", srcName, "srcNS", srcNS,
			"dst", dstName, "dstNS", dstNS,
			"method", trace.Method, "url", trace.URL)
		return
	}

	// Build pb.APIEvent.
	latencyNs := uint64(trace.DurationMs) * uint64(time.Millisecond)

	var statusCode int32
	if n, err := fmt.Sscanf(trace.Status, "%d", &statusCode); n == 0 || err != nil {
		statusCode = 0
	}

	apiEvent := pb.APIEvent{
		Metadata: &pb.Metadata{
			Timestamp:    uint64(time.Now().UnixNano()),
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
			Method:  sanitizeUTF8(trace.Method),
			Path:    sanitizeUTF8(trace.URL),
			Headers: sanitizeHeaders(trace.RequestHeaders),
			Body:    sanitizeUTF8(trace.RequestBody),
		},
		Response: &pb.Response{
			StatusCode: statusCode,
			Headers:    sanitizeHeaders(trace.ResponseHeaders),
			Body:       sanitizeUTF8(trace.ResponseBody),
		},
		Protocol:  ev.ProtocolString(),
		LatencyNs: latencyNs,
	}

	// Push to feeder → gRPC subscribers.
	ao.Logger.PushAPIEvent(apiEvent)
	ao.Logger.Printf("API Event: %s %s -> %s/%s %s (%dms)",
		sanitizeUTF8(trace.Method), sanitizeUTF8(trace.URL), dstNS, dstName, trace.Status, trace.DurationMs)
}

// K8s metadata resolution

func (ao *APIObserver) resolveWorkload(ip string) (name, namespace string) {
	if ao.watcher == nil {
		return ip, ""
	}
	if uri := ao.watcher.GetPodURI(ip); uri != "" {
		if before, after, ok := strings.Cut(uri, "/"); ok {
			return after, before
		}
		return uri, ""
	}
	if svcs := ao.watcher.GetServicesByIP(ip); len(svcs) > 0 {
		return svcs[0].Name, svcs[0].Namespace
	}
	return ip, ""
}

// SSL uprobes -> currently not being called. In Progress 
func (ao *APIObserver) attachSSLUprobes() error {
	libPaths, err := ssl.LibSSLPaths()
	if err != nil {
		ao.Logger.Warnf("libssl not found, HTTPS capture disabled: %v", err)
		return nil
	}
	for _, libPath := range libPaths {
		offsets, err := ssl.OffsetsForLib(libPath)
		if err != nil {
			ao.Logger.Warnf("SSL struct offsets unknown for %s: %v", libPath, err)
			continue
		}
		if err := ao.objs.SslSymaddrs.Put(uint32(0), offsets); err != nil {
			return fmt.Errorf("ssl_symaddrs update: %w", err)
		}
		ex, err := link.OpenExecutable(libPath)
		if err != nil {
			return fmt.Errorf("open %s: %w", libPath, err)
		}
		if l, err := ex.Uprobe("SSL_write", ao.objs.UprobeSslWrite, nil); err == nil {
			ao.links = append(ao.links, l)
			ao.Logger.Printf("uprobe/SSL_write attached (%s)", libPath)
		}
		if lEntry, err := ex.Uprobe("SSL_read", ao.objs.UprobeSslRead, nil); err == nil {
			ao.links = append(ao.links, lEntry)
			if lRet, err := ex.Uretprobe("SSL_read", ao.objs.UretprobeSslRead, nil); err == nil {
				ao.links = append(ao.links, lRet)
				ao.Logger.Printf("uprobe+uretprobe/SSL_read attached (%s)", libPath)
			}
		}
	}
	return nil
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
	if err := ao.objs.Close(); err != nil {
		ao.Logger.Err(err.Error())
		cleanupErr = errors.Join(cleanupErr, err)
	}
	for _, l := range ao.links {
		if l == nil {
			continue
		}
		if err := l.Close(); err != nil {
			ao.Logger.Err(err.Error())
			cleanupErr = errors.Join(cleanupErr, err)
		}
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
