//go:build ignore

// SPDX-License-Identifier: GPL-2.0
// Copyright 2026 Authors of KubeArmor
//
// api_observer.bpf.c — eBPF entry points for the API Observer.
//
// Architecture: dual-path network capture.
//
//   Path A — Plain traffic:
//     cgroup_skb/ingress + cgroup_skb/egress → ka_pkts_buffer (perf array)
//     → Go PacketsPoller → gopacket dissection → pb.APIEvent
//
//   Path B — TLS traffic:
//     OpenSSL uprobes (SSL_write/SSL_read) + Go crypto/tls uprobes
//     → ks_chunks_buffer (perf array) → Go TlsPoller → gopacket dissection
//     → pb.APIEvent
//
//   Path C — Go gRPC/HTTP2 header extraction:
//     uprobes on operateHeaders, handleStream, Invoke, WriteStatus, hpack.WriteField
//     → go_h2_transport_events + go_http2_events + go_h2_single_header_events
//     (ring buffers) → Go header event pipeline
//
//   Path D — gRPC-C (libgrpc.so) for Python/C++/Ruby/PHP/C#:
//     uprobe on grpc_chttp2_maybe_complete_recv_initial_metadata
//     → grpcc_events ring buffer
//
// ARM64 cross-compilation: must come before shared.h because bpf_tracing.h
// uses struct user_pt_regs when bpf_target_arm64 is defined.
#if defined(__TARGET_ARCH_arm64) || defined(__aarch64__)
#ifndef __USER_PT_REGS_DEFINED
#define __USER_PT_REGS_DEFINED
struct user_pt_regs {
    unsigned long long regs[31];
    unsigned long long sp;
    unsigned long long pc;
    unsigned long long pstate;
};
#endif
#endif

#include "shared.h"

#include "apiobserver/common/macros.h"
#include "apiobserver/common/structs.h"
#include "apiobserver/common/maps.h"
#include "apiobserver/filter_helpers.h"
#include "apiobserver/cgroup_target.h"
#include "apiobserver/packet_sniffer.h"

/* SSL capture infrastructure (ks_* probes).
 * These headers define their own SEC() entries inline. */
#include "apiobserver/ks_ssl_common.h"
#include "apiobserver/ks_fd_tracepoints.h"
#include "apiobserver/ks_tcp_kprobes.h"
#include "apiobserver/ks_connect_tracepoints.h"
#include "apiobserver/ks_openssl_uprobes.h"

/* Go HTTP/2 and gRPC transport header uprobes. */
#include "apiobserver/go_tls_trace.h"
#include "apiobserver/go_http2_trace.h"

/* gRPC-C (libgrpc.so) uprobes for Python/C++/Ruby/PHP/C#. */
#include "apiobserver/grpc_c_trace.h"

/* Exec-triggered SSL uprobe attachment (Path E).
 * raw_tracepoint/sched_process_fork + kretprobe/sys_execve emit ka_found_pid_events
 * to userspace so the Go ExecWatcher can attach SSL uprobes within milliseconds
 * of any process starting — catching ephemeral processes (curl, wget, etc.)
 * that the 30s /proc poll would miss. */
#include "apiobserver/exec_trace.h"

// ===========================================================================
// Path A: cgroup_skb packet sniffer (plain / unencrypted traffic)
// Attached per pod cgroup via CgroupController.AttachPacketSniffer().
// Returns 1 (pass) always — we never drop traffic, only observe.
// ===========================================================================

SEC("cgroup_skb/ingress")
int ka_filter_ingress_packets(struct __sk_buff *skb) {
    return handle_ingress_packets(skb);
}

SEC("cgroup_skb/egress")
int ka_filter_egress_packets(struct __sk_buff *skb) {
    return handle_egress_packets(skb);
}

// ===========================================================================
// Path B: OpenSSL and Go crypto/tls uprobes
// All SEC() entries are defined inline in:
//   ks_openssl_uprobes.h  — ks_ssl_write, ks_ssl_ret_write, ks_ssl_read, etc.
//   go_tls_trace.h        — ka_go_tls_write_*, ka_go_tls_read_*
// Nothing more to add here; the includes above cover all OpenSSL probes.
// ===========================================================================



// ===========================================================================
// Path C: Go crypto/tls uprobes
// Attached at every ret-instruction offset (discovered by x86/arm64 disassembly
// in goprobe/go_tls_offsets.go) to avoid Go runtime stack relocation issues
// that make standard uretprobes unsafe in Go binaries.
// NOTE: SEC entries are defined inline in go_tls_trace.h
// ===========================================================================

// ===========================================================================
// Path C: Go HTTP/2 / gRPC transport header uprobes
// Attached to Go gRPC and net/http HTTP2 transport methods.
// Captures :method, :path, :status, content-type directly after HPACK decoding,
// bypassing BPF-level HPACK stream state tracking.
// NOTE: SEC entries defined inline in go_http2_trace.h
// ===========================================================================

SEC("uprobe/operate_headers_server")
int ka_uprobe_operate_headers_server_entry(struct pt_regs *ctx) {
    return ka_uprobe_operate_headers_server(ctx);
}

SEC("uprobe/operate_headers_client")
int ka_uprobe_operate_headers_client_entry(struct pt_regs *ctx) {
    return ka_uprobe_operate_headers_client(ctx);
}

// ===========================================================================
// Path D: gRPC-C uprobes (libgrpc.so)
// Targets Python/C++/Ruby/PHP/C# services using the gRPC-C library.
// Reads grpc_chttp2_stream.method directly from process memory,
// bypassing HPACK entirely for reliable method extraction.
// ===========================================================================

SEC("uprobe/grpc_chttp2_maybe_complete_recv_initial_metadata")
int ka_uprobe_grpc_c_recv_initial_metadata_entry(struct pt_regs *ctx) {
    return handle_grpc_c_recv_initial_metadata(ctx);
}
