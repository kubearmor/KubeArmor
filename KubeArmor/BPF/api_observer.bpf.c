//go:build ignore

// SPDX-License-Identifier: GPL-2.0
// Copyright 2026 Authors of KubeArmor
// 
// api_observer.bpf.c — eBPF entry points for the API Observer.

/*
 * ARM64 cross-compilation support.
 *
 * MUST come before shared.h because shared.h → bpf_tracing.h uses
 * struct user_pt_regs when bpf_target_arm64 is defined.
 *
 * bpf2go -target arm64 passes -D__TARGET_ARCH_arm64 to clang.
 * bpf_tracing.h then casts PT_REGS via struct user_pt_regs.
 * Since vmlinux.h is generated from the host kernel BTF (x86 in dev),
 * it only defines struct pt_regs. We provide the ARM64 struct here.
 */
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
#include "apiobserver/protocol_inference.h"
#include "apiobserver/conn_tracker.h"
#include "apiobserver/sock_trace.h"
#include "apiobserver/openssl_trace.h"
#include "apiobserver/go_tls_trace.h"
#include "apiobserver/go_http2_trace.h"
#include "apiobserver/grpc_c_trace.h"

/* Kubeshark-style SSL capture infrastructure.
 * These headers define their own SEC() entries inline. */
#include "apiobserver/ks_ssl_common.h"
#include "apiobserver/ks_fd_tracepoints.h"
#include "apiobserver/ks_tcp_kprobes.h"
#include "apiobserver/ks_connect_tracepoints.h"
#include "apiobserver/ks_openssl_uprobes.h"
// Probe implementations are defined inline in go_http2_trace.h using
// goroutine-based correlation (OTel-style). They capture the gRPC
// method/path from transport.Stream.Method after HPACK decoding.

// ===================================================================
// SSL uprobes — Strategy B: Userspace Offset FD access (Netty/BoringSSL)
// ===================================================================
SEC("uprobe/SSL_write")
int uprobe_ssl_write(struct pt_regs *ctx) {
    return handle_ssl_write_entry(ctx);
}
SEC("uretprobe/SSL_write")
int uretprobe_ssl_write(struct pt_regs *ctx) {
    return handle_ssl_write_return(ctx);
}
SEC("uprobe/SSL_read")
int uprobe_ssl_read(struct pt_regs *ctx) {
    return handle_ssl_read_entry(ctx);
}
SEC("uretprobe/SSL_read")
int uretprobe_ssl_read(struct pt_regs *ctx) {
    return handle_ssl_read_return(ctx);
}

// ===================================================================
// SSL uprobes — Strategy A: Nested Syscall FD access (OpenSSL/Python/static)
// ===================================================================
SEC("uprobe/SSL_write_syscall_fd")
int uprobe_ssl_write_syscall_fd(struct pt_regs *ctx) {
    return handle_ssl_write_entry_syscall_fd(ctx);
}
SEC("uretprobe/SSL_write_syscall_fd")
int uretprobe_ssl_write_syscall_fd(struct pt_regs *ctx) {
    return handle_ssl_write_return_syscall_fd(ctx);
}
SEC("uprobe/SSL_read_syscall_fd")
int uprobe_ssl_read_syscall_fd(struct pt_regs *ctx) {
    return handle_ssl_read_entry_syscall_fd(ctx);
}
SEC("uretprobe/SSL_read_syscall_fd")
int uretprobe_ssl_read_syscall_fd(struct pt_regs *ctx) {
    return handle_ssl_read_return_syscall_fd(ctx);
}

// SSL_write_ex / SSL_read_ex — nested syscall only (OpenSSL 1.1.1+)
SEC("uprobe/SSL_write_ex_syscall_fd")
int uprobe_ssl_write_ex_syscall_fd(struct pt_regs *ctx) {
    return handle_ssl_write_ex_entry_syscall_fd(ctx);
}
SEC("uretprobe/SSL_write_ex_syscall_fd")
int uretprobe_ssl_write_ex_syscall_fd(struct pt_regs *ctx) {
    return handle_ssl_write_ex_return_syscall_fd(ctx);
}
SEC("uprobe/SSL_read_ex_syscall_fd")
int uprobe_ssl_read_ex_syscall_fd(struct pt_regs *ctx) {
    return handle_ssl_read_ex_entry_syscall_fd(ctx);
}
SEC("uretprobe/SSL_read_ex_syscall_fd")
int uretprobe_ssl_read_ex_syscall_fd(struct pt_regs *ctx) {
    return handle_ssl_read_ex_return_syscall_fd(ctx);
}

// SSL_shutdown — cleanup
SEC("uprobe/SSL_shutdown")
int uprobe_ssl_shutdown(struct pt_regs *ctx) {
    return handle_ssl_shutdown(ctx);
}

// ===================================================================
// Go crypto/tls uprobes — attached to Go binaries at runtime
// ===================================================================
// NOTE: SEC entries defined inline in go_tls_trace.h
// (ka_uprobe_go_tls_write, ka_uretprobe_go_tls_write,
//  ka_uprobe_go_tls_read, ka_uretprobe_go_tls_read)

// gRPC-C uprobes — attached to libgrpc.so at runtime for Python/C++/Ruby/PHP/C# services.
// Captures grpc_chttp2_stream.method directly from process memory, bypassing the HPACK
SEC("uprobe/grpc_chttp2_maybe_complete_recv_initial_metadata")
int ka_uprobe_grpc_c_recv_initial_metadata_entry(struct pt_regs *ctx) {
    return handle_grpc_c_recv_initial_metadata(ctx);  
}

// connection lifecycle
SEC("tracepoint/sock/inet_sock_set_state")
int tracepoint_inet_sock_set_state(struct inet_sock_set_state_args *ctx) {
    return handle_inet_sock_set_state(ctx);
}

// Egress: write / writev / sendto / sendmsg 
SEC("kprobe/sys_write")
int kprobe_sys_write(struct pt_regs *ctx) {
    return handle_sys_write_entry(ctx);
}

SEC("kprobe/sys_writev")
int kprobe_sys_writev(struct pt_regs *ctx) {
    return handle_sys_writev_entry(ctx);
}

SEC("kprobe/sys_sendto")
int kprobe_sys_sendto(struct pt_regs *ctx) {
    return handle_sys_sendto_entry(ctx);
}

SEC("kprobe/sys_sendmsg")
int kprobe_sys_sendmsg(struct pt_regs *ctx) {
    return handle_sys_sendmsg_entry(ctx);
}

// Ingress: read / readv / recvfrom / recvmsg (entry + return pairs)
SEC("kprobe/sys_read")
int kprobe_sys_read(struct pt_regs *ctx) {
    return handle_sys_read_entry(ctx);
}

SEC("kretprobe/sys_read")
int kretprobe_sys_read(struct pt_regs *ctx) {
    return handle_sys_read_return(ctx);
}

SEC("kprobe/sys_readv")
int kprobe_sys_readv(struct pt_regs *ctx) {
    return handle_sys_readv_entry(ctx);
}

SEC("kretprobe/sys_readv")
int kretprobe_sys_readv(struct pt_regs *ctx) {
    return handle_sys_readv_return(ctx);
}

SEC("kprobe/sys_recvfrom")
int kprobe_sys_recvfrom(struct pt_regs *ctx) {
    return handle_sys_recvfrom_entry(ctx);
}

SEC("kretprobe/sys_recvfrom")
int kretprobe_sys_recvfrom(struct pt_regs *ctx) {
    return handle_sys_recvfrom_return(ctx);
}

SEC("kprobe/sys_recvmsg")
int kprobe_sys_recvmsg(struct pt_regs *ctx) {
    return handle_sys_recvmsg_entry(ctx);
}

SEC("kretprobe/sys_recvmsg")
int kretprobe_sys_recvmsg(struct pt_regs *ctx) {
    return handle_sys_recvmsg_return(ctx);
}

// FD lifecycle tracking
SEC("kprobe/sys_connect")
int kprobe_sys_connect(struct pt_regs *ctx) {
    return handle_connect_entry(ctx);
}

SEC("kretprobe/sys_connect")
int kretprobe_sys_connect(struct pt_regs *ctx) {
    return handle_connect_return(ctx);
}

SEC("kretprobe/sys_accept")
int kretprobe_sys_accept(struct pt_regs *ctx) {
    return handle_accept_return(ctx);
}

SEC("kretprobe/sys_accept4")
int kretprobe_sys_accept4(struct pt_regs *ctx) {
    return handle_accept_return(ctx);
}

SEC("kprobe/sys_close")
int kprobe_sys_close(struct pt_regs *ctx) {
    return handle_close_entry(ctx);
}

SEC("uprobe/operate_headers_server")
int ka_uprobe_operate_headers_server_entry(struct pt_regs *ctx) {
    return ka_uprobe_operate_headers_server(ctx);
}
SEC("uprobe/operate_headers_client")
int ka_uprobe_operate_headers_client_entry(struct pt_regs *ctx) {
    return ka_uprobe_operate_headers_client(ctx);
}
