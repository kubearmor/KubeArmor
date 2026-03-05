//go:build ignore

// SPDX-License-Identifier: GPL-2.0
// Copyright 2026 Authors of KubeArmor
// 
// api_observer.bpf.c — eBPF entry points for the API Observer.

#include "shared.h"

#include "apiobserver/common/macros.h"
#include "apiobserver/common/structs.h"
#include "apiobserver/common/maps.h"
#include "apiobserver/filter_helpers.h"
#include "apiobserver/protocol_inference.h"
#include "apiobserver/conn_tracker.h"
#include "apiobserver/sock_trace.h"
#include "apiobserver/openssl_trace.h"

SEC("uprobe/SSL_write")
int uprobe_ssl_write(struct pt_regs *ctx) {
    return handle_ssl_write(ctx);
}
SEC("uprobe/SSL_read")
int uprobe_ssl_read(struct pt_regs *ctx) {
    return handle_ssl_read_entry(ctx);
}
SEC("uretprobe/SSL_read")
int uretprobe_ssl_read(struct pt_regs *ctx) {
    return handle_ssl_read_return(ctx);
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
