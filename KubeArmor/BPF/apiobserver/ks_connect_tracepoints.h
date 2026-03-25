/* SPDX-License-Identifier: GPL-2.0
 * Copyright 2026 Authors of KubeArmor
 *
 * ks_connect_tracepoints.h — Connect/accept tracepoints for connection tracking.
 * Ported from kubeshark/tracer bpf/fd_to_address_tracepoints.c (GPL-3.0)
 *
 * Tracks which FDs are client-side (from connect) vs server-side (from accept).
 * The connection_context map entry is REQUIRED by output_ssl_chunk —
 * without it, we can't determine the connection role and the event is dropped.
 */

#pragma once

#include "common/macros.h"
#include "common/maps.h"
#include "common/structs.h"

/* ---- Accept tracepoint context ---- */

struct ks_accept_info {
  uintptr_t addrlen;
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 4096);
  __type(key, __u64);
  __type(value, struct ks_accept_info);
} ks_accept_syscall_context SEC(".maps");

struct ks_sys_enter_accept4_ctx {
  __u64 __unused_syscall_header;
  __u32 __unused_syscall_nr;
  __u64 fd;
  __u64 *sockaddr;
  uintptr_t addrlen;
};

struct ks_sys_exit_accept4_ctx {
  __u64 __unused_syscall_header;
  __u32 __unused_syscall_nr;
  __u64 ret;
};

SEC("tracepoint/syscalls/sys_enter_accept4")
void ks_sys_enter_accept4(struct ks_sys_enter_accept4_ctx *ctx) {
  __u64 id = bpf_get_current_pid_tgid();
  struct ks_accept_info info = { .addrlen = ctx->addrlen };
  bpf_map_update_elem(&ks_accept_syscall_context, &id, &info, BPF_ANY);
}

SEC("tracepoint/syscalls/sys_exit_accept4")
void ks_sys_exit_accept4(struct ks_sys_exit_accept4_ctx *ctx) {
  __u64 id = bpf_get_current_pid_tgid();

  if (ctx->ret < 0) {
    bpf_map_delete_elem(&ks_accept_syscall_context, &id);
    return;
  }

  struct ks_accept_info *info_ptr =
      bpf_map_lookup_elem(&ks_accept_syscall_context, &id);
  if (info_ptr == NULL)
    return;

  bpf_map_delete_elem(&ks_accept_syscall_context, &id);

  /* Server-side: flags = 0 (no CLIENT bit). */
  ks_conn_flags flags = 0;

  __u32 pid = id >> 32;
  __u32 fd = (__u32)ctx->ret; /* accept returns the new FD */

  __u64 key = (__u64)pid << 32 | fd;
  bpf_map_update_elem(&ks_connection_context, &key, &flags, BPF_ANY);
}

/* ---- Connect tracepoint context ---- */

struct ks_connect_info {
  __u64 fd;
  __u32 addrlen;
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 4096);
  __type(key, __u64);
  __type(value, struct ks_connect_info);
} ks_connect_syscall_info SEC(".maps");

struct ks_sys_enter_connect_ctx {
  __u64 __unused_syscall_header;
  __u32 __unused_syscall_nr;
  __u64 fd;
  __u64 *sockaddr;
  __u32 addrlen;
};

struct ks_sys_exit_connect_ctx {
  __u64 __unused_syscall_header;
  __u32 __unused_syscall_nr;
  __u64 ret;
};

SEC("tracepoint/syscalls/sys_enter_connect")
void ks_sys_enter_connect(struct ks_sys_enter_connect_ctx *ctx) {
  __u64 id = bpf_get_current_pid_tgid();
  struct ks_connect_info info = { .fd = ctx->fd, .addrlen = ctx->addrlen };
  bpf_map_update_elem(&ks_connect_syscall_info, &id, &info, BPF_ANY);
}

SEC("tracepoint/syscalls/sys_exit_connect")
void ks_sys_exit_connect(struct ks_sys_exit_connect_ctx *ctx) {
  __u64 id = bpf_get_current_pid_tgid();

  /* Note: don't check ret != 0 because async connect returns EINPROGRESS. */
  struct ks_connect_info *info_ptr =
      bpf_map_lookup_elem(&ks_connect_syscall_info, &id);
  if (info_ptr == NULL)
    return;

  struct ks_connect_info info;
  bpf_probe_read(&info, sizeof(struct ks_connect_info), info_ptr);
  bpf_map_delete_elem(&ks_connect_syscall_info, &id);

  /* Client-side: set CLIENT bit. */
  ks_conn_flags flags = TLS_FLAGS_IS_CLIENT_BIT;

  __u32 pid = id >> 32;
  __u32 fd = (__u32)info.fd;

  __u64 key = (__u64)pid << 32 | fd;
  bpf_map_update_elem(&ks_connection_context, &key, &flags, BPF_ANY);
}
