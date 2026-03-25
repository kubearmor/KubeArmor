/* SPDX-License-Identifier: GPL-2.0
 * Copyright 2026 Authors of KubeArmor
 *
 * ks_fd_tracepoints.h — Syscall tracepoints for SSL FD resolution.
 * Ported from kubeshark/tracer bpf/fd_tracepoints.c (GPL-3.0)
 *
 * When SSL_write/SSL_read calls the inner write()/read() syscall,
 * these tracepoints fire and capture the FD from the syscall args.
 * The FD is written back into the ssl_info entry in the
 * openssl_write_context or openssl_read_context map.
 *
 * For Go crypto/tls, the FD is stored in a separate kernel context
 * map (go_kernel_write/read_context) because Go's FD was already
 * extracted by the uprobe from the tls.Conn struct.
 */

#pragma once

#include "common/macros.h"
#include "common/maps.h"
#include "common/structs.h"

/* ---- Tracepoint context structs ---- */

struct ks_sys_enter_rw_ctx {
  __u64 __unused_syscall_header;
  __u32 __unused_syscall_nr;
  __u64 fd;
  __u64 *buf;
  __u64 count;
};

struct ks_sys_exit_rw_ctx {
  __u64 __unused_syscall_header;
  __u32 __unused_syscall_nr;
  __u64 ret;
};

struct ks_sys_enter_recvfrom_sendto_ctx {
  __u64 __unused_syscall_header;
  __u32 __unused_syscall_nr;
  __u64 fd;
  void *buf;
  __u64 count;
  __u32 flags;
  void *addr;
  void *addrlen;
};

/* ---- Inline handlers ---- */

static __always_inline void
ks_fd_handle_openssl(void *ctx, __u32 fd, __u64 id,
                     struct ks_ssl_info *info_ptr, void *map_fd) {
  struct ks_ssl_info info;
  long err = bpf_probe_read(&info, sizeof(struct ks_ssl_info), info_ptr);
  if (err != 0)
    return;

  info.fd = fd;
  bpf_map_update_elem(map_fd, &id, &info, BPF_ANY);
}

static __always_inline void
ks_fd_handle_go(void *ctx, __u32 fd, __u64 id, void *map_fd) {
  bpf_map_update_elem(map_fd, &id, &fd, BPF_ANY);
}

static __always_inline void ks_handle_read(void *ctx, __u64 fd) {
  __u64 id = bpf_get_current_pid_tgid();

  struct ks_ssl_info *info_ptr =
      bpf_map_lookup_elem(&ks_openssl_read_context, &id);
  if (info_ptr != NULL)
    ks_fd_handle_openssl(ctx, fd, id, info_ptr, &ks_openssl_read_context);

  ks_fd_handle_go(ctx, fd, id, &ks_go_kernel_read_context);
}

static __always_inline void ks_handle_write(void *ctx, __u64 fd) {
  __u64 id = bpf_get_current_pid_tgid();

  struct ks_ssl_info *info_ptr =
      bpf_map_lookup_elem(&ks_openssl_write_context, &id);
  if (info_ptr != NULL)
    ks_fd_handle_openssl(ctx, fd, id, info_ptr, &ks_openssl_write_context);

  ks_fd_handle_go(ctx, fd, id, &ks_go_kernel_write_context);
}

/* ---- SEC entry probes ---- */

SEC("tracepoint/syscalls/sys_enter_read")
void ks_sys_enter_read(struct ks_sys_enter_rw_ctx *ctx) {
  ks_handle_read(ctx, ctx->fd);
}

SEC("tracepoint/syscalls/sys_enter_write")
void ks_sys_enter_write(struct ks_sys_enter_rw_ctx *ctx) {
  ks_handle_write(ctx, ctx->fd);
}

SEC("tracepoint/syscalls/sys_enter_recvfrom")
void ks_sys_enter_recvfrom(struct ks_sys_enter_recvfrom_sendto_ctx *ctx) {
  ks_handle_read(ctx, ctx->fd);
}

SEC("tracepoint/syscalls/sys_enter_sendto")
void ks_sys_enter_sendto(struct ks_sys_enter_recvfrom_sendto_ctx *ctx) {
  ks_handle_write(ctx, ctx->fd);
}

/* Exit probes: clean up Go kernel context (no longer needed).
 * OpenSSL context is intentionally kept for double-read pattern. */
SEC("tracepoint/syscalls/sys_exit_read")
void ks_sys_exit_read(struct ks_sys_exit_rw_ctx *ctx) {
  __u64 id = bpf_get_current_pid_tgid();
  bpf_map_delete_elem(&ks_go_kernel_read_context, &id);
}

SEC("tracepoint/syscalls/sys_exit_write")
void ks_sys_exit_write(struct ks_sys_exit_rw_ctx *ctx) {
  __u64 id = bpf_get_current_pid_tgid();
  bpf_map_delete_elem(&ks_go_kernel_write_context, &id);
}
