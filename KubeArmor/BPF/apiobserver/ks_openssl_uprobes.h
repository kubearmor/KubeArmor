/* SPDX-License-Identifier: GPL-2.0
 * Copyright 2026 Authors of KubeArmor
 *
 * ks_openssl_uprobes.h — OpenSSL/BoringSSL uprobe handlers.
 * Ported from kubeshark/tracer bpf/openssl_uprobes.c (GPL-3.0)
 *
 * Clean pattern: entry saves {buffer, count_ptr} → map[pid_tgid].
 * FD is filled by sys_enter_write tracepoint (ks_fd_tracepoints.h).
 * Address is filled by tcp_sendmsg kprobe (ks_tcp_kprobes.h).
 * Return reads byte count, emits chunk via perf buffer.
 */

#pragma once

#include "ks_ssl_common.h"

/* ---- Return value handling ---- */

static __always_inline int
ks_get_count_bytes(struct pt_regs *ctx, struct ks_ssl_info *info) {
  int return_value = PT_REGS_RC(ctx);

  if (info->count_ptr == 0) {
    /* ssl_read / ssl_write: return value IS the byte count. */
    return return_value;
  }

  /* ssl_read_ex / ssl_write_ex: return 1 for success.
   * Actual byte count is at *count_ptr. */
  if (return_value != 1)
    return 0;

  size_t count_bytes;
  long err = bpf_probe_read_user(&count_bytes, sizeof(size_t),
                                 (void *)info->count_ptr);
  if (err != 0)
    return 0;

  return (int)count_bytes;
}

/* ---- Entry handler (shared by all SSL_write/read variants) ---- */

static __always_inline void
ks_ssl_uprobe(struct pt_regs *ctx, void *ssl, uintptr_t buffer,
              int num, void *map_fd, uintptr_t count_ptr) {
  __u64 id = bpf_get_current_pid_tgid();

  /* Reuse existing info if fresh (for double-read pattern). */
  struct ks_ssl_info info = ks_lookup_ssl_info(ctx, map_fd, id);
  info.count_ptr = count_ptr;
  info.buffer = buffer;

  bpf_map_update_elem(map_fd, &id, &info, BPF_ANY);
}

/* ---- Return handler (shared by all SSL_write/read variants) ---- */

static __always_inline void
ks_ssl_uretprobe(struct pt_regs *ctx, void *map_fd, __u32 flags) {
  __u64 id = bpf_get_current_pid_tgid();

  struct ks_ssl_info *info_ptr = bpf_map_lookup_elem(map_fd, &id);
  if (info_ptr == NULL)
    return;

  struct ks_ssl_info info;
  long err = bpf_probe_read(&info, sizeof(struct ks_ssl_info), info_ptr);

  /* Don't delete map entry — needed for double-read pattern.
   * LRU eviction handles cleanup. */

  if (err != 0)
    return;

  if (info.fd == ks_invalid_fd)
    return;

  int count_bytes = ks_get_count_bytes(ctx, &info);
  if (count_bytes <= 0)
    return;

  ks_output_ssl_chunk(ctx, &info, count_bytes, id, flags);
}

/* ---- SEC entries ---- */

SEC("uprobe/ks_ssl_write")
void ks_ssl_write(struct pt_regs *ctx) {
  void *ssl = (void *)PT_REGS_PARM1(ctx);
  uintptr_t buffer = PT_REGS_PARM2(ctx);
  int num = PT_REGS_PARM3(ctx);
  ks_ssl_uprobe(ctx, ssl, buffer, num, &ks_openssl_write_context, 0);
}

SEC("uretprobe/ks_ssl_ret_write")
void ks_ssl_ret_write(struct pt_regs *ctx) {
  ks_ssl_uretprobe(ctx, &ks_openssl_write_context, 0);
}

SEC("uprobe/ks_ssl_read")
void ks_ssl_read(struct pt_regs *ctx) {
  void *ssl = (void *)PT_REGS_PARM1(ctx);
  uintptr_t buffer = PT_REGS_PARM2(ctx);
  int num = PT_REGS_PARM3(ctx);
  ks_ssl_uprobe(ctx, ssl, buffer, num, &ks_openssl_read_context, 0);
}

SEC("uretprobe/ks_ssl_ret_read")
void ks_ssl_ret_read(struct pt_regs *ctx) {
  ks_ssl_uretprobe(ctx, &ks_openssl_read_context, TLS_FLAGS_IS_READ_BIT);
}

SEC("uprobe/ks_ssl_write_ex")
void ks_ssl_write_ex(struct pt_regs *ctx) {
  void *ssl = (void *)PT_REGS_PARM1(ctx);
  uintptr_t buffer = PT_REGS_PARM2(ctx);
  int num = PT_REGS_PARM3(ctx);
  uintptr_t written = PT_REGS_PARM4(ctx);
  ks_ssl_uprobe(ctx, ssl, buffer, num, &ks_openssl_write_context, written);
}

SEC("uretprobe/ks_ssl_ret_write_ex")
void ks_ssl_ret_write_ex(struct pt_regs *ctx) {
  ks_ssl_uretprobe(ctx, &ks_openssl_write_context, 0);
}

SEC("uprobe/ks_ssl_read_ex")
void ks_ssl_read_ex(struct pt_regs *ctx) {
  void *ssl = (void *)PT_REGS_PARM1(ctx);
  uintptr_t buffer = PT_REGS_PARM2(ctx);
  int num = PT_REGS_PARM3(ctx);
  uintptr_t readbytes = PT_REGS_PARM4(ctx);
  ks_ssl_uprobe(ctx, ssl, buffer, num, &ks_openssl_read_context, readbytes);
}

SEC("uretprobe/ks_ssl_ret_read_ex")
void ks_ssl_ret_read_ex(struct pt_regs *ctx) {
  ks_ssl_uretprobe(ctx, &ks_openssl_read_context, TLS_FLAGS_IS_READ_BIT);
}

/* SSL_pending — proactively captures context for upcoming SSL_read.
 * Important for the double-read pattern. */
SEC("uprobe/ks_ssl_pending")
void ks_ssl_pending(struct pt_regs *ctx) {
  void *ssl = (void *)PT_REGS_PARM1(ctx);
  ks_ssl_uprobe(ctx, ssl, 0, 0, &ks_openssl_read_context, 0);
}
