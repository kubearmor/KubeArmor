/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Authors of KubeArmor
 *
 * openssl_trace.h — SSL_write / SSL_read uprobes.
 *
 * Two FD extraction strategies (ported from Pixie openssl_trace.c):
 *
 * Strategy A: Nested Syscall (OpenSSL, Python, static builds)
 *   Entry:  set ssl_user_space_call_map[pid_tgid] = {fd: -1}
 *           Syscall kprobes fill the FD via propagate_fd_to_user_space_call()
 *   Return: read FD from ssl_user_space_call_map, emit event
 *
 * Strategy B: Userspace Offsets (Netty/BoringSSL)
 *   Entry:  resolve FD via get_fd_from_ssl() using per-TGID ssl_symaddrs
 *   Return: emit using saved FD
 *
 * Dedup: conn->is_ssl = 1 causes sock_trace.h kprobes to skip,
 * preventing duplicate (encrypted + plaintext) events.
 */
#pragma once
#include "common/macros.h"
#include "common/maps.h"
#include "common/structs.h"

/* ===================================================================
 * FD extraction helpers
 * =================================================================== */

/* get_fd_from_ssl — Extract FD via ssl->rbio->num using per-TGID offsets.
 * Used for Netty/BoringSSL (Strategy B: userspace offsets). */
static __attribute__((always_inline)) s32 get_fd_from_ssl(u32 tgid, void *ssl_ptr) {
  struct ssl_symaddrs *addrs = bpf_map_lookup_elem(&ssl_symaddrs, &tgid);
  if (!addrs || addrs->ssl_rbio_offset < 0 || addrs->bio_num_offset < 0) {
    return -1;
  }

  void *rbio = NULL;
  bpf_probe_read_user(&rbio, sizeof(rbio),
                      (void *)((u64)ssl_ptr + addrs->ssl_rbio_offset));
  if (!rbio) {
    return -1;
  }

  int fd = -1;
  bpf_probe_read_user(&fd, sizeof(fd),
                      (void *)((u64)rbio + addrs->bio_num_offset));
  return (s32)fd;
}

/* get_fd_and_eval_nested_syscall — Read FD from ssl_user_space_call_map.
 * Used for Strategy A: nested syscall FD detection.
 * Consumes and deletes the map entry. */
static __attribute__((always_inline)) s32
get_fd_and_eval_nested_syscall(u64 pid_tgid) {
  struct nested_syscall_fd_t *nsc =
      bpf_map_lookup_elem(&ssl_user_space_call_map, &pid_tgid);
  if (!nsc) {
    return -1;
  }

  s32 fd = nsc->fd;
  /* Note: mismatched_fds is logged but we still use best-effort FD */
  bpf_map_delete_elem(&ssl_user_space_call_map, &pid_tgid);
  return fd;
}

/* ===================================================================
 * Shared event emission
 * =================================================================== */

/* emit_ssl_event — shared helper for both SSL_write and SSL_read return.
 * Resolves sock_ptr from FD, marks connection as SSL, emits decrypted payload. */
static __attribute__((always_inline)) int
emit_ssl_event_with_fd(void *buf, u32 len, u8 direction, s32 fd) {
  if (fd <= 2 || !buf || len == 0)
    return 0;

  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 tgid = (u32)(pid_tgid >> 32);
  struct conn_id cid = {.tgid = tgid, .fd = (u32)fd};
  u64 *sp = bpf_map_lookup_elem(&pid_fd_to_sock, &cid);
  if (!sp || *sp == 0)
    return 0;

  u64 sock_ptr = *sp;

  /* Mark connection as SSL — suppresses kprobe path for this sock */
  struct conn_info *conn = bpf_map_lookup_elem(&connections, &sock_ptr);
  if (conn && !conn->is_ssl) {
    conn->is_ssl = 1;
    bpf_map_update_elem(&connections, &sock_ptr, conn, BPF_EXIST);
  }

  u32 zero = 0;
  struct data_event *e = bpf_map_lookup_elem(&event_scratch, &zero);
  if (!e)
    return 0;

  /* Protocol-aware capture limit. */
  u32 max_capture = MAX_DATA_SIZE;
  if (conn)
    max_capture = get_protocol_max_capture(conn->protocol);

  e->flags = FLAG_IS_SSL;
  u32 to_copy = len < max_capture ? len : max_capture;
  if (bpf_probe_read_user(e->payload, to_copy & (MAX_DATA_SIZE - 1), buf) < 0)
    return 0;
  e->data_len = to_copy;
  if (len > max_capture)
    e->flags |= FLAG_TRUNCATED;

  return emit_data_event(sock_ptr, direction);
}

/* process_openssl_data — Handle return of SSL_read/SSL_write/_ex variants.
 * Reads the return code and for _ex calls, dereferences the output length ptr. */
static __attribute__((always_inline)) void
process_openssl_data(struct pt_regs *ctx, u8 direction,
                     void *buf, s32 fd, u64 ssl_ex_len_ptr) {
  /* Do not change to ssize_t/long! Using int prevents negative aliasing
   * from SSL return codes (from Pixie openssl_trace.c:46-53). */
  int bytes_count = (int)PT_REGS_RC(ctx);

  /* SSL_*_ex returns 1 on success; actual bytes in *ssl_ex_len_ptr */
  if (bytes_count == 1 && ssl_ex_len_ptr != 0) {
    u64 ex_bytes = 0;
    bpf_probe_read_user(&ex_bytes, sizeof(ex_bytes), (void *)ssl_ex_len_ptr);
    bytes_count = (int)ex_bytes;
  }

  if (bytes_count <= 0)
    return;

  emit_ssl_event_with_fd(buf, (u32)bytes_count, direction, fd);
}

/* ===================================================================
 * Strategy B: Userspace Offset FD access (Netty/BoringSSL)
 * Get FD at entry time via ssl->rbio->num struct walk.
 * =================================================================== */

/* SSL_write(SSL *ssl, const void *buf, int num) */
static __attribute__((always_inline)) int
handle_ssl_write_entry(struct pt_regs *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 tgid = (u32)(pid_tgid >> 32);

  void *ssl = (void *)PT_REGS_PARM1(ctx);
  void *buf = (void *)PT_REGS_PARM2(ctx);
  s32 fd = get_fd_from_ssl(tgid, ssl);
  if (fd <= 2)
    return 0;

  struct ssl_write_args args = {
    .ssl_ptr = (u64)ssl,
    .buf = (u64)buf,
    .ssl_ex_len_ptr = 0,
  };
  bpf_map_update_elem(&active_ssl_write_args, &pid_tgid, &args, BPF_ANY);

  /* Mark connection as SSL right away */
  struct conn_id cid = {.tgid = tgid, .fd = (u32)fd};
  u64 *sp = bpf_map_lookup_elem(&pid_fd_to_sock, &cid);
  if (sp && *sp != 0) {
    struct conn_info *conn = bpf_map_lookup_elem(&connections, sp);
    if (conn && !conn->is_ssl) {
      conn->is_ssl = 1;
      bpf_map_update_elem(&connections, sp, conn, BPF_EXIST);
    }
  }
  return 0;
}

static __attribute__((always_inline)) int
handle_ssl_write_return(struct pt_regs *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 tgid = (u32)(pid_tgid >> 32);

  struct ssl_write_args *args =
      bpf_map_lookup_elem(&active_ssl_write_args, &pid_tgid);
  if (!args)
    return 0;

  void *ssl = (void *)args->ssl_ptr;
  void *buf = (void *)args->buf;
  u64 ex_len = args->ssl_ex_len_ptr;
  bpf_map_delete_elem(&active_ssl_write_args, &pid_tgid);

  s32 fd = get_fd_from_ssl(tgid, ssl);
  if (fd <= 2)
    return 0;

  process_openssl_data(ctx, DIR_EGRESS, buf, fd, ex_len);
  return 0;
}

/* SSL_read(SSL *ssl, void *buf, int num) */
static __attribute__((always_inline)) int
handle_ssl_read_entry(struct pt_regs *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 tgid = (u32)(pid_tgid >> 32);

  void *ssl = (void *)PT_REGS_PARM1(ctx);
  void *buf = (void *)PT_REGS_PARM2(ctx);
  s32 fd = get_fd_from_ssl(tgid, ssl);
  if (fd <= 2)
    return 0;

  struct ssl_read_args args = {
    .ssl_ptr = (u64)ssl,
    .buf = (u64)buf,
    .ssl_ex_len_ptr = 0,
  };
  bpf_map_update_elem(&active_ssl_read_args, &pid_tgid, &args, BPF_ANY);

  /* Mark connection as SSL right away */
  struct conn_id cid = {.tgid = tgid, .fd = (u32)fd};
  u64 *sp = bpf_map_lookup_elem(&pid_fd_to_sock, &cid);
  if (sp && *sp != 0) {
    struct conn_info *conn = bpf_map_lookup_elem(&connections, sp);
    if (conn && !conn->is_ssl) {
      conn->is_ssl = 1;
      bpf_map_update_elem(&connections, sp, conn, BPF_EXIST);
    }
  }
  return 0;
}

static __attribute__((always_inline)) int
handle_ssl_read_return(struct pt_regs *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 tgid = (u32)(pid_tgid >> 32);

  struct ssl_read_args *args =
      bpf_map_lookup_elem(&active_ssl_read_args, &pid_tgid);
  if (!args)
    return 0;

  void *ssl = (void *)args->ssl_ptr;
  void *buf = (void *)args->buf;
  u64 ex_len = args->ssl_ex_len_ptr;
  bpf_map_delete_elem(&active_ssl_read_args, &pid_tgid);

  s32 fd = get_fd_from_ssl(tgid, ssl);
  if (fd <= 2)
    return 0;

  process_openssl_data(ctx, DIR_INGRESS, buf, fd, ex_len);
  return 0;
}

/* ===================================================================
 * Strategy A: Nested Syscall FD access (OpenSSL, Python, static)
 * FD is captured by inner write()/read() syscalls via
 * propagate_fd_to_user_space_call() in syscall_trace.h.
 * =================================================================== */

/* SSL_write — nested syscall variant */
static __attribute__((always_inline)) int
handle_ssl_write_entry_syscall_fd(struct pt_regs *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();

  /* Signal that an SSL call is active — syscall kprobes will fill the FD */
  struct nested_syscall_fd_t nsc = {.fd = -1, .mismatched_fds = 0};
  bpf_map_update_elem(&ssl_user_space_call_map, &pid_tgid, &nsc, BPF_ANY);

  void *buf = (void *)PT_REGS_PARM2(ctx);
  struct ssl_write_args args = {
    .ssl_ptr = (u64)PT_REGS_PARM1(ctx),
    .buf = (u64)buf,
    .ssl_ex_len_ptr = 0,
  };
  bpf_map_update_elem(&active_ssl_write_args, &pid_tgid, &args, BPF_ANY);
  return 0;
}

static __attribute__((always_inline)) int
handle_ssl_write_return_syscall_fd(struct pt_regs *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();

  s32 fd = get_fd_and_eval_nested_syscall(pid_tgid);
  if (fd <= 2)
    goto cleanup;

  {
    struct ssl_write_args *args =
        bpf_map_lookup_elem(&active_ssl_write_args, &pid_tgid);
    if (args) {
      process_openssl_data(ctx, DIR_EGRESS, (void *)args->buf, fd, args->ssl_ex_len_ptr);
    }
  }

cleanup:
  bpf_map_delete_elem(&active_ssl_write_args, &pid_tgid);
  return 0;
}

/* SSL_read — nested syscall variant */
static __attribute__((always_inline)) int
handle_ssl_read_entry_syscall_fd(struct pt_regs *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();

  struct nested_syscall_fd_t nsc = {.fd = -1, .mismatched_fds = 0};
  bpf_map_update_elem(&ssl_user_space_call_map, &pid_tgid, &nsc, BPF_ANY);

  void *buf = (void *)PT_REGS_PARM2(ctx);
  struct ssl_read_args args = {
    .ssl_ptr = (u64)PT_REGS_PARM1(ctx),
    .buf = (u64)buf,
    .ssl_ex_len_ptr = 0,
  };
  bpf_map_update_elem(&active_ssl_read_args, &pid_tgid, &args, BPF_ANY);
  return 0;
}

static __attribute__((always_inline)) int
handle_ssl_read_return_syscall_fd(struct pt_regs *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();

  s32 fd = get_fd_and_eval_nested_syscall(pid_tgid);
  if (fd <= 2)
    goto cleanup;

  {
    struct ssl_read_args *args =
        bpf_map_lookup_elem(&active_ssl_read_args, &pid_tgid);
    if (args) {
      process_openssl_data(ctx, DIR_INGRESS, (void *)args->buf, fd, args->ssl_ex_len_ptr);
    }
  }

cleanup:
  bpf_map_delete_elem(&active_ssl_read_args, &pid_tgid);
  return 0;
}

/* ===================================================================
 * _ex variants (SSL_write_ex / SSL_read_ex) — nested syscall only
 * These return 1 on success with byte count in *written / *readbytes.
 * =================================================================== */

/* SSL_write_ex(SSL *ssl, const void *buf, size_t num, size_t *written) */
static __attribute__((always_inline)) int
handle_ssl_write_ex_entry_syscall_fd(struct pt_regs *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();

  struct nested_syscall_fd_t nsc = {.fd = -1, .mismatched_fds = 0};
  bpf_map_update_elem(&ssl_user_space_call_map, &pid_tgid, &nsc, BPF_ANY);

  struct ssl_write_args args = {
    .ssl_ptr = (u64)PT_REGS_PARM1(ctx),
    .buf = (u64)PT_REGS_PARM2(ctx),
    .ssl_ex_len_ptr = (u64)PT_REGS_PARM4(ctx),  /* size_t *written */
  };
  bpf_map_update_elem(&active_ssl_write_args, &pid_tgid, &args, BPF_ANY);
  return 0;
}

static __attribute__((always_inline)) int
handle_ssl_write_ex_return_syscall_fd(struct pt_regs *ctx) {
  /* Reuse non-ex return — same logic, just ssl_ex_len_ptr is set */
  return handle_ssl_write_return_syscall_fd(ctx);
}

/* SSL_read_ex(SSL *ssl, void *buf, size_t num, size_t *readbytes) */
static __attribute__((always_inline)) int
handle_ssl_read_ex_entry_syscall_fd(struct pt_regs *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();

  struct nested_syscall_fd_t nsc = {.fd = -1, .mismatched_fds = 0};
  bpf_map_update_elem(&ssl_user_space_call_map, &pid_tgid, &nsc, BPF_ANY);

  struct ssl_read_args args = {
    .ssl_ptr = (u64)PT_REGS_PARM1(ctx),
    .buf = (u64)PT_REGS_PARM2(ctx),
    .ssl_ex_len_ptr = (u64)PT_REGS_PARM4(ctx),  /* size_t *readbytes */
  };
  bpf_map_update_elem(&active_ssl_read_args, &pid_tgid, &args, BPF_ANY);
  return 0;
}

static __attribute__((always_inline)) int
handle_ssl_read_ex_return_syscall_fd(struct pt_regs *ctx) {
  return handle_ssl_read_return_syscall_fd(ctx);
}

/* ===================================================================
 * SSL_shutdown — cleanup on connection close
 * =================================================================== */

/* SSL_shutdown(SSL *ssl) — clean up in-flight args maps */
static __attribute__((always_inline)) int
handle_ssl_shutdown(struct pt_regs *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();

  /* Clean up any in-flight SSL operations for this thread */
  bpf_map_delete_elem(&active_ssl_read_args, &pid_tgid);
  bpf_map_delete_elem(&active_ssl_write_args, &pid_tgid);
  bpf_map_delete_elem(&ssl_user_space_call_map, &pid_tgid);

  return 0;
}
