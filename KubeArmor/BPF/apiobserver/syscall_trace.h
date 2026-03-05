/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Authors of KubeArmor
 *
 * syscall_trace.h — Syscall-level data capture for the API Observer.
 *
 * Covers socket I/O syscalls:
 *   - write, writev, sendto, sendmsg (egress): read, readv, recvfrom, recvmsg
 */
#pragma once

#include "common/macros.h"
#include "common/maps.h"
#include "common/structs.h"
#include "conn_tracker.h"

static __always_inline struct pt_regs *get_syscall_regs(struct pt_regs *ctx) {
  return (struct pt_regs *)PT_REGS_PARM1(ctx);
}

static __always_inline u64 syscall_arg1(struct pt_regs *regs) {
  u64 val = 0;
  bpf_probe_read_kernel(&val, sizeof(val), &regs->di);
  return val;
}

static __always_inline u64 syscall_arg2(struct pt_regs *regs) {
  u64 val = 0;
  bpf_probe_read_kernel(&val, sizeof(val), &regs->si);
  return val;
}

static __always_inline u64 syscall_arg3(struct pt_regs *regs) {
  u64 val = 0;
  bpf_probe_read_kernel(&val, sizeof(val), &regs->dx);
  return val;
}

static __always_inline u64 syscall_arg4(struct pt_regs *regs) {
  u64 val = 0;
  bpf_probe_read_kernel(&val, sizeof(val), &regs->r10);
  return val;
}


// iovec / msghdr helpers — extract first buffer from vectored I/O structs.
//
// These are USERSPACE pointers, so we use bpf_probe_read_user.
//
// struct iovec { void *iov_base; size_t iov_len; };   // 16 bytes on x86_64
// struct msghdr { ...; struct iovec *msg_iov; size_t msg_iovlen; ... };
// msg_iov is at offset 16 (after msg_name:8 + msg_namelen:4 + pad:4)


/* Read iov[0].iov_base from a userspace struct iovec array pointer */
static __always_inline void *read_iov_base(const void *iov_ptr) {
  void *base = NULL;
  bpf_probe_read_user(&base, sizeof(base), iov_ptr);
  return base;
}

/* Read iov[0].iov_len from a userspace struct iovec array pointer */
static __always_inline u64 read_iov_len(const void *iov_ptr) {
  u64 len = 0;
  bpf_probe_read_user(&len, sizeof(len), (const void *)((u64)iov_ptr + 8));
  return len;
}

/* Read msg_iov pointer from a userspace struct msghdr */
static __always_inline void *read_msghdr_iov(const void *msg_ptr) {
  void *iov = NULL;
  /* msg_iov is at offset 16 in struct msghdr on x86_64 */
  bpf_probe_read_user(&iov, sizeof(iov), (const void *)((u64)msg_ptr + 16));
  return iov;
}

/* 
 * Common egress helper — used by write, writev, sendto, sendmsg
 *
 * All egress handlers resolve FD, read payload from user buffer, and emit.
 *  */
static __always_inline int egress_submit(u32 fd, const void *buf, u32 count) {
  if (!buf || count == 0)
    return 0;

  u64 sock_ptr = resolve_fd_to_sock_ptr(fd);
  if (sock_ptr == 0)
    return 0;

  struct conn_info *ci = bpf_map_lookup_elem(&connections, &sock_ptr);
  if (ci && ci->is_ssl)
    return 0;

  u32 zero = 0;
  struct data_event *e = bpf_map_lookup_elem(&event_scratch, &zero);
  if (!e)
    return 0;

  u32 to_copy = count;
  if (to_copy > MAX_DATA_SIZE)
    to_copy = MAX_DATA_SIZE;

  e->flags = 0;
  if (bpf_probe_read_user(e->payload, to_copy & (MAX_DATA_SIZE - 1), buf) < 0)
    return 0;
  e->data_len = to_copy;

  if (count > MAX_DATA_SIZE)
    e->flags |= FLAG_TRUNCATED;

  return emit_data_event(sock_ptr, DIR_EGRESS);
}

/* 
 * Common ingress entry helper — used by read, readv, recvfrom, recvmsg
 *
 * Saves {fd, buf} to active_data_args for the return probe to consume.
 *  */
static __always_inline int ingress_entry(u32 fd, const void *buf) {
  if (!buf)
    return 0;

  u64 sock_ptr = resolve_fd_to_sock_ptr(fd);
  if (sock_ptr == 0)
    return 0;

  u64 pid_tgid = bpf_get_current_pid_tgid();
  struct data_args args = {
      .fd = fd,
      .buf = (u64)buf,
  };
  bpf_map_update_elem(&active_data_args, &pid_tgid, &args, BPF_ANY);
  return 0;
}

static __always_inline int ingress_return(struct pt_regs *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();

  struct data_args *args = bpf_map_lookup_elem(&active_data_args, &pid_tgid);
  if (!args)
    return 0;

  u32 fd = args->fd;
  void *buf = (void *)args->buf;
  bpf_map_delete_elem(&active_data_args, &pid_tgid);

  int ret = (int)PT_REGS_RC(ctx);
  if (ret <= 0 || !buf)
    return 0;

  u64 sock_ptr = resolve_fd_to_sock_ptr(fd);
  if (sock_ptr == 0)
    return 0;

  struct conn_info *ci = bpf_map_lookup_elem(&connections, &sock_ptr);
  if (ci && ci->is_ssl)
    return 0;

  u32 bytes_read = (u32)ret;
  if (bytes_read > MAX_DATA_SIZE)
    bytes_read = MAX_DATA_SIZE;

  u32 zero = 0;
  struct data_event *e = bpf_map_lookup_elem(&event_scratch, &zero);
  if (!e)
    return 0;

  e->flags = 0;
  if (bpf_probe_read_user(e->payload, bytes_read & (MAX_DATA_SIZE - 1),
                          buf) < 0)
    return 0;
  e->data_len = bytes_read;

  if ((u32)ret > MAX_DATA_SIZE)
    e->flags |= FLAG_TRUNCATED;

  return emit_data_event(sock_ptr, DIR_INGRESS);
}

static __always_inline int handle_sys_write_entry(struct pt_regs *ctx) {
  struct pt_regs *regs = get_syscall_regs(ctx);
  if (!regs)
    return 0;
  u32 fd = (u32)syscall_arg1(regs);
  const void *buf = (const void *)syscall_arg2(regs);
  u32 count = (u32)syscall_arg3(regs);
  return egress_submit(fd, buf, count);
}

static __always_inline int handle_sys_sendto_entry(struct pt_regs *ctx) {
  struct pt_regs *regs = get_syscall_regs(ctx);
  if (!regs)
    return 0;
  u32 fd = (u32)syscall_arg1(regs);
  const void *buf = (const void *)syscall_arg2(regs);
  u32 count = (u32)syscall_arg3(regs);
  return egress_submit(fd, buf, count);
}

// Reads from iov[0].iov_base — the first vector typically contains
// HTTP headers, which is all we need for protocol detection.
static __always_inline int handle_sys_writev_entry(struct pt_regs *ctx) {
  struct pt_regs *regs = get_syscall_regs(ctx);
  if (!regs)
    return 0;
  u32 fd = (u32)syscall_arg1(regs);
  const void *iov_ptr = (const void *)syscall_arg2(regs);
  if (!iov_ptr)
    return 0;

  void *buf = read_iov_base(iov_ptr);
  u32 len = (u32)read_iov_len(iov_ptr);
  return egress_submit(fd, buf, len);
}

// Follows msghdr → msg_iov → iov[0].iov_base to find the payload.
static __always_inline int handle_sys_sendmsg_entry(struct pt_regs *ctx) {
  struct pt_regs *regs = get_syscall_regs(ctx);
  if (!regs)
    return 0;
  u32 fd = (u32)syscall_arg1(regs);
  const void *msg_ptr = (const void *)syscall_arg2(regs);
  if (!msg_ptr)
    return 0;

  void *iov_ptr = read_msghdr_iov(msg_ptr);
  if (!iov_ptr)
    return 0;

  void *buf = read_iov_base(iov_ptr);
  u32 len = (u32)read_iov_len(iov_ptr);
  return egress_submit(fd, buf, len);
}

static __always_inline int handle_sys_read_entry(struct pt_regs *ctx) {
  struct pt_regs *regs = get_syscall_regs(ctx);
  if (!regs)
    return 0;
  u32 fd = (u32)syscall_arg1(regs);
  const void *buf = (const void *)syscall_arg2(regs);
  return ingress_entry(fd, buf);
}

static __always_inline int handle_sys_read_return(struct pt_regs *ctx) {
  return ingress_return(ctx);
}

static __always_inline int handle_sys_recvfrom_entry(struct pt_regs *ctx) {
  struct pt_regs *regs = get_syscall_regs(ctx);
  if (!regs)
    return 0;
  u32 fd = (u32)syscall_arg1(regs);

  /* Check MSG_PEEK: don't capture peeked reads */
  int flags = (int)syscall_arg4(regs);
  if (flags & MSG_PEEK)
    return 0;

  const void *buf = (const void *)syscall_arg2(regs);
  return ingress_entry(fd, buf);
}

static __always_inline int handle_sys_recvfrom_return(struct pt_regs *ctx) {
  return ingress_return(ctx);
}

static __always_inline int handle_sys_readv_entry(struct pt_regs *ctx) {
  struct pt_regs *regs = get_syscall_regs(ctx);
  if (!regs)
    return 0;
  u32 fd = (u32)syscall_arg1(regs);
  const void *iov_ptr = (const void *)syscall_arg2(regs);
  if (!iov_ptr)
    return 0;

  void *buf = read_iov_base(iov_ptr);
  return ingress_entry(fd, buf);
}

static __always_inline int handle_sys_readv_return(struct pt_regs *ctx) {
  return ingress_return(ctx);
}

static __always_inline int handle_sys_recvmsg_entry(struct pt_regs *ctx) {
  struct pt_regs *regs = get_syscall_regs(ctx);
  if (!regs)
    return 0;
  u32 fd = (u32)syscall_arg1(regs);

  /* Check MSG_PEEK */
  int flags = (int)syscall_arg3(regs);
  if (flags & MSG_PEEK)
    return 0;

  const void *msg_ptr = (const void *)syscall_arg2(regs);
  if (!msg_ptr)
    return 0;

  void *iov_ptr = read_msghdr_iov(msg_ptr);
  if (!iov_ptr)
    return 0;

  void *buf = read_iov_base(iov_ptr);
  return ingress_entry(fd, buf);
}

static __always_inline int handle_sys_recvmsg_return(struct pt_regs *ctx) {
  return ingress_return(ctx);
}
