/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Authors of KubeArmor
 *
 * conn_tracker.h — Connection lifecycle tracking (open / close) + FD->sock
 *                  resolution.
 * Connection tracking logic that hooks into inet_sock_set_state
 */
#pragma once

#include "common/macros.h"
#include "common/maps.h"
#include "common/structs.h"
#include "protocol_inference.h"

struct inet_sock_set_state_args {
  u64 pad;
  const void *skaddr;
  int oldstate;
  int newstate;
  u16 sport;
  u16 dport;
  u16 family;
  u16 protocol;
  u8 saddr[4];
  u8 daddr[4];
  u8 saddr_v6[16];
  u8 daddr_v6[16];
};

static __attribute__((always_inline)) void update_stats(u8 protocol,
                                                        int filtered) {
  u32 key = 0;
  struct stats *s = bpf_map_lookup_elem(&stats_map, &key);
  if (!s) {
    return;
  }

  __sync_fetch_and_add(&s->total_packets, 1);
  if (filtered) {
    __sync_fetch_and_add(&s->filtered_packets, 1);
    return;
  }

  // Explicit bounds check so the BPF verifier can bound the compiler's
  // jump-table offset to at most PROTO_GRPC (3), preventing an
  // "invalid access to map value, value_size=56 off=256" rejection.
  if (protocol < PROTO_HTTP1 || protocol > PROTO_GRPC) {
    return;
  }

  switch (protocol) {
  case PROTO_HTTP1:
    __sync_fetch_and_add(&s->http1_packets, 1);
    break;
  case PROTO_HTTP2:
    __sync_fetch_and_add(&s->http2_packets, 1);
    break;
  case PROTO_GRPC:
    __sync_fetch_and_add(&s->grpc_packets, 1);
    break;
  }
}

// FD -> sock_ptr resolution
// Returns (u64)sk or 0 on failure.  Requires kernel ≥ 5.8 (BTF).
static __attribute__((always_inline)) u64 get_sock_from_fd(u32 fd) {
  struct task_struct *task = (struct task_struct *)bpf_get_current_task();
  if (!task)
    return 0;

  struct files_struct *files = NULL;
  BPF_CORE_READ_INTO(&files, task, files);
  if (!files) {
    return 0;
  }

  /* files->fdt (current fdtable) */
  struct fdtable *fdt = NULL;
  BPF_CORE_READ_INTO(&fdt, files, fdt);
  if (!fdt) {
    return 0;
  }

  /* fdt->fd is struct file **; index by fd */
  struct file **fd_array = NULL;
  BPF_CORE_READ_INTO(&fd_array, fdt, fd);
  if (!fd_array) {
    return 0;
  }

  struct file *f = NULL;
  bpf_probe_read_kernel(&f, sizeof(f), &fd_array[fd]);
  if (!f) {
    return 0;
  }

  /* file->private_data is (struct socket *) for sockets */
  struct socket *socket = NULL;
  BPF_CORE_READ_INTO(&socket, f, private_data);
  if (!socket) {
    return 0;
  }

  /* socket->sk is the struct sock * we want */
  struct sock *sk = NULL;
  BPF_CORE_READ_INTO(&sk, socket, sk);
  return (u64)sk;
}

/* resolve_fd_to_sock_ptr — fast path: map lookup first, CO-RE fdtable
 * walk as fallback for pre-existing connections.  Returns 0 for
 * non-socket FDs. */
static __attribute__((always_inline)) u64 resolve_fd_to_sock_ptr(u32 fd) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  struct conn_id cid = {
      .tgid = (u32)(pid_tgid >> 32),
      .fd = fd,
  };

  u64 *sp = bpf_map_lookup_elem(&pid_fd_to_sock, &cid);
  if (sp && *sp != 0) {
    return *sp;
  }

  u64 sock_ptr = get_sock_from_fd(fd);
  if (sock_ptr == 0) {
    return 0; /* not a socket (pipe, file, eventfd, etc.) */
  }

  /* Lazily populate both forward and reverse maps */
  bpf_map_update_elem(&pid_fd_to_sock, &cid, &sock_ptr, BPF_NOEXIST);
  bpf_map_update_elem(&sock_to_conn_id, &sock_ptr, &cid, BPF_NOEXIST);

  /* Fallback lazy generation of the connection info from structural socket
   * state. Without this, emit_data_event drops all traffic from pre-existing
   * connections because they never triggered an inet_sock_set_state
   * TCP_ESTABLISHED handler!
   */
  if (!bpf_map_lookup_elem(&connections, &sock_ptr)) {
    struct sock *sk = (struct sock *)sock_ptr;
    u16 family = 0;
    BPF_CORE_READ_INTO(&family, sk, __sk_common.skc_family);

    struct conn_info info = {0};
    if (family == AF_INET) {
      BPF_CORE_READ_INTO(&info.src_ip, sk, __sk_common.skc_rcv_saddr);
      BPF_CORE_READ_INTO(&info.dst_ip, sk, __sk_common.skc_daddr);
    } else if (family == AF_INET6) {
      /* Extract IPv4-mapped IPv6 */
      u8 sv6[16] = {0}, dv6[16] = {0};
      BPF_CORE_READ_INTO(sv6, sk, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);
      BPF_CORE_READ_INTO(dv6, sk, __sk_common.skc_v6_daddr.in6_u.u6_addr8);
      int mapped = 1;
#pragma unroll
      for (int i = 0; i < 10; i++) {
        if (sv6[i] != 0 || dv6[i] != 0) {
          mapped = 0;
          break;
        }
      }
      if (mapped && sv6[10] == 0xff && sv6[11] == 0xff) {
        __builtin_memcpy(&info.src_ip, &sv6[12], 4);
        __builtin_memcpy(&info.dst_ip, &dv6[12], 4);
      } else {
        return sock_ptr;
      }
    } else {
      return sock_ptr; // Unknown family
    }

    u16 dport = 0, sport = 0;
    BPF_CORE_READ_INTO(&dport, sk, __sk_common.skc_dport);
    info.dst_port = bpf_ntohs(dport);
    BPF_CORE_READ_INTO(&sport, sk, __sk_common.skc_num);
    info.src_port = sport;
    info.protocol = PROTO_UNKNOWN;
    bpf_map_update_elem(&connections, &sock_ptr, &info, BPF_NOEXIST);
  }

  return sock_ptr;
}

static __attribute__((always_inline)) int
handle_inet_sock_set_state(struct inet_sock_set_state_args *ctx) {
  if (ctx->family != AF_INET && ctx->family != AF_INET6) {
    return 0;
  }

  u64 sock_ptr = (u64)ctx->skaddr;

  if (ctx->newstate == TCP_ESTABLISHED) {
    struct conn_info info = {0};

    if (ctx->family == AF_INET6) {
      /* Copy v6 addresses to stack — direct ctx->saddr_v6[N] indexing
       * triggers "modified ctx ptr" verifier error for tracepoints. */
      u8 sv6[16], dv6[16];
      bpf_probe_read_kernel(sv6, sizeof(sv6), ctx->saddr_v6);
      bpf_probe_read_kernel(dv6, sizeof(dv6), ctx->daddr_v6);

      /* Accept IPv4-mapped only; pure IPv6 deferred to Task 7. */
      int mapped = 1;
#pragma unroll
      for (int i = 0; i < 10; i++) {
        if (sv6[i] != 0 || dv6[i] != 0) {
          mapped = 0;
          break;
        }
      }
      if (mapped && sv6[10] == 0xff && sv6[11] == 0xff) {
        __builtin_memcpy(&info.src_ip, &sv6[12], 4);
        __builtin_memcpy(&info.dst_ip, &dv6[12], 4);
      } else {
        return 0;
      }
    } else {
      __builtin_memcpy(&info.src_ip, ctx->saddr, 4);
      __builtin_memcpy(&info.dst_ip, ctx->daddr, 4);
    }

    info.src_port = ctx->sport;
    info.dst_port = ctx->dport;
    info.protocol = PROTO_UNKNOWN;
    info.http2_detected = 0;
    info.is_ssl = 0;
    bpf_map_update_elem(&connections, &sock_ptr, &info, BPF_ANY);

    /* populate reverse map.
     * The current pid_tgid owns this connection. */
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct conn_id cid = {
        .tgid = (u32)(pid_tgid >> 32),
        .fd = 0, /* fd not available from tracepoint; will be backfilled */
    };
    bpf_map_update_elem(&sock_to_conn_id, &sock_ptr, &cid, BPF_NOEXIST);
  } else if (ctx->newstate == TCP_CLOSE) {
    bpf_map_delete_elem(&connections, &sock_ptr);
    bpf_map_delete_elem(&connection_filter_cache, &sock_ptr);
    bpf_map_delete_elem(&sock_to_conn_id, &sock_ptr);
  }
  return 0;
}

static __attribute__((always_inline)) int
handle_connect_entry(struct pt_regs *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  // On x86_64 with syscall wrappers, PT_REGS_PARM1 gives the inner
  // pt_regs pointer.
  struct pt_regs *regs = (struct pt_regs *)PT_REGS_PARM1(ctx);
  u64 fd_val = 0;
  bpf_probe_read_kernel(&fd_val, sizeof(fd_val), &regs->di);
  struct connect_args args = {.fd = (u32)fd_val};
  bpf_map_update_elem(&active_connect_args, &pid_tgid, &args, BPF_ANY);
  return 0;
}

static __attribute__((always_inline)) int
handle_connect_return(struct pt_regs *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  struct connect_args *args =
      bpf_map_lookup_elem(&active_connect_args, &pid_tgid);
  if (!args) {
    return 0;
  }
  u32 fd = args->fd;
  bpf_map_delete_elem(&active_connect_args, &pid_tgid);

  long ret = (long)PT_REGS_RC(ctx);
  /* connect() returns 0 on success, or -EINPROGRESS for non-blocking.
   * Both are valid — the connection will complete asynchronously. */
  if (ret < 0 && ret != -115) {
    return 0; // connect() failed
  }

  // Resolve the FD to the actual struct sock * via the kernel fdtable.
  u64 sock_ptr = get_sock_from_fd(fd);
  struct conn_id cid = {.tgid = (u32)(pid_tgid >> 32), .fd = fd};
  bpf_map_update_elem(&pid_fd_to_sock, &cid, &sock_ptr, BPF_ANY);

  if (sock_ptr) {
    bpf_map_update_elem(&sock_to_conn_id, &sock_ptr, &cid, BPF_NOEXIST);
  }
  return 0;
}

static __attribute__((always_inline)) int
handle_accept_return(struct pt_regs *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  bpf_map_delete_elem(&active_accept_args, &pid_tgid);

  long ret_fd = (long)PT_REGS_RC(ctx);
  if (ret_fd < 0)
    return 0;

  u64 sock_ptr = get_sock_from_fd((u32)ret_fd);
  struct conn_id cid = {
      .tgid = (u32)(pid_tgid >> 32),
      .fd = (u32)ret_fd,
  };
  bpf_map_update_elem(&pid_fd_to_sock, &cid, &sock_ptr, BPF_ANY);

  if (sock_ptr) {
    bpf_map_update_elem(&sock_to_conn_id, &sock_ptr, &cid, BPF_NOEXIST);
  }
  return 0;
}

static __attribute__((always_inline)) int
handle_close_entry(struct pt_regs *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();

  struct pt_regs *regs = (struct pt_regs *)PT_REGS_PARM1(ctx);
  u64 fd_val = 0;
  bpf_probe_read_kernel(&fd_val, sizeof(fd_val), &regs->di);
  u32 fd = (u32)fd_val;
  struct conn_id cid = {.tgid = (u32)(pid_tgid >> 32), .fd = fd};

  u64 *sp = bpf_map_lookup_elem(&pid_fd_to_sock, &cid);
  if (sp && *sp) {
    u64 sock_ptr = *sp;
    bpf_map_delete_elem(&connections, &sock_ptr);
    bpf_map_delete_elem(&connection_filter_cache, &sock_ptr);
    bpf_map_delete_elem(&sock_to_conn_id, &sock_ptr);
    bpf_map_delete_elem(&active_data_args, &pid_tgid);
  }
  bpf_map_delete_elem(&pid_fd_to_sock, &cid);
  return 0;
}
