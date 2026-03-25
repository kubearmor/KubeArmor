/* SPDX-License-Identifier: GPL-2.0
 * Copyright 2026 Authors of KubeArmor
 *
 * ks_tcp_kprobes.h — TCP kprobes for SSL address resolution.
 * Ported from kubeshark/tracer bpf/tcp_kprobes.c (GPL-3.0)
 *
 * When SSL_write calls write() which calls tcp_sendmsg(), this kprobe
 * fires and reads the source/destination address from struct sock.
 * The address info is written into the ssl_info entry (OpenSSL) or
 * the go_user_kernel context map (Go TLS).
 */

#pragma once

#include "common/macros.h"
#include "common/maps.h"
#include "common/structs.h"

#ifndef AF_INET
#define AF_INET  2
#endif
#ifndef AF_INET6
#define AF_INET6 10
#endif

/* Read source/dest IP + port from struct sock (kprobe param 1). */
static __always_inline int
ks_tcp_get_address_pair(struct pt_regs *ctx, __u64 id,
                        struct ks_address_info *addr) {
  struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
  __u16 family_short;
  long err;

  err = bpf_probe_read_kernel(&family_short, sizeof(family_short),
                              &sk->__sk_common.skc_family);
  if (err != 0)
    return -1;

  addr->family = (__be32)family_short;

  if (addr->family == AF_INET) {
    bpf_probe_read_kernel(&addr->saddr4, sizeof(addr->saddr4),
                          &sk->__sk_common.skc_rcv_saddr);
    bpf_probe_read_kernel(&addr->daddr4, sizeof(addr->daddr4),
                          &sk->__sk_common.skc_daddr);
  } else if (addr->family == AF_INET6) {
    bpf_probe_read_kernel(addr->saddr6, sizeof(addr->saddr6),
                          &sk->__sk_common.skc_v6_rcv_saddr);
    bpf_probe_read_kernel(addr->daddr6, sizeof(addr->daddr6),
                          &sk->__sk_common.skc_v6_daddr);
  } else {
    return -1;
  }

  bpf_probe_read_kernel(&addr->dport, sizeof(addr->dport),
                        &sk->__sk_common.skc_dport);

  __u16 sport_h;
  bpf_probe_read_kernel(&sport_h, sizeof(sport_h),
                        &sk->__sk_common.skc_num);
  addr->sport = bpf_htons(sport_h);

  return 0;
}

/* Forward address info to Go user-kernel context map. */
static __always_inline void
ks_tcp_forward_go(struct pt_regs *ctx, __u64 id, __u32 fd,
                  struct ks_address_info addr, void *map_fd) {
  __u32 pid = id >> 32;
  __u64 key = (__u64)pid << 32 | fd;
  bpf_map_update_elem(map_fd, &key, &addr, BPF_ANY);
}

/* Forward address info directly into OpenSSL ssl_info entry. */
static __always_inline void
ks_tcp_forward_openssl(struct pt_regs *ctx, __u64 id,
                       struct ks_ssl_info *info_ptr,
                       struct ks_address_info addr) {
  info_ptr->address_info.family = addr.family;

  if (addr.family == AF_INET) {
    info_ptr->address_info.saddr4 = addr.saddr4;
    info_ptr->address_info.daddr4 = addr.daddr4;
  } else if (addr.family == AF_INET6) {
    __builtin_memcpy(info_ptr->address_info.saddr6, addr.saddr6, 16);
    __builtin_memcpy(info_ptr->address_info.daddr6, addr.daddr6, 16);
  }

  info_ptr->address_info.dport = addr.dport;
  info_ptr->address_info.sport = addr.sport;
}

/* Shared kprobe handler for tcp_sendmsg / tcp_recvmsg. */
static __always_inline void
ks_tcp_kprobe(struct pt_regs *ctx, void *map_fd_openssl,
              void *map_fd_go_kernel, void *map_fd_go_user_kernel) {
  __u64 id = bpf_get_current_pid_tgid();

  struct ks_address_info addr = {};
  if (ks_tcp_get_address_pair(ctx, id, &addr) != 0)
    return;

  /* Try OpenSSL context first. */
  struct ks_ssl_info *info_ptr = bpf_map_lookup_elem(map_fd_openssl, &id);
  if (info_ptr != NULL) {
    ks_tcp_forward_openssl(ctx, id, info_ptr, addr);
    return;
  }

  /* Try Go kernel context. */
  __u32 *fd_ptr = bpf_map_lookup_elem(map_fd_go_kernel, &id);
  if (fd_ptr != NULL)
    ks_tcp_forward_go(ctx, id, *fd_ptr, addr, map_fd_go_user_kernel);
}

/* ---- SEC entries ---- */

SEC("kprobe/tcp_sendmsg")
int ks_kprobe_tcp_sendmsg(struct pt_regs *ctx) {
  ks_tcp_kprobe(ctx, &ks_openssl_write_context,
                &ks_go_kernel_write_context,
                &ks_go_user_kernel_write_context);
  return 0;
}

SEC("kprobe/tcp_recvmsg")
int ks_kprobe_tcp_recvmsg(struct pt_regs *ctx) {
  ks_tcp_kprobe(ctx, &ks_openssl_read_context,
                &ks_go_kernel_read_context,
                &ks_go_user_kernel_read_context);
  return 0;
}
