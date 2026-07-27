/* SPDX-License-Identifier: GPL-2.0
 * Copyright 2026 Authors of KubeArmor
 *
 * ks_ssl_common.h — Common helpers for kubeshark-style SSL capture.
 * Ported from kubeshark/tracer bpf/common.c (GPL-3.0)
 *
 * Provides:
 *   - new_ssl_info() / lookup_ssl_info()  — create/reuse ssl_info with TTL
 *   - output_ssl_chunk()                  — chunk + emit via perf buffer
 */

#pragma once

#include "common/macros.h"
#include "common/maps.h"
#include "common/structs.h"
#include "filter_helpers.h"

/* =========================================================================
 * Core SSL / Go TLS maps (Kubeshark-style — "ks_" prefix)
 * ========================================================================= */

#define KS_MAX_ENTRIES_LRU_HASH (1 << 14) /* 16384 */

/* OpenSSL per-operation context: pid_tgid → ks_ssl_info. */
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, KS_MAX_ENTRIES_LRU_HASH);
  __type(key, __u64);
  __type(value, struct ks_ssl_info);
} ks_openssl_write_context SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, KS_MAX_ENTRIES_LRU_HASH);
  __type(key, __u64);
  __type(value, struct ks_ssl_info);
} ks_openssl_read_context SEC(".maps");

/* Go crypto/tls per-operation context: (pid<<32|goroutine_id) → ks_ssl_info */
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, KS_MAX_ENTRIES_LRU_HASH);
  __type(key, __u64);
  __type(value, struct ks_ssl_info);
} ks_go_write_context SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, KS_MAX_ENTRIES_LRU_HASH);
  __type(key, __u64);
  __type(value, struct ks_ssl_info);
} ks_go_read_context SEC(".maps");

/* Go kernel-side FD capture: pid_tgid → fd (filled by sys_enter_write tracepoint) */
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, KS_MAX_ENTRIES_LRU_HASH);
  __type(key, __u64);
  __type(value, __u32);
} ks_go_kernel_write_context SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, KS_MAX_ENTRIES_LRU_HASH);
  __type(key, __u64);
  __type(value, __u32);
} ks_go_kernel_read_context SEC(".maps");

/* Go user-kernel address bridge: (pid<<32|fd) → ks_address_info.
 * Filled by tcp_kprobes from struct sock; consumed by Go TLS return probes. */
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, KS_MAX_ENTRIES_LRU_HASH);
  __type(key, __u64);
  __type(value, struct ks_address_info);
} ks_go_user_kernel_write_context SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, KS_MAX_ENTRIES_LRU_HASH);
  __type(key, __u64);
  __type(value, struct ks_address_info);
} ks_go_user_kernel_read_context SEC(".maps");

/* Connection context: (pid<<32|fd) → ks_conn_flags (client/server bit).
 * Filled by connect/accept tracepoints. */
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, KS_MAX_ENTRIES_LRU_HASH);
  __type(key, __u64);
  __type(value, ks_conn_flags);
} ks_connection_context SEC(".maps");

/* Persistent per-FD address cache: (pid<<32|fd) → ks_address_info.
 *
 * Problem: on keep-alive HTTPS connections, subsequent SSL_read calls
 * serve data from OpenSSL's internal TLS record buffer — recv() is NOT
 * called, so tcp_recvmsg never fires and address_info stays family=0.
 * This map fixes that by caching the peer address the FIRST time
 * tcp_recvmsg fires for a (pid,fd) pair. All subsequent SSL operations
 * on the same FD look up this cache in the SSL entry probe so the
 * address is always available regardless of whether tcp_recvmsg fired.
 */
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, KS_MAX_ENTRIES_LRU_HASH);
  __type(key, __u64);            /* (pid << 32) | fd */
  __type(value, struct ks_address_info);
} ks_openssl_conn_addr SEC(".maps");

/* Per-CPU scratch for TLS chunk assembly. */
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, int);
  __type(value, struct ks_tls_chunk);
} ks_heap SEC(".maps");

/* Perf buffer for TLS chunks: BPF → Go TlsPoller. */
struct {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
  __uint(max_entries, 1024);
  __type(key, int);
  __type(value, __u32);
} ks_chunks_buffer SEC(".maps");

/* Per-thread last-socket-FD cache (memory BIO fallback for Node.js). */
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 8192);
  __type(key, __u64);
  __type(value, __u32);
} ks_pid_last_socket_fd SEC(".maps");

/* Per-process last-socket-FD cache (Java/Netty useTasks=true fallback). */
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 4096);
  __type(key, __u32);
  __type(value, __u32);
} ks_tgid_last_socket_fd SEC(".maps");


/* ks_go_tls_symaddrs — per-TGID Go TLS struct layout offsets.
 * Populated by userspace scanner (goprobe.ScanBinary) with values
 * derived from DWARF debug info or known Go stdlib defaults:
 *   conn_data_offset:   offset of net.Conn interface data pointer within
 *                       *tls.Conn. tls.Conn.conn is at +0; data ptr is
 *                       second word of the iface → +8.
 *   netfd_sysfd_offset: offset of poll.FD.Sysfd within *netFD.
 *                       netFD.pfd is at +0; pfd.Sysfd follows a 16-byte
 *                       fdMutex → +16 (0x10).
 * Written into ks_go_tls_fd_offsets[tgid]. BPF reads them in
 * go_tls_get_fd() instead of hardcoded constants; falls back to
 * standard defaults when no entry exists for the current TGID. */
struct ks_go_tls_symaddrs {
  __u64 conn_data_offset;    /* default  8 — tls.Conn.conn data ptr at +8  */
  __u64 netfd_sysfd_offset;  /* default 16 — netFD.pfd.Sysfd at +0x10     */
};

/* Per-TGID OpenSSL/BoringSSL struct field offsets. */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 4096);
  __type(key, __u32);
  __type(value, struct ssl_symaddrs);
} ssl_symaddrs SEC(".maps");

/* Per-TGID Go TLS struct layout offsets.
 * Allows go_tls_get_fd() to use binary-specific offsets instead of
 * hardcoded defaults. Written by userspace when a Go binary is probed.
 * If no entry exists for the current TGID, BPF falls back to defaults. */
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 4096);
  __type(key, __u32);
  __type(value, struct ks_go_tls_symaddrs);
} ks_go_tls_fd_offsets SEC(".maps");




/* ---- Helpers ---- */

static __always_inline struct ks_ssl_info ks_new_ssl_info(void) {
  struct ks_ssl_info info = {
      .fd = ks_invalid_fd,
      .created_at_nano = bpf_ktime_get_ns(),
  };
  return info;
}

/*
 * lookup_ssl_info — Reuse existing ssl_info if it's fresh, else create new.
 * This is critical for the double-read pattern where SSL_pending then
 * SSL_read are called — the first call captures the FD,
 * and the second call needs to reuse it.
 */
static __always_inline struct ks_ssl_info
ks_lookup_ssl_info(struct pt_regs *ctx, void *map_fd, __u64 pid_tgid) {
  struct ks_ssl_info *info_ptr = bpf_map_lookup_elem(map_fd, &pid_tgid);
  struct ks_ssl_info info = ks_new_ssl_info();

  if (info_ptr != NULL) {
    long err = bpf_probe_read(&info, sizeof(struct ks_ssl_info), info_ptr);
    if (err != 0)
      return ks_new_ssl_info();

    /* Discard stale entries — the FD may have been reused. */
    if ((bpf_ktime_get_ns() - info.created_at_nano) > SSL_INFO_MAX_TTL_NANO) {
      info.fd = ks_invalid_fd;
      info.created_at_nano = bpf_ktime_get_ns();
    }
  }

  return info;
}

/* ---- Chunk assembly and emission ---- */

static __always_inline int ks_add_address_to_chunk(struct pt_regs *ctx,
                                                   struct ks_tls_chunk *chunk,
                                                   __u64 id, __u32 fd,
                                                   struct ks_ssl_info *info) {
  __u32 pid = id >> 32;
  __u64 key = (__u64)pid << 32 | fd;

  ks_conn_flags *flags = bpf_map_lookup_elem(&ks_connection_context, &key);
  if (flags != NULL) {
    chunk->flags |= (*flags & TLS_FLAGS_IS_CLIENT_BIT);
  }
  /* If no connect/accept was seen, we still copy address info below.
   * The client/server flag won't be set, but the addresses from
   * the user_kernel map (populated by tcp_sendmsg/tcp_recvmsg) are
   * still valid and needed for event correlation. */

  if (info->address_info.family == AF_INET) {
    chunk->address_info.family = AF_INET;
    chunk->address_info.saddr4 = info->address_info.saddr4;
    chunk->address_info.daddr4 = info->address_info.daddr4;
  } else if (info->address_info.family == AF_INET6) {
    chunk->address_info.family = AF_INET6;
    __builtin_memcpy(chunk->address_info.saddr6, info->address_info.saddr6, 16);
    __builtin_memcpy(chunk->address_info.daddr6, info->address_info.daddr6, 16);
  } else {
    chunk->address_info.family = 0; /* AF_UNSPEC */
  }

  chunk->address_info.sport = info->address_info.sport;
  chunk->address_info.dport = info->address_info.dport;

  return 1;
}

static __always_inline int ks_send_chunk_part(struct pt_regs *ctx,
                                              uintptr_t buffer, __u64 id,
                                              struct ks_tls_chunk *chunk,
                                              int start, int end) {
  int recorded = end - start;
  if (recorded <= 0)
    return 1;

  if (recorded > (int)sizeof(chunk->data))
    recorded = sizeof(chunk->data);

  chunk->recorded = recorded;
  chunk->start = start;

  /* Verifier-happy trick: branch on exact size for bounded probe_read. */
  long err = 0;
  if (chunk->recorded == sizeof(chunk->data)) {
    err = bpf_probe_read(chunk->data, sizeof(chunk->data),
                         (void *)(buffer + start));
  } else {
    int masked = recorded & (sizeof(chunk->data) - 1); /* N^2 mask */
    err = bpf_probe_read(chunk->data, masked, (void *)(buffer + start));
  }

  if (err != 0)
    return 2;

  return bpf_perf_event_output(ctx, &ks_chunks_buffer, BPF_F_CURRENT_CPU, chunk,
                               sizeof(struct ks_tls_chunk));
}

static __always_inline int ks_send_chunk(struct pt_regs *ctx, uintptr_t buffer,
                                         __u64 id, struct ks_tls_chunk *chunk) {
  int ret = 0;
#pragma unroll
  for (int i = 0; i < TLS_MAX_CHUNKS_PER_OP; i++) {
    if (chunk->len <= (TLS_CHUNK_SIZE * i))
      break;
    int err = ks_send_chunk_part(ctx, buffer, id, chunk, TLS_CHUNK_SIZE * i,
                                 chunk->len);
    if (err && ret == 0)
      ret = err;
  }
  return ret;
}

/*
 * output_ssl_chunk — The main emit function.
 * Allocates from per-CPU heap, fills metadata, copies data in chunks,
 * sends via perf buffer.
 */
static __always_inline void ks_output_ssl_chunk(struct pt_regs *ctx,
                                                struct ks_ssl_info *info,
                                                int count_bytes, __u64 id,
                                                __u32 flags) {

  // Namespace filter: drop SSL chunks from filtered cgroups.
  if (is_ns_filtered()) {
    return;
  }

  if (count_bytes > (TLS_CHUNK_SIZE * TLS_MAX_CHUNKS_PER_OP))
    return;

  struct ks_tls_chunk *chunk;
  int zero = 0;

  chunk = bpf_map_lookup_elem(&ks_heap, &zero);
  if (!chunk)
    return;

  chunk->flags = flags;
  chunk->timestamp = bpf_ktime_get_ns();
  /* CRITICAL: populate cgroup_id so the Go side can attribute this chunk
   * to the correct K8s namespace. Without this, all TLS chunks arrive
   * with CgroupID=0, making namespace-based correlation impossible. */
  chunk->cgroup_id = (__u32)bpf_get_current_cgroup_id();
  chunk->pid = id >> 32;
  chunk->tgid = id;
  chunk->len = count_bytes;
  chunk->fd = info->fd;

  ks_add_address_to_chunk(ctx, chunk, id, chunk->fd, info);

  /* NOTE: We intentionally do NOT drop chunks where family==0 (address
   * resolution missed this connection). Instead, we send all chunks to
   * userspace so the /proc socket resolver can fill in missing IPs.
   *
   * Rationale: tcp_sendmsg/tcp_recvmsg kprobes fire asynchronously and
   * may not have populated the address map before the first TLS chunk
   * arrives. Dropping here causes permanent data loss for connections
   * established before probe attachment. Userspace resolves IPs via
   * /proc/<pid>/net/tcp (process-namespace scoped) which is accurate
   * and avoids the :0>:0 connKey collision in the dissector. */
  ks_send_chunk(ctx, info->buffer, id, chunk);
}
