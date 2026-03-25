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

static __always_inline int
ks_add_address_to_chunk(struct pt_regs *ctx, struct ks_tls_chunk *chunk,
                        __u64 id, __u32 fd, struct ks_ssl_info *info) {
  __u32 pid = id >> 32;
  __u64 key = (__u64)pid << 32 | fd;

  ks_conn_flags *flags = bpf_map_lookup_elem(&ks_connection_context, &key);
  if (flags == NULL) {
    /* No connect/accept seen — can't determine client/server side.
     * Unlike kubeshark we continue anyway to avoid dropping data. */
    return 1;
  }

  chunk->flags |= (*flags & TLS_FLAGS_IS_CLIENT_BIT);

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

static __always_inline int
ks_send_chunk_part(struct pt_regs *ctx, uintptr_t buffer, __u64 id,
                   struct ks_tls_chunk *chunk, int start, int end) {
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

  return bpf_perf_event_output(ctx, &ks_chunks_buffer, BPF_F_CURRENT_CPU,
                               chunk, sizeof(struct ks_tls_chunk));
}

static __always_inline int
ks_send_chunk(struct pt_regs *ctx, uintptr_t buffer, __u64 id,
              struct ks_tls_chunk *chunk) {
  int ret = 0;
#pragma unroll
  for (int i = 0; i < TLS_MAX_CHUNKS_PER_OP; i++) {
    if (chunk->len <= (TLS_CHUNK_SIZE * i))
      break;
    int err = ks_send_chunk_part(ctx, buffer, id, chunk,
                                 TLS_CHUNK_SIZE * i, chunk->len);
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
static __always_inline void
ks_output_ssl_chunk(struct pt_regs *ctx, struct ks_ssl_info *info,
                    int count_bytes, __u64 id, __u32 flags) {
  if (count_bytes > (TLS_CHUNK_SIZE * TLS_MAX_CHUNKS_PER_OP))
    return;

  struct ks_tls_chunk *chunk;
  int zero = 0;

  chunk = bpf_map_lookup_elem(&ks_heap, &zero);
  if (!chunk)
    return;

  chunk->flags = flags;
  chunk->timestamp = bpf_ktime_get_ns();
  chunk->pid = id >> 32;
  chunk->tgid = id;
  chunk->len = count_bytes;
  chunk->fd = info->fd;

  ks_add_address_to_chunk(ctx, chunk, id, chunk->fd, info);

  ks_send_chunk(ctx, info->buffer, id, chunk);
}
