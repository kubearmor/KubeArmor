/* SPDX-License-Identifier: GPL-2.0
 * Copyright 2026 Authors of KubeArmor
 *
 * grpc_c_trace.h — BPF uprobe for gRPC-C :path recovery.
 *
 * Fixes ":path: *" for Python, C++, Ruby, PHP, and C# gRPC services by
 * reading grpc_chttp2_stream.method directly from process memory, entirely
 * bypassing the HPACK dynamic table that causes the "*" fallback.
 *
 * Target function:
 *   grpc_chttp2_maybe_complete_recv_initial_metadata(transport, stream)
 *
 * grpc_slice memory layout on 64-bit (x86_64 and aarch64):
 *   +0x00  void  *refcount   — NULL → inlined data; non-NULL → heap pointer
 *   +0x08  union {
 *              struct { void *bytes; size_t length; }       // heap path
 *              struct { uint8_t length; uint8_t bytes[15]; } // inlined path
 *          }
 *
 * GRPC_SLICE_INLINED_SIZE = sizeof(void*) + sizeof(size_t) - 1 = 15 on LP64.
 * Real service paths (e.g. /hipstershop.CurrencyService/GetSupportedCurrencies
 * = 51 bytes) ALWAYS take the heap path. Both paths are implemented here.
 */
#pragma once
#include "common/macros.h"
#include "common/maps.h"
#include "common/structs.h"
#include <bpf/bpf_helpers.h>

/* grpc_slice field offsets — identical on x86_64 and aarch64 (LP64). */
#define GRPCC_SLICE_REFCOUNT_OFF 0    /* void *refcount                   */
#define GRPCC_SLICE_HEAP_PTR_OFF 8    /* data.refcounted.bytes (void *)   */
#define GRPCC_SLICE_HEAP_LEN_OFF 16   /* data.refcounted.length (size_t)  */
#define GRPCC_SLICE_INLINED_LEN_OFF 8 /* data.inlined.length  (uint8_t)   */
#define GRPCC_SLICE_INLINED_DAT_OFF 9 /* data.inlined.bytes[15]           */
#define GRPCC_SLICE_INLINED_MAX 15    /* GRPC_SLICE_INLINED_SIZE on LP64  */

/* ── Ring buffer: gRPC-C header events → userspace ─────────────────────── */
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 2 * 1024 * 1024); /* 2 MB — matches go_http2_events */
} grpcc_events SEC(".maps");

/* ── Version-specific struct offsets (written once by userspace at startup) */
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, u32);
  __type(value, struct grpcc_symaddrs);
} grpcc_symaddrs_map SEC(".maps");

/* ── Event wire format emitted to userspace ─────────────────────────────── */
struct grpcc_header_event {
  u32 pid;
  u32 fd;
  u32 stream_id;
  u8 _pad;
  u8 method[GRPCC_MAX_METHOD_SIZE]; /* null-terminated, up to 64 bytes   */
};

/* ── Architecture-portable argument access ──────────────────────────────── */
#if defined(__TARGET_ARCH_x86)
/* System V AMD64 ABI: integer args in RDI, RSI, RDX, RCX, R8, R9 */
#define GRPCC_ARG1(ctx) ((void *)(ctx)->di)
#define GRPCC_ARG2(ctx) ((void *)(ctx)->si)
#elif defined(__TARGET_ARCH_arm64)
/* AArch64 ABI: integer args in x0..x7 */
#define GRPCC_ARG1(ctx) ((void *)(u64)PT_REGS_PARM1(ctx))
#define GRPCC_ARG2(ctx) ((void *)(u64)PT_REGS_PARM2(ctx))
#else
#define GRPCC_ARG1(ctx) ((void *)(u64)PT_REGS_PARM1(ctx))
#define GRPCC_ARG2(ctx) ((void *)(u64)PT_REGS_PARM2(ctx))
#endif

/*
 * read_grpc_slice — reads a grpc_slice's string content into dst[0..max_size].
 *
 * Handles BOTH the inlined path (refcount==NULL, length ≤ 15 bytes) and the
 * heap path (refcount!=NULL, {bytes ptr, length} in data.refcounted).
 *
 * Real gRPC service method paths average 35-55 bytes and ALWAYS use the heap
 * path. The inlined path handles short paths only (<16 bytes).
 *
 * Returns bytes written (excluding null terminator), or 0 on failure.
 */
static __always_inline u32 read_grpc_slice(void *slice_ptr, u8 *dst,
                                           u32 max_size) {
  void *refcount = NULL;
  if (bpf_probe_read_user(
          &refcount, sizeof(refcount),
          (void *)((u64)slice_ptr + GRPCC_SLICE_REFCOUNT_OFF)) != 0)
    return 0;

  if (refcount == NULL) {
    /* Inlined path: data sits directly in the slice struct. */
    u8 length = 0;
    if (bpf_probe_read_user(
            &length, 1,
            (void *)((u64)slice_ptr + GRPCC_SLICE_INLINED_LEN_OFF)) != 0)
      return 0;
    if (length == 0 || length > GRPCC_SLICE_INLINED_MAX)
      return 0;
    u32 to_copy = length < max_size ? length : max_size - 1;
    if (bpf_probe_read_user(
            dst, to_copy & (GRPCC_MAX_METHOD_SIZE - 1),
            (void *)((u64)slice_ptr + GRPCC_SLICE_INLINED_DAT_OFF)) != 0)
      return 0;
    dst[to_copy & (GRPCC_MAX_METHOD_SIZE - 1)] = '\0';
    return to_copy;
  }

  /* Heap path: data is at an external pointer. */
  void *bytes_ptr = NULL;
  u64 length = 0;
  if (bpf_probe_read_user(
          &bytes_ptr, sizeof(bytes_ptr),
          (void *)((u64)slice_ptr + GRPCC_SLICE_HEAP_PTR_OFF)) != 0)
    return 0;
  if (bpf_probe_read_user(
          &length, sizeof(length),
          (void *)((u64)slice_ptr + GRPCC_SLICE_HEAP_LEN_OFF)) != 0)
    return 0;
  if (!bytes_ptr || length == 0 || length > 4096)
    return 0;
  u32 to_copy = (u32)length < max_size ? (u32)length : max_size - 1;
  /* Mask to keep the BPF verifier happy with the dynamic size. */
  if (bpf_probe_read_user(dst, to_copy & (GRPCC_MAX_METHOD_SIZE - 1),
                          bytes_ptr) != 0)
    return 0;
  dst[to_copy & (GRPCC_MAX_METHOD_SIZE - 1)] = '\0';
  return to_copy;
}

/*
 * uprobe: grpc_chttp2_maybe_complete_recv_initial_metadata
 *
 * Called exactly once per RPC stream once all HEADERS frames have been
 * assembled. stream->method is fully populated at this point with the
 * ":path" value from the HEADERS block — decoded by gRPC-C itself, not us.
 *
 * Signature:
 *   void grpc_chttp2_maybe_complete_recv_initial_metadata(
 *       grpc_chttp2_transport *t,   ← GRPCC_ARG1
 *       grpc_chttp2_stream    *s)   ← GRPCC_ARG2
 *
 * Struct layout offsets come from the grpcc_symaddrs_map BPF array
 * (index 0) populated by userspace on startup for the detected version.
 */
static __attribute__((always_inline)) int
handle_grpc_c_recv_initial_metadata(struct pt_regs *ctx) {
  void *transport_ptr = GRPCC_ARG1(ctx);
  void *stream_ptr = GRPCC_ARG2(ctx);
  if (!transport_ptr || !stream_ptr)
    return 0;

  u32 zero = 0;
  struct grpcc_symaddrs *addrs =
      bpf_map_lookup_elem(&grpcc_symaddrs_map, &zero);
  if (!addrs || addrs->stream_method_offset < 0 || addrs->stream_id_offset < 0)
    return 0;

  /* Read stream_id (uint32) at stream + stream_id_offset */
  u32 stream_id = 0;
  if (bpf_probe_read_user(
          &stream_id, sizeof(stream_id),
          (void *)((u64)stream_ptr + (u32)addrs->stream_id_offset)) != 0)
    return 0;

  /* Read FD: transport + transport_fd_offset */
  int fd = 0;
  if (bpf_probe_read_user(
          &fd, sizeof(fd),
          (void *)((u64)transport_ptr + (u32)addrs->transport_fd_offset)) != 0)
    return 0;
  if (fd <= 0)
    return 0;

  /* Reserve ring buffer slot before the expensive slice read. */
  struct grpcc_header_event *ev =
      bpf_ringbuf_reserve(&grpcc_events, sizeof(struct grpcc_header_event), 0);
  if (!ev)
    return 0;

  u64 pid_tgid = bpf_get_current_pid_tgid();
  ev->pid = (u32)(pid_tgid >> 32);
  ev->fd = (u32)fd;
  ev->stream_id = stream_id;
  ev->_pad = 0;
  __builtin_memset(ev->method, 0, GRPCC_MAX_METHOD_SIZE);

  /* Read grpc_slice at stream_ptr + stream_method_offset */
  void *slice_ptr =
      (void *)((u64)stream_ptr + (u32)addrs->stream_method_offset);
  u32 n = read_grpc_slice(slice_ptr, ev->method, GRPCC_MAX_METHOD_SIZE);
  if (n == 0) {
    bpf_ringbuf_discard(ev, 0);
    return 0;
  }

  bpf_ringbuf_submit(ev, 0);
  return 0;
}
