/* SPDX-License-Identifier: GPL-2.0
 * Copyright 2026 Authors of KubeArmor
 *
 * go_http2_trace.h — BPF uprobes for Go gRPC header tracing (OTel-style).
 *
 * Uses goroutine-address-based correlation (adapted from OpenTelemetry
 * go_grpc.c) instead of the Pixie-style FD/itable extraction chain.
 * This approach works with stripped binaries and avoids complex BPF
 * bounded loops and interface traversals.
 *
 * Target functions:
 *   - grpc.(*Server).handleStream            (server entry + return)
 *   - grpc/internal/transport.(*http2Server).operateHeaders
 *   - grpc/internal/transport.(*http2Server).WriteStatus
 *   - grpc.(*ClientConn).Invoke              (client entry + return)
 *   - grpc.(*ClientConn).NewStream           (client streaming)
 *   - grpc.(*clientStream).RecvMsg           (client streaming return)
 */

#pragma once

#include "common/macros.h"
#include "go_http2_symaddrs.h"
#include "go_types.h"

/* ---- Constants ---- */
#define GRPC_MAX_PATH_SIZE 160

/* ---- Go register ABI parameter access (Go 1.17+ amd64) ---- */
#define GO_PARAM1(ctx) ((void *)(ctx)->ax)
#define GO_PARAM2(ctx) ((void *)(ctx)->bx)
#define GO_PARAM3(ctx) ((void *)(ctx)->cx)
#define GO_PARAM4(ctx) ((void *)(ctx)->di)
#define GO_PARAM5(ctx) ((void *)(ctx)->si)
#define GO_PARAM6(ctx) ((void *)(ctx)->r8)

/* Goroutine pointer: Go stores the current goroutine in r14 (amd64). */
#define GOROUTINE_PTR(ctx) ((void *)(ctx)->r14)

/* ---- Event type emitted to userspace ---- */
enum go_grpc_event_type {
  GO_GRPC_EVENT_SERVER_REQUEST = 1,
  GO_GRPC_EVENT_CLIENT_REQUEST = 2,
};

/* ---- Goroutine + PID key for BPF map lookups ---- */
struct go_addr_key {
  u64 addr; /* goroutine address */
  u32 pid;
  u32 _pad;
};

/* ---- gRPC request event emitted via ring buffer ---- */
struct go_grpc_request_event {
  u64 start_ns;
  u64 end_ns;
  u32 pid;
  u16 status;
  u8 event_type; /* go_grpc_event_type */
  u8 _pad;
  char path[GRPC_MAX_PATH_SIZE];
};

/* ---- Server-side invocation context (stored between entry/return) ---- */
struct go_grpc_server_invocation {
  u64 start_ns;
  u64 stream_ptr;
};

/* ---- Client-side invocation context ---- */
struct go_grpc_client_invocation {
  u64 start_ns;
  u64 method_ptr;
  u64 method_len;
};

/* ---- BPF Maps ---- */

/* Ring buffer for gRPC events → userspace. */
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 * 1024 * 1024);
} go_http2_events SEC(".maps");

/* Goroutine key → server invocation context. */
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 8192);
  __type(key, struct go_addr_key);
  __type(value, struct go_grpc_server_invocation);
} ongoing_grpc_server_requests SEC(".maps");

/* Goroutine key → client invocation context. */
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 8192);
  __type(key, struct go_addr_key);
  __type(value, struct go_grpc_client_invocation);
} ongoing_grpc_client_requests SEC(".maps");

/* Goroutine key → gRPC status code. */
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 8192);
  __type(key, struct go_addr_key);
  __type(value, u16);
} ongoing_grpc_request_status SEC(".maps");

/* hpack Encoder pointer → stream context (for WriteField correlation).
 * Set by loopyWriter.writeHeader or http2writeResHeaders.writeFrame,
 * read by hpack.(*Encoder).WriteField. */
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 4096);
  __type(key, u64);  /* encoder pointer */
  __type(value, struct go_h2_encoder_ctx);
} go_h2_active_encoder_map SEC(".maps");

/* Ring buffer for single-header events from hpack.WriteField. */
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 512 * 1024);
} go_h2_single_header_events SEC(".maps");

/* Per-CPU scratch for single-header event assembly. */
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, u32);
  __type(value, struct go_h2_single_header_event);
} go_h2_single_header_scratch SEC(".maps");

/* ---- Helpers ---- */

static __always_inline void go_addr_key_init(struct go_addr_key *key,
                                             void *goroutine) {
  key->addr = (u64)goroutine;
  key->pid = (u32)(bpf_get_current_pid_tgid() >> 32);
  key->_pad = 0;
}

/*
 * Read a Go string from a struct at base_ptr + offset.
 * Go strings are {ptr uintptr, len int}, so we read the pointer and length,
 * then read up to max_size bytes from the pointer.
 * Returns 1 on success, 0 on failure.
 */
static __always_inline int read_go_str(void *base_ptr, s64 offset, char *dst,
                                       u64 max_size) {
  void *str_ptr = NULL;
  u64 str_len = 0;

  if (bpf_probe_read_user(&str_ptr, sizeof(str_ptr), base_ptr + offset) != 0)
    return 0;
  if (bpf_probe_read_user(&str_len, sizeof(str_len), base_ptr + offset + 8) !=
      0)
    return 0;
  if (!str_ptr || str_len == 0)
    return 0;

  u64 size = str_len < max_size ? str_len : max_size - 1;
  if (bpf_probe_read_user(dst, size, str_ptr) != 0)
    return 0;

  /* Null-terminate if we didn't fill the buffer */
  if (size < max_size)
    dst[size] = '\0';

  return 1;
}

/*
 * Read a Go string directly from a pointer + length.
 * Used for client-side method reading where we have ptr and len from registers.
 */
static __always_inline int read_go_str_n(void *ptr, u64 len, char *dst,
                                         u64 max_size) {
  if (!ptr || len == 0)
    return 0;

  u64 size = len < max_size ? len : max_size - 1;
  if (bpf_probe_read_user(dst, size, ptr) != 0)
    return 0;

  if (size < max_size)
    dst[size] = '\0';

  return 1;
}

/* ---- Probes ---- */

/*
 * uprobe: grpc.(*Server).handleStream
 * Entry point for server-side gRPC request handling.
 * Captures: goroutine addr, stream pointer, start timestamp.
 *
 * Signature (Go):
 *   func (s *Server) handleStream(t transport.ServerTransport,
 *                                  stream *transport.Stream,
 *                                  trInfo *traceInfo)
 *   Receiver in rax, args in rbx, rcx, rdi.
 *   Stream is 3rd arg (rcx) = GO_PARAM3.
 *   After gRPC v1.60: extra ctx arg shifts stream to GO_PARAM4.
 */
SEC("uprobe/server_handleStream")
int ka_uprobe_server_handleStream(struct pt_regs *ctx) {
  void *goroutine_addr = GOROUTINE_PTR(ctx);
  struct go_addr_key g_key = {};
  go_addr_key_init(&g_key, goroutine_addr);

  void *stream_ptr = GO_PARAM3(ctx);

  struct go_offset_table *ot = get_offsets();
  if (ot) {
    s64 is_v160 = go_offset(ot, GO_OFF_GRPC_V160);
    if (is_v160 == 1) {
      /* v1.60+: extra context arg shifts stream to 4th param */
      stream_ptr = GO_PARAM4(ctx);
    }
  }

  bpf_printk("ka_uprobe: server_handleStream goroutine=%lx stream=%lx",
             goroutine_addr, stream_ptr);

  struct go_grpc_server_invocation invocation = {
      .start_ns = bpf_ktime_get_ns(),
      .stream_ptr = (u64)stream_ptr,
  };

  bpf_map_update_elem(&ongoing_grpc_server_requests, &g_key, &invocation,
                      BPF_ANY);
  return 0;
}

/*
 * uretprobe: grpc.(*Server).handleStream
 * Return point. Reads Stream.Method (= gRPC path) and computes latency.
 */
SEC("uretprobe/server_handleStream")
int ka_uretprobe_server_handleStream(struct pt_regs *ctx) {
  void *goroutine_addr = GOROUTINE_PTR(ctx);
  struct go_addr_key g_key = {};
  go_addr_key_init(&g_key, goroutine_addr);

  struct go_grpc_server_invocation *invocation =
      bpf_map_lookup_elem(&ongoing_grpc_server_requests, &g_key);
  if (!invocation) {
    bpf_printk(
        "ka_uretprobe: server_handleStream no invocation for goroutine=%lx",
        goroutine_addr);
    goto done;
  }

  struct go_offset_table *ot = get_offsets();
  if (!ot) {
    bpf_printk("ka_uretprobe: no offset table");
    goto done;
  }

  s64 method_offset = go_offset(ot, GO_OFF_GRPC_STREAM_METHOD);
  if (method_offset < 0) {
    bpf_printk("ka_uretprobe: invalid method offset");
    goto done;
  }

  /* Read status if available */
  u16 *status_ptr = bpf_map_lookup_elem(&ongoing_grpc_request_status, &g_key);
  u16 status = 0;
  if (status_ptr)
    status = *status_ptr;

  /* Reserve ring buffer space */
  struct go_grpc_request_event *event = bpf_ringbuf_reserve(
      &go_http2_events, sizeof(struct go_grpc_request_event), 0);
  if (!event) {
    bpf_printk("ka_uretprobe: ring buffer full");
    goto done;
  }

  event->start_ns = invocation->start_ns;
  event->end_ns = bpf_ktime_get_ns();
  event->pid = (u32)(bpf_get_current_pid_tgid() >> 32);
  event->status = status;
  event->event_type = GO_GRPC_EVENT_SERVER_REQUEST;
  event->path[0] = '\0';

  /* Read Stream.Method → path */
  void *stream_ptr = (void *)invocation->stream_ptr;
  if (!read_go_str(stream_ptr, method_offset, event->path,
                   GRPC_MAX_PATH_SIZE)) {
    bpf_printk("ka_uretprobe: can't read Stream.Method at offset %d",
               method_offset);
    bpf_ringbuf_discard(event, 0);
    goto done;
  }

  bpf_printk("ka_uretprobe: server path=%s latency=%llu ns", event->path,
             event->end_ns - event->start_ns);

  bpf_ringbuf_submit(event, 0);

done:
  bpf_map_delete_elem(&ongoing_grpc_server_requests, &g_key);
  bpf_map_delete_elem(&ongoing_grpc_request_status, &g_key);
  return 0;
}

/*
 * uprobe: grpc/internal/transport.(*http2Server).WriteStatus
 * Captures the gRPC response status code.
 *
 * Adapted from OTel's transport_writeStatus probe.
 * Signature: func (t *http2Server) WriteStatus(s *Stream, st *status.Status)
 * error In register ABI: receiver=rax, s=rbx, st=rcx
 */
SEC("uprobe/transport_writeStatus")
int ka_uprobe_transport_writeStatus(struct pt_regs *ctx) {
  void *goroutine_addr = GOROUTINE_PTR(ctx);
  struct go_addr_key g_key = {};
  go_addr_key_init(&g_key, goroutine_addr);

  void *status_ptr = GO_PARAM3(ctx);
  if (!status_ptr)
    return 0;

  struct go_offset_table *ot = get_offsets();
  if (!ot)
    return 0;

  s64 s_offset = go_offset(ot, GO_OFF_GRPC_STATUS_S);
  s64 code_offset = go_offset(ot, GO_OFF_GRPC_STATUS_CODE);
  if (s_offset < 0 || code_offset < 0)
    return 0;

  void *s_ptr = NULL;
  bpf_probe_read_user(&s_ptr, sizeof(s_ptr), status_ptr + s_offset);
  if (!s_ptr)
    return 0;

  u16 status_code = 0;
  bpf_probe_read_user(&status_code, sizeof(status_code), s_ptr + code_offset);

  bpf_printk("ka_uprobe: writeStatus goroutine=%lx status=%d", goroutine_addr,
             status_code);

  bpf_map_update_elem(&ongoing_grpc_request_status, &g_key, &status_code,
                      BPF_ANY);
  return 0;
}

/*
 * uprobe: grpc.(*ClientConn).Invoke
 * Entry point for unary client gRPC calls.
 *
 * Signature: func (cc *ClientConn) Invoke(ctx context.Context, method string,
 *                                          args, reply interface{}, opts
 * ...CallOption) error Register ABI: cc=rax, ctx.type=rbx, ctx.data=rcx,
 * method.ptr=rdi, method.len=rsi
 */
SEC("uprobe/ClientConn_Invoke")
int ka_uprobe_ClientConn_Invoke(struct pt_regs *ctx) {
  void *goroutine_addr = GOROUTINE_PTR(ctx);
  struct go_addr_key g_key = {};
  go_addr_key_init(&g_key, goroutine_addr);

  void *method_ptr = GO_PARAM4(ctx);
  void *method_len = GO_PARAM5(ctx);

  bpf_printk(
      "ka_uprobe: ClientConn_Invoke goroutine=%lx method_ptr=%lx len=%lx",
      goroutine_addr, method_ptr, method_len);

  struct go_grpc_client_invocation invocation = {
      .start_ns = bpf_ktime_get_ns(),
      .method_ptr = (u64)method_ptr,
      .method_len = (u64)method_len,
  };

  bpf_map_update_elem(&ongoing_grpc_client_requests, &g_key, &invocation,
                      BPF_ANY);
  return 0;
}

/*
 * uretprobe: grpc.(*ClientConn).Invoke
 * Return from unary client call. Emits event with method and latency.
 */
SEC("uretprobe/ClientConn_Invoke")
int ka_uretprobe_ClientConn_Invoke(struct pt_regs *ctx) {
  void *goroutine_addr = GOROUTINE_PTR(ctx);
  struct go_addr_key g_key = {};
  go_addr_key_init(&g_key, goroutine_addr);

  /* Check for error return */
  void *err = GO_PARAM1(ctx);

  struct go_grpc_client_invocation *invocation =
      bpf_map_lookup_elem(&ongoing_grpc_client_requests, &g_key);
  if (!invocation) {
    goto done;
  }

  struct go_grpc_request_event *event = bpf_ringbuf_reserve(
      &go_http2_events, sizeof(struct go_grpc_request_event), 0);
  if (!event) {
    goto done;
  }

  event->start_ns = invocation->start_ns;
  event->end_ns = bpf_ktime_get_ns();
  event->pid = (u32)(bpf_get_current_pid_tgid() >> 32);
  event->status = err ? 2 : 0; /* Unknown=2 if error, OK=0 otherwise */
  event->event_type = GO_GRPC_EVENT_CLIENT_REQUEST;
  event->path[0] = '\0';

  if (!read_go_str_n((void *)invocation->method_ptr, invocation->method_len,
                     event->path, GRPC_MAX_PATH_SIZE)) {
    bpf_printk("ka_uretprobe: can't read client method");
    bpf_ringbuf_discard(event, 0);
    goto done;
  }

  bpf_printk("ka_uretprobe: client path=%s latency=%llu ns", event->path,
             event->end_ns - event->start_ns);

  bpf_ringbuf_submit(event, 0);

done:
  bpf_map_delete_elem(&ongoing_grpc_client_requests, &g_key);
  return 0;
}

/*
 * uprobe: grpc.(*ClientConn).NewStream
 * Entry for streaming client calls. Same pattern as Invoke but
 * method is at different register positions.
 *
 * Signature: func (cc *ClientConn) NewStream(ctx context.Context,
 *            desc *StreamDesc, method string, opts ...CallOption)
 * (ClientStream, error) Register ABI: cc=rax, ctx.type=rbx, ctx.data=rcx,
 * desc=rdi, method.ptr=rsi, method.len=r8
 */
SEC("uprobe/ClientConn_NewStream")
int ka_uprobe_ClientConn_NewStream(struct pt_regs *ctx) {
  void *goroutine_addr = GOROUTINE_PTR(ctx);
  struct go_addr_key g_key = {};
  go_addr_key_init(&g_key, goroutine_addr);

  void *method_ptr = GO_PARAM5(ctx);
  void *method_len = GO_PARAM6(ctx);

  struct go_grpc_client_invocation invocation = {
      .start_ns = bpf_ktime_get_ns(),
      .method_ptr = (u64)method_ptr,
      .method_len = (u64)method_len,
  };

  bpf_map_update_elem(&ongoing_grpc_client_requests, &g_key, &invocation,
                      BPF_ANY);
  return 0;
}

/*
 * uretprobe: grpc.(*clientStream).RecvMsg
 * Completes a streaming client call. Same emission logic as Invoke return.
 */
SEC("uretprobe/clientStream_RecvMsg")
int ka_uretprobe_clientStream_RecvMsg(struct pt_regs *ctx) {
  void *goroutine_addr = GOROUTINE_PTR(ctx);
  struct go_addr_key g_key = {};
  go_addr_key_init(&g_key, goroutine_addr);

  void *err = GO_PARAM1(ctx);

  struct go_grpc_client_invocation *invocation =
      bpf_map_lookup_elem(&ongoing_grpc_client_requests, &g_key);
  if (!invocation)
    return 0;

  struct go_grpc_request_event *event = bpf_ringbuf_reserve(
      &go_http2_events, sizeof(struct go_grpc_request_event), 0);
  if (!event)
    goto done;

  event->start_ns = invocation->start_ns;
  event->end_ns = bpf_ktime_get_ns();
  event->pid = (u32)(bpf_get_current_pid_tgid() >> 32);
  event->status = err ? 2 : 0;
  event->event_type = GO_GRPC_EVENT_CLIENT_REQUEST;
  event->path[0] = '\0';

  if (!read_go_str_n((void *)invocation->method_ptr, invocation->method_len,
                     event->path, GRPC_MAX_PATH_SIZE)) {
    bpf_ringbuf_discard(event, 0);
    goto done;
  }

  bpf_ringbuf_submit(event, 0);

done:
  bpf_map_delete_elem(&ongoing_grpc_client_requests, &g_key);
  return 0;
}

// operateHeaders helpers

// Default MetaHeadersFrame offsets (golang.org/x/net/http2, stable since Go 1.9)
// These are used as fallbacks if the offset table is unavailable.
//   offset  0: *HeadersFrame  (8 bytes)
//   offset  8: Fields.Ptr     (8 bytes) ← slice data pointer to
//   []hpack.HeaderField offset 16: Fields.Len     (8 bytes) offset 24:
//   Fields.Cap     (8 bytes)
// FrameHeader (embedded at start of HeadersFrame):
//   offset  0: valid  (1)  Type (1)  Flags (1)  pad (1)
//   offset  4: Length (u32)
//   offset  8: StreamID (u32)
// hpack.HeaderField = 32 bytes:
//   offset  0: Name.Ptr  (8)  Name.Len  (8)
//   offset 16: Value.Ptr (8)  Value.Len (8)

// Hardcoded defaults (used when offset table entry is -1 or unavailable).
#define META_FIELDS_PTR_OFF_DEFAULT 8
#define META_FIELDS_LEN_OFF_DEFAULT 16
#define HFRAME_STREAM_ID_OFF_DEFAULT 8
#define HFIELD_SIZE_DEFAULT 32
#define HFIELD_NAME_PTR_OFF 0
#define HFIELD_NAME_LEN_OFF 8
#define HFIELD_VAL_PTR_OFF 16
#define HFIELD_VAL_LEN_OFF 24

static __always_inline int __emit_operate_headers(struct pt_regs *ctx,
                                                  __u8 is_server) {
  void *frame_ptr = GO_PARAM2(ctx);
  if (!frame_ptr)
    return 0;

  /* Resolve configurable offsets from the BPF map, with fallbacks. */
  struct go_offset_table *ot = get_offsets();
  __u64 meta_fields_ptr_off = META_FIELDS_PTR_OFF_DEFAULT;
  __u64 meta_fields_len_off = META_FIELDS_LEN_OFF_DEFAULT;
  __u64 hframe_stream_id_off = HFRAME_STREAM_ID_OFF_DEFAULT;
  __u64 hfield_size = HFIELD_SIZE_DEFAULT;

  if (ot) {
    s64 v;
    v = go_offset(ot, GO_OFF_META_FIELDS_PTR);
    if (v >= 0) meta_fields_ptr_off = (__u64)v;
    v = go_offset(ot, GO_OFF_META_FIELDS_LEN);
    if (v >= 0) meta_fields_len_off = (__u64)v;
    v = go_offset(ot, GO_OFF_HFRAME_STREAM_ID);
    if (v >= 0) hframe_stream_id_off = (__u64)v;
    v = go_offset(ot, GO_OFF_HFIELD_SIZE);
    if (v > 0) hfield_size = (__u64)v;
  }

  __u64 hframe_ptr = 0;
  if (bpf_probe_read_user(&hframe_ptr, sizeof(hframe_ptr), frame_ptr) != 0 ||
      !hframe_ptr)
    return 0;

  __u32 stream_id = 0;
  if (bpf_probe_read_user(&stream_id, sizeof(stream_id),
                          (void *)(hframe_ptr + hframe_stream_id_off)) != 0)
    return 0;

  __u64 fields_ptr = 0, fields_len = 0;
  bpf_probe_read_user(&fields_ptr, sizeof(fields_ptr),
                      (void *)((__u64)frame_ptr + meta_fields_ptr_off));
  bpf_probe_read_user(&fields_len, sizeof(fields_len),
                      (void *)((__u64)frame_ptr + meta_fields_len_off));
  if (!fields_ptr || !fields_len)
    return 0;

  // Use per-CPU scratch — ringbuf-reserved pointers reject zero-assignment.
  __u32 zero = 0;
  struct go_h2_transport_event *ev =
      bpf_map_lookup_elem(&go_h2_transport_scratch, &zero);
  if (!ev)
    return 0;

  // Per-CPU map values support normal assignment; safe to zero here.
  ev->pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
  ev->stream_id = stream_id;
  ev->is_server = is_server;
  ev->pad = 0;
  ev->field_count = 0;

  __u64 n = fields_len < GO_H2_MAX_FIELDS ? fields_len : GO_H2_MAX_FIELDS;

#pragma unroll
  for (int i = 0; i < GO_H2_MAX_FIELDS; i++) {
    // Mark slot empty at the top of every iteration — clears stale data
    // from the previous call on this CPU and handles the continue paths.
    ev->fields[i].name[0] = '\0';
    ev->fields[i].value[0] = '\0';

    if ((__u64)i >= n)
      continue;

    __u64 foff = fields_ptr + (__u64)i * hfield_size;

    __u64 nptr = 0, nlen = 0, vptr = 0, vlen = 0;
    bpf_probe_read_user(&nptr, sizeof(nptr),
                        (void *)(foff + HFIELD_NAME_PTR_OFF));
    bpf_probe_read_user(&nlen, sizeof(nlen),
                        (void *)(foff + HFIELD_NAME_LEN_OFF));
    bpf_probe_read_user(&vptr, sizeof(vptr),
                        (void *)(foff + HFIELD_VAL_PTR_OFF));
    bpf_probe_read_user(&vlen, sizeof(vlen),
                        (void *)(foff + HFIELD_VAL_LEN_OFF));

    if (!nptr || !nlen || nlen >= GO_H2_NAME_SIZE)
      continue; // slot already marked empty above

    bpf_probe_read_user_str(ev->fields[i].name, GO_H2_NAME_SIZE, (void *)nptr);
    if (vptr && vlen > 0 && vlen < GO_H2_VAL_SIZE)
      bpf_probe_read_user_str(ev->fields[i].value, GO_H2_VAL_SIZE,
                               (void *)vptr);

    ev->field_count++;
  }

  if (ev->field_count == 0)
    return 0;

  // bpf_ringbuf_output copies from map pointer into the ringbuf —
  // no MEM_RINGBUF pointer is ever touched directly.
  bpf_ringbuf_output(&go_h2_transport_events, ev, sizeof(*ev), 0);
  return 0;
}

// uprobe:
// google.golang.org/grpc/internal/transport.(*http2Server).operateHeaders
SEC("uprobe/operate_headers_server")
int ka_uprobe_operate_headers_server(struct pt_regs *ctx) {
  return __emit_operate_headers(ctx, 1);
}

// uprobe:
// google.golang.org/grpc/internal/transport.(*http2Client).operateHeaders
SEC("uprobe/operate_headers_client")
int ka_uprobe_operate_headers_client(struct pt_regs *ctx) {
  return __emit_operate_headers(ctx, 0);
}

// uprobe:
// net/http.(*http2serverConn).processHeaders
// Handles incoming HTTP/2 headers in Go's stdlib net/http HTTP/2 server.
// The net/http.http2MetaHeadersFrame is a vendored copy of
// golang.org/x/net/http2.MetaHeadersFrame with identical layout.
SEC("uprobe/net_http_processHeaders")
int ka_uprobe_net_http_processHeaders(struct pt_regs *ctx) {
  return __emit_operate_headers(ctx, 1);
}

// =====================================================================
// hpack Encoder probes — outgoing header capture
// Adapted from Pixie's go_http2_trace.c (proven stable go1.6–go1.24)
// =====================================================================

// Helper: emit a single header field via the ring buffer.
static __always_inline void __emit_single_header(
    __u32 pid, __u32 stream_id, __u8 is_server, __u8 event_type,
    void *name_ptr, u64 name_len, void *value_ptr, u64 value_len) {
  __u32 zero = 0;
  struct go_h2_single_header_event *ev =
      bpf_map_lookup_elem(&go_h2_single_header_scratch, &zero);
  if (!ev)
    return;

  ev->pid = pid;
  ev->stream_id = stream_id;
  ev->is_server = is_server;
  ev->event_type = event_type;
  ev->_pad = 0;

  // Clamp and copy name
  u64 nlen = name_len < HEADER_FIELD_STR_SIZE ? name_len : HEADER_FIELD_STR_SIZE - 1;
  ev->name_len = (__u16)nlen;
  ev->name[0] = '\0';
  if (name_ptr && nlen > 0)
    bpf_probe_read_user_str(ev->name, HEADER_FIELD_STR_SIZE, name_ptr);

  // Clamp and copy value
  u64 vlen = value_len < HEADER_FIELD_STR_SIZE ? value_len : HEADER_FIELD_STR_SIZE - 1;
  ev->value_len = (__u16)vlen;
  ev->value[0] = '\0';
  if (value_ptr && vlen > 0)
    bpf_probe_read_user_str(ev->value, HEADER_FIELD_STR_SIZE, value_ptr);

  bpf_ringbuf_output(&go_h2_single_header_events, ev, sizeof(*ev), 0);
}

// uprobe: google.golang.org/grpc/internal/transport.(*loopyWriter).writeHeader
//
// Captures outgoing gRPC headers. Iterates the []hpack.HeaderField array
// and emits each field. Also sets up the encoder→stream_id correlation
// for the subsequent hpack.WriteField calls.
//
// func (l *loopyWriter) writeHeader(streamID uint32, endStream bool,
//                                   hf []hpack.HeaderField, onWrite func()) error
SEC("uprobe/loopy_writer_write_header")
int ka_uprobe_loopy_writer_write_header(struct pt_regs *ctx) {
  // Go register ABI (go1.17+):
  //   param1 (l *loopyWriter) → AX
  //   param2 (streamID uint32)→ BX
  //   param3 (endStream bool)  → CX (low byte)
  //   param4 (hf.ptr)          → DI
  //   param5 (hf.len)          → SI
  //   param6 (hf.cap)          → R8
  //   param7 (onWrite func())  → R9
  void *loopy_writer_ptr = GO_PARAM1(ctx);
  __u32 stream_id = (__u32)(u64)GO_PARAM2(ctx);
  void *fields_ptr = GO_PARAM4(ctx);
  u64 fields_len = (u64)GO_PARAM5(ctx);

  if (!loopy_writer_ptr || !fields_ptr || fields_len == 0)
    return 0;

  __u32 pid = (__u32)(bpf_get_current_pid_tgid() >> 32);

  // Read configurable offsets
  struct go_offset_table *ot = get_offsets();

  __u64 hfield_size = HFIELD_SIZE_DEFAULT;
  if (ot) {
    s64 v = go_offset(ot, GO_OFF_HFIELD_SIZE);
    if (v > 0) hfield_size = (__u64)v;
  }

  // Emit each header field
  u64 n = fields_len < GO_H2_MAX_FIELDS ? fields_len : GO_H2_MAX_FIELDS;

  #pragma unroll
  for (int i = 0; i < GO_H2_MAX_FIELDS; i++) {
    if ((__u64)i >= n)
      break;

    __u64 foff = (u64)fields_ptr + (__u64)i * hfield_size;

    u64 nptr = 0, nlen = 0, vptr = 0, vlen = 0;
    bpf_probe_read_user(&nptr, sizeof(nptr), (void *)(foff + HFIELD_NAME_PTR_OFF));
    bpf_probe_read_user(&nlen, sizeof(nlen), (void *)(foff + HFIELD_NAME_LEN_OFF));
    bpf_probe_read_user(&vptr, sizeof(vptr), (void *)(foff + HFIELD_VAL_PTR_OFF));
    bpf_probe_read_user(&vlen, sizeof(vlen), (void *)(foff + HFIELD_VAL_LEN_OFF));

    if (!nptr || !nlen)
      continue;

    // event_type=2 → write (outgoing)
    __emit_single_header(pid, stream_id, 0, 2,
                         (void *)nptr, nlen, (void *)vptr, vlen);
  }

  return 0;
}

// uprobe: golang.org/x/net/http2/hpack.(*Encoder).WriteField
//
// Captures individual header fields during HPACK encoding.
// Correlates with the encoder context set by writeFrame/writeHeader.
//
// func (e *Encoder) WriteField(f HeaderField) error
// Go register ABI:
//   param1 (e *Encoder)      → AX
//   param2 (f.Name.ptr)      → BX
//   param3 (f.Name.len)      → CX
//   param4 (f.Value.ptr)     → DI
//   param5 (f.Value.len)     → SI
// Verified stable from go1.6 to go1.24 (from Pixie).
SEC("uprobe/hpack_write_field")
int ka_uprobe_hpack_write_field(struct pt_regs *ctx) {
  u64 encoder_ptr = (u64)GO_PARAM1(ctx);
  if (!encoder_ptr)
    return 0;

  // Look up the encoder context (set by writeFrame or loopyWriter probe)
  struct go_h2_encoder_ctx *enc_ctx =
      bpf_map_lookup_elem(&go_h2_active_encoder_map, &encoder_ptr);
  if (!enc_ctx)
    return 0;

  // Extract name and value Go strings from registers
  void *name_ptr = GO_PARAM2(ctx);
  u64 name_len = (u64)GO_PARAM3(ctx);
  void *value_ptr = GO_PARAM4(ctx);
  u64 value_len = (u64)GO_PARAM5(ctx);

  if (!name_ptr || name_len == 0)
    return 0;

  // event_type=2 → write (outgoing)
  __emit_single_header(enc_ctx->pid, enc_ctx->stream_id, 0, 2,
                       name_ptr, name_len, value_ptr, value_len);
  return 0;
}

// uprobe: net/http.(*http2writeResHeaders).writeFrame
//
// Sets up hpack encoder → stream_id correlation for net/http HTTP/2
// response headers. The hpack Encoder will call WriteField for each
// header, and we'll join them via the encoder pointer.
//
// func (w *http2writeResHeaders) writeFrame(ctx http2writeContext) error
// Go register ABI:
//   param1 (w *http2writeResHeaders) → AX
//   param2 (ctx.type)                 → BX
//   param3 (ctx.ptr → *http2serverConn) → CX
SEC("uprobe/http2_write_res_headers")
int ka_uprobe_http2_write_res_headers(struct pt_regs *ctx) {
  void *w_ptr = GO_PARAM1(ctx);      // *http2writeResHeaders
  void *sc_ptr = GO_PARAM3(ctx);     // *http2serverConn (interface data ptr)

  if (!w_ptr || !sc_ptr)
    return 0;

  struct go_offset_table *ot = get_offsets();
  if (!ot)
    return 0;

  // Read stream_id from http2writeResHeaders
  s64 sid_off = go_offset(ot, GO_OFF_WRITE_RES_STREAM_ID);
  if (sid_off < 0)
    return 0;

  __u32 stream_id = 0;
  if (bpf_probe_read_user(&stream_id, sizeof(stream_id),
                          (void *)((u64)w_ptr + (u64)sid_off)) != 0)
    return 0;

  // Read hpack encoder pointer from http2serverConn
  s64 henc_off = go_offset(ot, GO_OFF_H2SC_HPACK_ENCODER);
  if (henc_off < 0)
    return 0;

  u64 henc_ptr = 0;
  if (bpf_probe_read_user(&henc_ptr, sizeof(henc_ptr),
                          (void *)((u64)sc_ptr + (u64)henc_off)) != 0 || !henc_ptr)
    return 0;

  // Store encoder → {pid, stream_id} for WriteField correlation
  __u32 pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
  struct go_h2_encoder_ctx enc_ctx = {
    .pid = pid,
    .stream_id = stream_id,
  };
  bpf_map_update_elem(&go_h2_active_encoder_map, &henc_ptr, &enc_ctx, BPF_ANY);

  return 0;
}
