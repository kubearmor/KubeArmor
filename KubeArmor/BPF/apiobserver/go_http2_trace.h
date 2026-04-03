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

#include "go_types.h"
#include "go_http2_symaddrs.h"
#include "common/macros.h"

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
  u64 addr;  /* goroutine address */
  u32 pid;
  u32 _pad;
};

/* ---- gRPC request event emitted via ring buffer ---- */
struct go_grpc_request_event {
  u64 start_ns;
  u64 end_ns;
  u32 pid;
  u16 status;
  u8  event_type;  /* go_grpc_event_type */
  u8  _pad;
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

/* Inode → offset table (populated from userspace). */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 4096);
  __type(key, u64);
  __type(value, struct go_offset_table);
} go_offsets_map SEC(".maps");

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

/* ---- Helpers ---- */

static __always_inline void go_addr_key_init(struct go_addr_key *key, void *goroutine) {
  key->addr = (u64)goroutine;
  key->pid = (u32)(bpf_get_current_pid_tgid() >> 32);
  key->_pad = 0;
}

/*
 * Get the offset table for the current process's binary.
 * Uses the inode of the executable as key (same as OTel).
 */
static __always_inline struct go_offset_table *get_offsets(void) {
  struct task_struct *task = (struct task_struct *)bpf_get_current_task();
  u64 ino = BPF_CORE_READ(task, mm, exe_file, f_inode, i_ino);
  return (struct go_offset_table *)bpf_map_lookup_elem(&go_offsets_map, &ino);
}

static __always_inline s64 go_offset(struct go_offset_table *ot, enum go_offset_kind kind) {
  if (!ot || kind >= GO_OFF_MAX)
    return -1;
  return ot->offsets[kind];
}

/*
 * Read a Go string from a struct at base_ptr + offset.
 * Go strings are {ptr uintptr, len int}, so we read the pointer and length,
 * then read up to max_size bytes from the pointer.
 * Returns 1 on success, 0 on failure.
 */
static __always_inline int read_go_str(void *base_ptr, s64 offset,
                                        char *dst, u64 max_size) {
  void *str_ptr = NULL;
  u64 str_len = 0;

  if (bpf_probe_read_user(&str_ptr, sizeof(str_ptr), base_ptr + offset) != 0)
    return 0;
  if (bpf_probe_read_user(&str_len, sizeof(str_len), base_ptr + offset + 8) != 0)
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
static __always_inline int read_go_str_n(void *ptr, u64 len,
                                          char *dst, u64 max_size) {
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

  bpf_printk("ka_uprobe: server_handleStream goroutine=%lx stream=%lx", goroutine_addr, stream_ptr);

  struct go_grpc_server_invocation invocation = {
    .start_ns = bpf_ktime_get_ns(),
    .stream_ptr = (u64)stream_ptr,
  };

  bpf_map_update_elem(&ongoing_grpc_server_requests, &g_key, &invocation, BPF_ANY);
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
    bpf_printk("ka_uretprobe: server_handleStream no invocation for goroutine=%lx", goroutine_addr);
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
  struct go_grpc_request_event *event =
    bpf_ringbuf_reserve(&go_http2_events, sizeof(struct go_grpc_request_event), 0);
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
  if (!read_go_str(stream_ptr, method_offset, event->path, GRPC_MAX_PATH_SIZE)) {
    bpf_printk("ka_uretprobe: can't read Stream.Method at offset %d", method_offset);
    bpf_ringbuf_discard(event, 0);
    goto done;
  }

  bpf_printk("ka_uretprobe: server path=%s latency=%llu ns",
             event->path, event->end_ns - event->start_ns);

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
 * Signature: func (t *http2Server) WriteStatus(s *Stream, st *status.Status) error
 * In register ABI: receiver=rax, s=rbx, st=rcx
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

  bpf_printk("ka_uprobe: writeStatus goroutine=%lx status=%d", goroutine_addr, status_code);

  bpf_map_update_elem(&ongoing_grpc_request_status, &g_key, &status_code, BPF_ANY);
  return 0;
}

/*
 * uprobe: grpc.(*ClientConn).Invoke
 * Entry point for unary client gRPC calls.
 *
 * Signature: func (cc *ClientConn) Invoke(ctx context.Context, method string,
 *                                          args, reply interface{}, opts ...CallOption) error
 * Register ABI: cc=rax, ctx.type=rbx, ctx.data=rcx, method.ptr=rdi, method.len=rsi
 */
SEC("uprobe/ClientConn_Invoke")
int ka_uprobe_ClientConn_Invoke(struct pt_regs *ctx) {
  void *goroutine_addr = GOROUTINE_PTR(ctx);
  struct go_addr_key g_key = {};
  go_addr_key_init(&g_key, goroutine_addr);

  void *method_ptr = GO_PARAM4(ctx);
  void *method_len = GO_PARAM5(ctx);

  bpf_printk("ka_uprobe: ClientConn_Invoke goroutine=%lx method_ptr=%lx len=%lx",
             goroutine_addr, method_ptr, method_len);

  struct go_grpc_client_invocation invocation = {
    .start_ns = bpf_ktime_get_ns(),
    .method_ptr = (u64)method_ptr,
    .method_len = (u64)method_len,
  };

  bpf_map_update_elem(&ongoing_grpc_client_requests, &g_key, &invocation, BPF_ANY);
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

  struct go_grpc_request_event *event =
    bpf_ringbuf_reserve(&go_http2_events, sizeof(struct go_grpc_request_event), 0);
  if (!event) {
    goto done;
  }

  event->start_ns = invocation->start_ns;
  event->end_ns = bpf_ktime_get_ns();
  event->pid = (u32)(bpf_get_current_pid_tgid() >> 32);
  event->status = err ? 2 : 0;  /* Unknown=2 if error, OK=0 otherwise */
  event->event_type = GO_GRPC_EVENT_CLIENT_REQUEST;
  event->path[0] = '\0';

  if (!read_go_str_n((void *)invocation->method_ptr, invocation->method_len,
                      event->path, GRPC_MAX_PATH_SIZE)) {
    bpf_printk("ka_uretprobe: can't read client method");
    bpf_ringbuf_discard(event, 0);
    goto done;
  }

  bpf_printk("ka_uretprobe: client path=%s latency=%llu ns",
             event->path, event->end_ns - event->start_ns);

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
 *            desc *StreamDesc, method string, opts ...CallOption) (ClientStream, error)
 * Register ABI: cc=rax, ctx.type=rbx, ctx.data=rcx, desc=rdi, method.ptr=rsi, method.len=r8
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

  bpf_map_update_elem(&ongoing_grpc_client_requests, &g_key, &invocation, BPF_ANY);
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

  struct go_grpc_request_event *event =
    bpf_ringbuf_reserve(&go_http2_events, sizeof(struct go_grpc_request_event), 0);
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
