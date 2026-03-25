/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Authors of KubeArmor
 *
 * sock_trace.h — Shared emit core for the API Observer.
 * Core data emission logic for the API observer.
 *
 * Design:
 *   All callers (syscall handlers in syscall_trace.h, SSL uprobes in
 *   openssl_trace.h) fill the per-CPU scratch data_event, then call
 *   emit_data_event() which handles protocol detection, filtering,
 *   and ring-buffer submission in one place.
 */

#pragma once

#include "common/macros.h"
#include "common/maps.h"
#include "common/structs.h"
#include "conn_tracker.h"
#include "filter_helpers.h"
#include "protocol_inference.h"

/* emit_data_event — shared emit core.
 *
 * All callers fill e->payload / e->data_len / e->flags into the per-CPU
 * scratch buffer, then call this.  It handles:
 *   • filter cache lookup / population
 *   • protocol detection & sticky update on conn_info
 *   • health-check suppression
 *   • ring buffer reservation and submission
 *   • stats accounting */
static __attribute__((always_inline)) int emit_data_event(u64 sock_ptr,
                                                          u8 direction) {
  u8 *cached = bpf_map_lookup_elem(&connection_filter_cache, &sock_ptr);
  if (cached && *cached == 0) {
    update_stats(PROTO_UNKNOWN, 1);
    return 0;
  }

  // check conn record
  struct conn_info *conn = bpf_map_lookup_elem(&connections, &sock_ptr);
  if (!conn)
    return 0;

  // first packet port filter
  if (!cached) {
    u8 allow =
        (should_trace_port(conn->src_port) && should_trace_port(conn->dst_port))
            ? 1
            : 0;
    bpf_map_update_elem(&connection_filter_cache, &sock_ptr, &allow, BPF_ANY);
    if (!allow) {
      update_stats(PROTO_UNKNOWN, 1);
      return 0;
    }
  }

  // Pull scratch event
  u32 zero = 0;
  struct data_event *e = bpf_map_lookup_elem(&event_scratch, &zero);
  if (!e)
    return 0;

  // protocol detection 
  u8 proto = PROTO_UNKNOWN;
  if (e->data_len >= MIN_HTTP_SIZE) {
    proto = detect_protocol(e->payload, e->data_len, conn);
    if (proto != PROTO_UNKNOWN) {
      conn->protocol = proto;
      bpf_map_update_elem(&connections, &sock_ptr, conn, BPF_EXIST);
    }
  }
  // reuse last classification for continuation frames
  if (proto == PROTO_UNKNOWN) {
    proto = conn->protocol;
  }

  // Drop entirely unclassified traffic (not HTTP1/2/gRPC)
  if (proto == PROTO_UNKNOWN && !conn->http2_detected) {
    return 0;
  }

  // check health checks -- suppress 
  if (direction == DIR_EGRESS && proto == PROTO_HTTP1 && e->data_len >= 16 &&
      is_health_check((const char *)e->payload, e->data_len)) {
    update_stats(proto, 1);
    return 0;
  }

  // stampt event header
  u64 pid_tgid = bpf_get_current_pid_tgid();
  e->timestamp = bpf_ktime_get_ns();
  e->pid = (u32)(pid_tgid >> 32);
  e->tid = (u32)pid_tgid;
  e->src_ip = conn->src_ip;
  e->dst_ip = conn->dst_ip;
  e->src_port = conn->src_port;
  e->dst_port = conn->dst_port;
  e->direction = direction;
  e->protocol = proto;
  e->sock_ptr = sock_ptr;

  // {PID,FD} keying: look up or lazily populate
  struct conn_id *cid = bpf_map_lookup_elem(&sock_to_conn_id, &sock_ptr);
  if (cid) {
    e->fd = cid->fd;
    /* If tgid was set to 0 (tracepoint fallback), backfill with real PID */
    if (cid->tgid == 0) {
      cid->tgid = e->pid;
      bpf_map_update_elem(&sock_to_conn_id, &sock_ptr, cid, BPF_EXIST);
    }
  } else {
    // Create a reverse mapping with fd=0 (PID-only mode).
    e->fd = 0;
    struct conn_id new_cid = {.tgid = e->pid, .fd = 0};
    bpf_map_update_elem(&sock_to_conn_id, &sock_ptr, &new_cid, BPF_NOEXIST);
  }

  // reserve ring buff slot
  struct data_event *slot =
      bpf_ringbuf_reserve(&apiobserver_events, sizeof(struct data_event), 0);
  if (!slot) {
    struct stats *s = bpf_map_lookup_elem(&stats_map, &zero);
    if (s) {
      __sync_fetch_and_add(&s->dropped_packets, 1);
    }
    return 0;
  }

  bpf_probe_read_kernel(slot, sizeof(struct data_event), e);
  bpf_ringbuf_submit(slot, 0);

  update_stats(proto, 0);
  return 0;
}

/* Include syscall-level handlers (they call emit_data_event above) */
#include "syscall_trace.h"
