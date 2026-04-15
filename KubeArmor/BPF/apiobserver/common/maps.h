/* SPDX-License-Identifier: GPL-2.0
 * Copyright 2026 Authors of KubeArmor
 *
 * maps.h — All BPF map definitions for the API Observer.
 *
 */

#pragma once

#include "structs.h"

// Ring buffer: data events -> userspace
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 4 * 1024 * 1024);
} apiobserver_events SEC(".maps");

// Active TCP connections: sock_ptr -> conn_info
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 65536);
  __type(key, u64); // sock_ptr
  __type(value, struct conn_info);
} connections SEC(".maps");

// Per-connection filter cache: sock_ptr -> u8 (0=drop, 1=allow)
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 65536);
  __type(key, u64);
  __type(value, u8);
} connection_filter_cache SEC(".maps");

// Per-CPU scratch: avoids 8 KB data_event on BPF stack
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, u32);
  __type(value, struct data_event);
} event_scratch SEC(".maps");

// In-flight sys_read/sys_recvfrom calls: pid_tgid -> data_args
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 65536);
  __type(key, u64);
  __type(value, struct data_args);
} active_data_args SEC(".maps");

// {tgid, fd} -> sock_ptr
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 65536);
  __type(key, struct conn_id);
  __type(value, u64);
} pid_fd_to_sock SEC(".maps");

// sock_ptr -> {tgid, fd} (reverse map for emit_data_event)
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 65536);
  __type(key, u64);              /* sock_ptr */
  __type(value, struct conn_id); /* {tgid, fd} */
} sock_to_conn_id SEC(".maps");

// In-flight sys_connect: pid_tgid -> connect_args
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 4096);
  __type(key, u64);
  __type(value, struct connect_args);
} active_connect_args SEC(".maps");

// In-flight sys_accept: pid_tgid -> accept_args
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 4096);
  __type(key, u64);
  __type(value, struct accept_args);
} active_accept_args SEC(".maps");

// Per-CPU statistics
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, u32);
  __type(value, struct stats);
} stats_map SEC(".maps");

// In-flight SSL_read calls: pid_tgid -> ssl_read_args
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 65536);
  __type(key, u64);
  __type(value, struct ssl_read_args);
} active_ssl_read_args SEC(".maps");

// In-flight SSL_write calls: pid_tgid -> ssl_write_args
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 65536);
  __type(key, u64);
  __type(value, struct ssl_write_args);
} active_ssl_write_args SEC(".maps");

// Nested syscall FD capture: pid_tgid -> nested_syscall_fd_t
// Set by SSL uprobe entry, updated by syscall kprobes, consumed by SSL return.
// This is the primary FD resolution method for OpenSSL, Python, and static builds.
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 65536);
  __type(key, u64);
  __type(value, struct nested_syscall_fd_t);
} ssl_user_space_call_map SEC(".maps");

// Per-TGID OpenSSL/BoringSSL struct field offsets.
// Written by userspace per process. Key = TGID, Value = ssl_symaddrs.
// Needed for userspace-offset FD access (Netty/BoringSSL) where
// different processes may use different SSL library versions.
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 4096);
  __type(key, u32);
  __type(value, struct ssl_symaddrs);
} ssl_symaddrs SEC(".maps");

// Ring buffer for operateHeaders transport-level header events.
// Written via bpf_ringbuf_output from go_h2_transport_scratch (per-CPU).
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 2 * 1024 * 1024);
} go_h2_transport_events SEC(".maps");

// Per-CPU scratch for go_h2_transport_event.
// Used because bpf_ringbuf_reserve pointers reject zero-assignment
// (BPF clang lowers = 0 to __builtin_memset which is banned on MEM_RINGBUF).
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct go_h2_transport_event);
} go_h2_transport_scratch SEC(".maps");

// Protocol-aware capture size limits, keyed by PROTO_CONFIG_* indices.
// Written once at startup by userspace (apiObserver.go).
// Lookup returns per-protocol max_capture_size for payload clamping.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, PROTO_CONFIG_MAX);
    __type(key, __u32);
    __type(value, struct protocol_config);
} protocol_config_map SEC(".maps");

/* ===================================================================
 * Kubeshark-style SSL maps
 * Ported from kubeshark/tracer (GPL-3.0)
 * =================================================================== */

#define KS_MAX_ENTRIES_LRU_HASH (1 << 14) /* 16384 */

/* OpenSSL per-operation context: pid_tgid → ks_ssl_info.
 * Separate maps for read vs write to avoid collisions. */
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

/* Go user-kernel address bridge: (pid<<32|fd) → ks_address_info
 * Filled by tcp_kprobes from struct sock, consumed by Go TLS return probes. */
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

/* Connection context: (pid<<32|fd) → conn_flags (client/server bit).
 * Filled by connect/accept tracepoints. REQUIRED: output_ssl_chunk drops
 * events without this entry. */
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, KS_MAX_ENTRIES_LRU_HASH);
  __type(key, __u64);
  __type(value, ks_conn_flags);
} ks_connection_context SEC(".maps");

/* Per-CPU scratch for TLS chunk assembly — stack is only 512 bytes. */
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, int);
  __type(value, struct ks_tls_chunk);
} ks_heap SEC(".maps");

/* Perf buffer for TLS chunks: BPF → Go reader. */
struct {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
  __uint(max_entries, 1024);
  __type(key, int);
  __type(value, __u32);
} ks_chunks_buffer SEC(".maps");

/* Port exclusion map: port (u16) → excluded (u8).
 * Populated by userspace at startup. Lookup returns non-NULL if port should
 * be excluded from tracing. Replaces hardcoded switch in filter_helpers.h. */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 64);
  __type(key, __u16);
  __type(value, __u8);
} port_exclusion_map SEC(".maps");

/* Per-thread last-socket-FD cache: pid_tgid → fd.
 * Populated by sys_enter_{read,write,recvfrom,sendto,sendmsg,recvmsg}
 * and sys_exit_{accept4,connect}.
 * Consumed as fallback in ks_ssl_uretprobe when fd=invalid (memory BIO apps
 * like Node.js where SSL_write/SSL_read make zero syscalls). */
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 8192);
  __type(key, __u64);
  __type(value, __u32);
} ks_pid_last_socket_fd SEC(".maps");

/* Per-process last-socket-FD cache: tgid (u32) → fd.
 * Secondary fallback for Java/Netty with useTasks=true where
 * the SSL operation runs on a different thread than socket I/O.
 * Less precise than per-thread cache (may correlate wrong FD for
 * multi-connection processes), but better than dropping events. */
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 4096);
  __type(key, __u32);
  __type(value, __u32);
} ks_tgid_last_socket_fd SEC(".maps");
