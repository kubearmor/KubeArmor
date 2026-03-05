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

// OpenSSL struct field offsets — written once by userspace at startup
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, u32);
  __type(value, struct ssl_symaddrs);
} ssl_symaddrs SEC(".maps");
