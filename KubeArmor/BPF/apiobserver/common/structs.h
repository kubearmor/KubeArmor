/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Authors of KubeArmor
 *
 * structs.h — All shared BPF struct definitions for the API Observer.
 * match with ParseDataEvent() in KubeArmor/apiObserver/events/event.go
 */

#pragma once

#include "macros.h"

//! TODO REMOVE THIS
/*
 * data_event — emitted to ring buffer for every captured payload chunk.
 *
 *   offset  0 : u64 timestamp    (ktime_get_ns)
 *   offset  8 : u32 pid
 *   offset 12 : u32 tid
 *   offset 16 : u32 src_ip       (IPv4 host byte order)
 *   offset 20 : u32 dst_ip
 *   offset 24 : u16 src_port
 *   offset 26 : u16 dst_port
 *   offset 28 : u32 data_len     (actual captured bytes)
 *   offset 32 : u8  direction        (1 byte)
 *   offset 33 : u8  protocol         (1 byte)
 *   offset 34 : u8  flags            (1 byte)
 *   offset 35 : u8  pad[1]           (1 byte — alignment)
 *   offset 36 : u32 fd               (file descriptor)
 *   offset 40 : u64 sock_ptr         (8 bytes)
 *   offset 48 : u8  payload[]        (variable, up to MAX_DATA_SIZE = 8192)
 */

// data_event — emitted to ring buffer for every captured payload chunk.
struct data_event {
  u64 timestamp;
  u32 pid;
  u32 tid;
  u32 src_ip;
  u32 dst_ip;
  u16 src_port;
  u16 dst_port;
  u32 data_len;
  u8 direction;
  u8 protocol;
  u8 flags;
  u8 _pad[1];
  u32 fd;
  u64 sock_ptr;
  unsigned char payload[MAX_DATA_SIZE];
};

// conn_info — per-connection state, keyed by sock_ptr.
struct conn_info {
  u32 src_ip;
  u32 dst_ip;
  u16 src_port;
  u16 dst_port;
  u8 protocol;
  u8 http2_detected;
  u8 is_ssl;
  u8 _pad;
};

// data_args_t carries the extracted arguments from a sys_read or sys_recvfrom
// entry probe into the corresponding return probe.
struct data_args {
  u32 fd;  /* file descriptor from syscall arg */
  u64 buf; /* user buffer pointer (void * stored as u64) */
};

// ssl_read_args — saved on SSL_read entry; consumed on uretprobe return.
struct ssl_read_args {
  u64 ssl_ptr; /* SSL* stored as u64 */
  u64 buf;     /* void* plaintext buffer */
};

// ssl_symaddrs — version-specific OpenSSL struct field offsets.
// Detected in userspace and added into a BPF map
struct ssl_symaddrs {
  s32 ssl_rbio_offset; /* offsetof(SSL, rbio) */
  s32 bio_num_offset;  /* offsetof(BIO, num)  — holds the fd */
};

// Connection tracking key: {pid_tgid, fd} -> sock_ptr
struct conn_id {
  u32 tgid;
  u32 fd;
};

// connect_args — saved on sys_connect entry; keyed by pid_tgid.
struct connect_args {
  u32 fd;
};

// accept_args — saved on sys_accept/accept4 entry; keyed by pid_tgid.
struct accept_args {
  u64 addr;
};

// stats — per-CPU counters; aggregated in userspace
struct stats {
  u64 total_packets;
  u64 http1_packets;
  u64 http2_packets;
  u64 grpc_packets;
  u64 filtered_packets;
  u64 dropped_packets;
  u64 parse_errors;
};
