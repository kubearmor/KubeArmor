/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Authors of KubeArmor
 *
 * structs.h — All shared BPF struct definitions for the API Observer.
 * match with ParseDataEvent() in KubeArmor/apiObserver/events/event.go
 */

#pragma once

#include "macros.h"

/*
 * data_event — emitted to ring buffer for every captured payload chunk.
 *
 * Wire layout (must match ParseDataEvent() in apiObserver/events/events.go):
 *
 *   offset  0 : u64 timestamp    (ktime_get_ns)
 *   offset  8 : u32 pid
 *   offset 12 : u32 tid
 *   offset 16 : u32 src_ip       (IPv4 host byte order)
 *   offset 20 : u32 dst_ip
 *   offset 24 : u16 src_port
 *   offset 26 : u16 dst_port
 *   offset 28 : u32 data_len     (actual captured bytes)
 *   offset 32 : u8  direction    (DIR_EGRESS=0, DIR_INGRESS=1)
 *   offset 33 : u8  protocol     (PROTO_UNKNOWN/HTTP1/HTTP2/GRPC)
 *   offset 34 : u8  flags        (FLAG_NO_PAYLOAD, FLAG_TRUNCATED, FLAG_IS_SSL)
 *   offset 35 : u8  pad[1]       (alignment)
 *   offset 36 : u32 fd           (file descriptor)
 *   offset 40 : u64 sock_ptr     (kernel socket pointer)
 *   offset 48 : u8  payload[]    (variable, up to MAX_DATA_SIZE = 8192)
 */
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
  u64 ssl_ptr;        /* SSL* stored as u64 */
  u64 buf;            /* void* plaintext buffer */
  u64 ssl_ex_len_ptr; /* size_t* for SSL_read_ex (0 for SSL_read) */
};

// ssl_write_args — saved on SSL_write entry; consumed on uretprobe return.
struct ssl_write_args {
  u64 ssl_ptr;        /* SSL* stored as u64 */
  u64 buf;            /* void* plaintext buffer */
  u64 ssl_ex_len_ptr; /* size_t* for SSL_write_ex (0 for SSL_write) */
};

// nested_syscall_fd_t — tracks FD capture during SSL_read/SSL_write.
// ssl_user_space_call_map[pid_tgid] is set on SSL uprobe entry,
// FD is filled by syscall kprobes (write/read/sendto/etc),
// consumed on SSL uprobe return.
struct nested_syscall_fd_t {
  s32 fd;             /* -1 until a nested syscall captures it */
  u8  mismatched_fds; /* true if multiple different FDs seen */
  u8  _pad[3];
};

// ssl_symaddrs — version-specific OpenSSL struct field offsets.
// Detected in userspace and added into a BPF map
struct ssl_symaddrs {
  s32 ssl_rbio_offset; /* offsetof(SSL, rbio) */
  s32 bio_num_offset;  /* offsetof(BIO, num)  — holds the fd */
};

/* ===================================================================
 * Kubeshark-style SSL capture structures
 * Ported from kubeshark/tracer (GPL-3.0)
 * =================================================================== */

// One minute in nanoseconds — stale ssl_info entries are discarded.
#define SSL_INFO_MAX_TTL_NANO (1000000000l * 60l)

// Chunk sizing — must be power of 2 for verifier-happy masking.
#define TLS_CHUNK_SIZE (1 << 12)       /* 4096 bytes per chunk */
#define TLS_MAX_CHUNKS_PER_OP (8)      /* 8 * 4096 = 32 KB max per operation */

// Flags shared between BPF and Go.
#define TLS_FLAGS_IS_CLIENT_BIT (1 << 0)
#define TLS_FLAGS_IS_READ_BIT   (1 << 1)

const __s32 ks_invalid_fd = -1;

// ks_address_info — source/destination IP + port, filled by tcp_kprobes.
struct ks_address_info {
  __be32 family;
  __be32 saddr4;
  __be32 daddr4;
  __u8   saddr6[16];
  __u8   daddr6[16];
  __be16 sport;
  __be16 dport;
};

// ks_ssl_info — per-operation SSL context, keyed by pid_tgid.
// Entry probe saves buffer+len; syscall tracepoints fill in fd;
// tcp kprobes fill in address_info; return probe emits the chunk.
struct ks_ssl_info {
  uintptr_t buffer;           /* plaintext buffer pointer */
  __u32     buffer_len;       /* number of bytes */
  __u32     fd;               /* socket FD, filled by sys_enter_write tracepoint */
  __u64     created_at_nano;  /* for TTL-based staleness check */
  struct ks_address_info address_info;
  uintptr_t count_ptr;        /* for SSL_write_ex and SSL_read_ex: pointer to output length */
};

// ks_tls_chunk — emitted to perf buffer for each SSL data chunk.
// Must match Go-side TlsChunk struct exactly (alignment matters).
struct ks_tls_chunk {
  __u64 timestamp;
  __u32 cgroup_id;
  __u32 pid;
  __u32 tgid;
  __u32 len;       /* total plaintext length */
  __u32 start;     /* byte offset within the total data */
  __u32 recorded;  /* bytes actually in data[] */
  __u32 fd;
  __u32 flags;
  struct ks_address_info address_info;
  __u8  data[TLS_CHUNK_SIZE]; /* must be N^2 */
};

typedef __u8 ks_conn_flags;

// grpcc_symaddrs — version-specific gRPC-C struct field offsets.
// Written once by userspace at startup via grpcc_symaddrs_map[0].
// MUST stay in sync with grpcc.GRPCCOffsets in Go.
struct grpcc_symaddrs {
    s32 stream_method_offset;   // offsetof(grpc_chttp2_stream,    method) — grpc_slice
    s32 stream_id_offset;       // offsetof(grpc_chttp2_stream,    id)     — uint32
    s32 transport_fd_offset;    // offsetof(grpc_chttp2_transport, fd)     — int
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

// Emitted by ka_uprobe_operate_headers_{server,client}.
// Carries post-HPACK decoded header fields read directly from
// golang.org/x/net/http2.MetaHeadersFrame.Fields ([]hpack.HeaderField).
// Sized for BPF ring-buf: 8 bytes header + 8*(32+128) = 1288 bytes total.
#define GO_H2_MAX_FIELDS  20
#define GO_H2_NAME_SIZE   128
#define GO_H2_VAL_SIZE    128

struct go_h2_hdr_field {
    char name[GO_H2_NAME_SIZE];
    char value[GO_H2_VAL_SIZE];
};

struct go_h2_transport_event {
    __u32 pid;
    __u32 stream_id;
    __u8  is_server;  // 1 = server operateHeaders, 0 = client
    __u8  field_count;
    __u16 pad;
    struct go_h2_hdr_field fields[GO_H2_MAX_FIELDS];
};

// Header field string size for per-field encoder events (matches Pixie).
#define HEADER_FIELD_STR_SIZE 128

// go_h2_encoder_ctx — correlates hpack Encoder pointer to stream context.
// Stored in active_encoder_map, looked up by hpack.WriteField.
struct go_h2_encoder_ctx {
    __u32 pid;
    __u32 stream_id;
};

// go_h2_single_header_event — emitted per-field by hpack.WriteField probe.
// Lighter than go_h2_transport_event: one name+value pair per event.
struct go_h2_single_header_event {
    __u32 pid;
    __u32 stream_id;
    __u8  is_server;   // 1=server, 0=client
    __u8  event_type;  // 1=read, 2=write
    __u16 name_len;
    __u16 value_len;
    __u16 _pad;
    char  name[HEADER_FIELD_STR_SIZE];
    char  value[HEADER_FIELD_STR_SIZE];
};

// protocol_config — per-protocol capture limits, set by userspace.
struct protocol_config {
    __u32 max_capture_size;
};
