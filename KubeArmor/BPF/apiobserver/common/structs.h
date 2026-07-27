/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Authors of KubeArmor
 *
 * structs.h — All shared BPF struct definitions for the API Observer.
 *
 * Architecture: Kubeshark-style dual-path capture.
 *   Removed: syscall-based stream structs (data_event, conn_info, data_args,
 *            active_data_args, etc.)
 *   Kept:    Kubeshark-style TLS chunk structs, Go uprobe structs, gRPC-C structs.
 */

#pragma once

#include "macros.h"

/* =========================================================================
 * Kubeshark-style SSL / Go TLS capture structures
 * ========================================================================= */

/* One minute in nanoseconds — stale ssl_info entries are discarded. */
#define SSL_INFO_MAX_TTL_NANO (1000000000l * 60l)

/* Chunk sizing — must be power of 2 for verifier-happy masking. */
#define TLS_CHUNK_SIZE        (1 << 12)  /* 4096 bytes per chunk */
#define TLS_MAX_CHUNKS_PER_OP (8)        /* 8 × 4096 = 32 KB max per SSL op */

/* Flags shared between BPF and Go. */
#define TLS_FLAGS_IS_CLIENT_BIT (1 << 0)
#define TLS_FLAGS_IS_READ_BIT   (1 << 1)

const __s32 ks_invalid_fd = -1;

/* ks_address_info — source/destination IP + port, filled by tcp_kprobes. */
struct ks_address_info {
  __be32 family;
  __be32 saddr4;
  __be32 daddr4;
  __u8   saddr6[16];
  __u8   daddr6[16];
  __be16 sport;
  __be16 dport;
};

/* ks_ssl_info — per-operation SSL context, keyed by pid_tgid.
 * Entry probe saves buffer+len; syscall tracepoints fill fd;
 * tcp kprobes fill address_info; return probe emits the chunk. */
struct ks_ssl_info {
  uintptr_t buffer;           /* plaintext buffer pointer */
  __u32     buffer_len;       /* number of bytes */
  __u32     fd;               /* socket FD, filled by sys_enter_write tracepoint */
  __u64     created_at_nano;  /* for TTL-based staleness check */
  struct ks_address_info address_info;
  uintptr_t count_ptr;        /* for SSL_write_ex/SSL_read_ex: pointer to output length */
};

/* ks_tls_chunk — emitted to perf buffer for each SSL data chunk.
 * Must match Go-side TlsChunk struct exactly (alignment matters). */
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

/* ssl_symaddrs — version-specific OpenSSL struct field offsets.
 * Detected in userspace and written into ssl_symaddrs BPF map. */
struct ssl_symaddrs {
  __s32 ssl_rbio_offset; /* offsetof(SSL, rbio) */
  __s32 bio_num_offset;  /* offsetof(BIO, num) — holds the fd */
};

/* =========================================================================
 * Go HTTP/2 / gRPC uprobe structures
 * ========================================================================= */

#define GO_H2_MAX_FIELDS  20
#define GO_H2_NAME_SIZE   128
#define GO_H2_VAL_SIZE    128

struct go_h2_hdr_field {
    char name[GO_H2_NAME_SIZE];
    char value[GO_H2_VAL_SIZE];
};

/* go_h2_transport_event — emitted by ka_uprobe_operate_headers_{server,client}.
 * Carries post-HPACK decoded header fields read from MetaHeadersFrame.Fields. */
struct go_h2_transport_event {
    __u32 pid;
    __u32 stream_id;
    __u8  is_server;   /* 1 = server operateHeaders, 0 = client */
    __u8  field_count;
    __u16 pad;
    struct go_h2_hdr_field fields[GO_H2_MAX_FIELDS];
};

/* go_h2_encoder_ctx — correlates hpack Encoder pointer to stream context. */
struct go_h2_encoder_ctx {
    __u32 pid;
    __u32 stream_id;
};

/* go_h2_single_header_event — emitted per-field by hpack.WriteField probe. */
#define HEADER_FIELD_STR_SIZE 128
struct go_h2_single_header_event {
    __u32 pid;
    __u32 stream_id;
    __u8  is_server;   /* 1=server, 0=client */
    __u8  event_type;  /* 1=read, 2=write */
    __u16 name_len;
    __u16 value_len;
    __u16 _pad;
    char  name[HEADER_FIELD_STR_SIZE];
    char  value[HEADER_FIELD_STR_SIZE];
};

/* NOTE: go_addr_key, go_grpc_server_inv, go_grpc_client_inv are defined
 * in go_http2_trace.h which owns them. Do NOT redefine here. */



/* NOTE: go_offset_table is defined in go_http2_symaddrs.h which owns it.
 * Do NOT redefine here. */



/* =========================================================================
 * gRPC-C (libgrpc.so) uprobe structures
 * ========================================================================= */

/* grpcc_symaddrs — version-specific gRPC-C struct field offsets.
 * Written once by userspace at startup via grpcc_symaddrs_map[0].
 * MUST stay in sync with grpcc.GRPCCOffsets in Go. */
struct grpcc_symaddrs {
    __s32 stream_method_offset;  /* offsetof(grpc_chttp2_stream, method) */
    __s32 stream_id_offset;      /* offsetof(grpc_chttp2_stream, id) */
    __s32 transport_fd_offset;   /* offsetof(grpc_chttp2_transport, fd) */
};
