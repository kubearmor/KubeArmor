/* SPDX-License-Identifier: GPL-2.0
 * Copyright 2026 Authors of KubeArmor
 *
 * go_http2_symaddrs.h — Offset structs for Go gRPC uprobes (OTel-style).
 *
 * These are populated by userspace and pushed to BPF via a per-inode
 * offset table map. The offsets allow probes to read Go struct fields
 * at the correct memory locations without needing DWARF or itable symbols.
 */

#pragma once

/* Offset table indices — must match Go-side OffsetKind constants. */
enum go_offset_kind {
  /* transport.Stream.method — Go string {ptr, len} */
  GO_OFF_GRPC_STREAM_METHOD = 0,
  /* transport.Stream.id — uint32 */
  GO_OFF_GRPC_STREAM_ID = 1,
  /* http2Server/http2Client.conn — net.Conn interface (type+ptr, 16B) */
  GO_OFF_GRPC_TRANSPORT_CONN = 2,
  /* status.Status.s — pointer to internal status */
  GO_OFF_GRPC_STATUS_S = 3,
  /* codes.Code position within status.Status.s */
  GO_OFF_GRPC_STATUS_CODE = 4,
  /* net.TCPConn → internal/poll.FD.Sysfd offset chain */
  GO_OFF_FD_SYSFD = 5,
  /* conn_fd_pos: net.Conn → FD pointer */
  GO_OFF_CONN_FD = 6,
  /* fd.laddr */
  GO_OFF_FD_LADDR = 7,
  /* fd.raddr */
  GO_OFF_FD_RADDR = 8,
  /* TCPAddr.Port */
  GO_OFF_TCP_ADDR_PORT = 9,
  /* TCPAddr.IP pointer */
  GO_OFF_TCP_ADDR_IP = 10,
  /* grpc version >= 1.60 (extra ctx arg) */
  GO_OFF_GRPC_V160 = 11,
  /* grpc version >= 1.69 (server stream wrapper) */
  GO_OFF_GRPC_V169 = 12,
  /* server stream → stream pointer (v1.69+) */
  GO_OFF_GRPC_SERVER_STREAM_STREAM = 13,
  /* server stream → st pointer (v1.69+) */
  GO_OFF_GRPC_SERVER_STREAM_ST = 14,
  /* stream.st pointer (pre-v1.69) */
  GO_OFF_GRPC_STREAM_ST = 15,

  GO_OFF_TLS_CONN_CONN = 16, 

  /* MetaHeadersFrame struct offsets (configurable, defaults in offsets.go) */
  GO_OFF_META_FIELDS_PTR = 17,   /* offset of Fields.Ptr in MetaHeadersFrame */
  GO_OFF_META_FIELDS_LEN = 18,   /* offset of Fields.Len in MetaHeadersFrame */
  GO_OFF_HFRAME_STREAM_ID = 19,  /* offset of StreamID in FrameHeader */
  GO_OFF_HFIELD_SIZE = 20,       /* sizeof(hpack.HeaderField) */

  /* loopyWriter.writeHeader probe offsets */
  GO_OFF_LOOPY_WRITER_FRAMER = 21,  /* loopyWriter → framer (Framer ptr) */

  /* http2serverConn offsets (for net/http response header correlation) */
  GO_OFF_H2SC_HPACK_ENCODER = 22,   /* http2serverConn → hpackEncoder ptr */
  GO_OFF_H2SC_CONN = 23,            /* http2serverConn → conn (net.Conn iface) */

  /* http2writeResHeaders struct offsets */
  GO_OFF_WRITE_RES_STREAM_ID = 24,  /* http2writeResHeaders → streamID */
  GO_OFF_WRITE_RES_END_STREAM = 25, /* http2writeResHeaders → endStream */

  /* Go crypto/tls FD extraction chain:
   * tls.Conn → GO_OFF_TLS_CONN_CONN (conn interface, already at idx 16)
   *   → interface.ptr → net.TCPConn
   *   → GO_OFF_CONN_FD (netFD ptr, already at idx 6)
   *   → GO_OFF_FD_SYSFD (pfd.Sysfd, already at idx 5) */

  GO_OFF_MAX = 26,
};

#define GO_OFFSET_TABLE_SIZE GO_OFF_MAX

/* Per-binary offset table, keyed by inode in the BPF map. */
struct go_offset_table {
  s64 offsets[GO_OFFSET_TABLE_SIZE];
};

/* Inode → offset table (populated from userspace). */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 4096);
  __type(key, u64);
  __type(value, struct go_offset_table);
} go_offsets_map SEC(".maps");

/*
 * Get the offset table for the current process's binary.
 * Uses the inode of the executable as key (same as OTel).
 */
static __always_inline struct go_offset_table *get_offsets(void) {
  struct task_struct *task = (struct task_struct *)bpf_get_current_task();
  u64 ino = BPF_CORE_READ(task, mm, exe_file, f_inode, i_ino);
  return (struct go_offset_table *)bpf_map_lookup_elem(&go_offsets_map, &ino);
}

static __always_inline s64 go_offset(struct go_offset_table *ot,
                                     enum go_offset_kind kind) {
  if (!ot || kind >= GO_OFF_MAX)
    return -1;
  return ot->offsets[kind];
}
