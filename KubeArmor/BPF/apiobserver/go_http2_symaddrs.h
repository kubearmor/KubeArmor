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

  GO_OFF_MAX,
};

#define GO_OFFSET_TABLE_SIZE GO_OFF_MAX

/* Per-binary offset table, keyed by inode in the BPF map. */
struct go_offset_table {
  s64 offsets[GO_OFFSET_TABLE_SIZE];
};
