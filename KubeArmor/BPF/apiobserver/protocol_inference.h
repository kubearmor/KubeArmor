/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Authors of KubeArmor
 *
 * protocol_inference.h — Protocol classification for captured payloads.
 */

#pragma once

#include "common/macros.h"
#include "common/structs.h"
#include "filter_helpers.h"

#include <bpf/bpf_endian.h>

static __attribute__((always_inline)) int
is_http2_preface(const unsigned char *buf, u32 len) {
  if (len < 24) {
    return 0;
  }

  // RFC 7540 §3.5 — the full 24-byte client connection preface
  static const char HTTP2_PREFACE[24] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

  char local[24] = {0};
  __builtin_memcpy(local, buf, 24);
  return __builtin_memcmp(local, HTTP2_PREFACE, 24) == 0;
}

static __attribute__((always_inline)) int
is_valid_http2_frame(const unsigned char *buf, u32 len) {
  if (len < 9) {
    return 0;
  }

  u32 flen = ((u32)buf[0] << 16) | ((u32)buf[1] << 8) | buf[2];
  u8 ftype = buf[3];
  if (flen > 16777215 || ftype > HTTP2_MAX_FRAME_TYPE) {
    return 0;
  }

  u32 sid = 0;
  __builtin_memcpy(&sid, buf + 5, 4);
  sid = bpf_ntohl(sid) & 0x7FFFFFFF;
  if ((ftype == HTTP2_FRAME_SETTINGS || ftype == HTTP2_FRAME_PING) &&
      sid != 0) {
    return 0;
  }

  if ((ftype == HTTP2_FRAME_DATA || ftype == HTTP2_FRAME_HEADERS) && sid == 0) {
    return 0;
  }

  return 1;
}

static __attribute__((always_inline)) int
is_grpc_headers_frame(const unsigned char *buf, u32 len) {
  if (!is_valid_http2_frame(buf, len)) {
    return 0;
  }

  if (buf[3] != HTTP2_FRAME_HEADERS) {
    return 0;
  }

  int limit = MAX_PROTOCOL_SCAN;
  if ((int)len < MAX_PROTOCOL_SCAN) {
    limit = (int)len;
  }

#pragma unroll
  for (int i = 9; i < MAX_PROTOCOL_SCAN - 4; i++) {
    if (i < limit - 4) {
      if (buf[i] == 'g' && buf[i + 1] == 'r' && buf[i + 2] == 'p' &&
          buf[i + 3] == 'c')
        return 1;
    }
  }
  return 0;
}

// Updates conn->http2_detected as sticky bit so response frames
// (which lack the preface) are still classified correctly.
// gRPC detection here is a HEURISTIC HINT only.
// Full reliable classification runs in userspace via grpc/parser.go.
static __attribute__((always_inline)) u8
detect_protocol(const unsigned char *buf, u32 len, struct conn_info *conn) {
  if (conn->http2_detected) {
    if (is_grpc_headers_frame(buf, len)) {
      return PROTO_GRPC;
    }

    if (is_valid_http2_frame(buf, len)) {
      return PROTO_HTTP2;
    }
  }

  if (is_http2_preface(buf, len)) {
    conn->http2_detected = 1;
    return PROTO_HTTP2;
  }

  if (is_valid_http2_frame(buf, len)) {
    conn->http2_detected = 1;
    return is_grpc_headers_frame(buf, len) ? PROTO_GRPC : PROTO_HTTP2;
  }

  if (is_http_traffic((const char *)buf, len)) {
    return PROTO_HTTP1;
  }

  return PROTO_UNKNOWN;
}
