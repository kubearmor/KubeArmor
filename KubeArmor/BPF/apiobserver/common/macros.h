/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Authors of KubeArmor
 *
 * macros.h — Compile-time constants for the API Observer BPF programs. *
 * Compile-time constants defining the protocol API between BPF code and
 * usrespace code.
 */

#pragma once

// Address families
#define AF_INET 2
#define AF_INET6 10

// TCP states
#define TCP_ESTABLISHED 1
#define TCP_CLOSE 7

// Message flags
#define MSG_PEEK 0x02

// Data direction — must match apiObserver/events/event.go DirEgress/DirIngress
#define DIR_EGRESS 0
#define DIR_INGRESS 1

// Protocol IDs — must match apiObserver/events/event.go Proto* constants
#define PROTO_UNKNOWN 0
#define PROTO_HTTP1 1
#define PROTO_HTTP2 2
#define PROTO_GRPC 3

// Data event flags (DataEvent.Flags bitmask)
#define FLAG_NO_PAYLOAD 0x01
#define FLAG_TRUNCATED 0x02

// Payload size limit, used by the ring buffer
#define MAX_DATA_SIZE 8192

// BPF loop limits
#define MAX_IOV_SEGMENTS 8
#define MAX_PROTOCOL_SCAN 128

// HTTP/2 frame types (RFC 7540 §6)
#define HTTP2_FRAME_DATA 0x00
#define HTTP2_FRAME_HEADERS 0x01
#define HTTP2_FRAME_PRIORITY 0x02
#define HTTP2_FRAME_RST_STREAM 0x03
#define HTTP2_FRAME_SETTINGS 0x04
#define HTTP2_FRAME_PUSH_PROMISE 0x05
#define HTTP2_FRAME_PING 0x06
#define HTTP2_FRAME_GOAWAY 0x07
#define HTTP2_FRAME_WINDOW_UPDATE 0x08
#define HTTP2_FRAME_CONTINUATION 0x09
#define HTTP2_MAX_FRAME_TYPE 0x09

// HTTP method first-4-bytes as uint32
#define HTTP_GET_INT 0x20544547  /* "GET "  */
#define HTTP_POST_INT 0x54534F50 /* "POST"  */
#define HTTP_PUT_INT 0x20545550  /* "PUT "  */
#define HTTP_DEL_INT 0x454C4544  /* "DEL"   */
#define HTTP_HTTP_INT 0x50545448 /* "HTTP"  — response prefix */
#define HTTP_HEAD_INT 0x44414548 /* "HEAD"  */
#define HTTP_PATC_INT 0x43544150 /* "PATC"  */
#define HTTP_OPTI_INT 0x4954504F /* "OPTI"  */

#define MIN_HTTP_SIZE 16
#define FLAG_IS_SSL 0x04 // event came from SSL uprobe

// Safe LE word read from BPF stack/percpu memory
// buf MUST be in BPF memory
#define READ_WORD_LE(buf, offset)                                              \
  ({                                                                           \
    u32 _w = 0;                                                                \
    __builtin_memcpy(&_w, (buf) + (offset), 4);                                \
    _w;                                                                        \
  })
