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
// Payload size limit per BPF event. Increasing beyond 8192 causes BPF
// verifier failures on some kernels (map value offset tracking).
// Userspace truncation in enrichAndEmit provides an additional safety cap.
#define MAX_DATA_SIZE 8192

// Protocol-specific capture size defaults (compile-time fallbacks).
// Used when protocol_config_map lookup fails. HTTP/2 and gRPC frames
// are typically much smaller than HTTP/1 full payloads.
#define DEFAULT_H1_CAPTURE_SIZE  8192
#define DEFAULT_H2_CAPTURE_SIZE  4096
#define DEFAULT_CAPTURE_SIZE     8192

// Protocol config map key indices (protocol IDs).
// Must match Go-side ProtocolConfigXxx constants in apiObserver.go.
#define PROTO_CONFIG_HTTP1  0
#define PROTO_CONFIG_HTTP2  1
#define PROTO_CONFIG_GRPC   2
#define PROTO_CONFIG_MAX    3

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

// Maximum gRPC method string length captured by the BPF uprobe.
// Must be a power of 2 for the BPF verifier's dynamic-size masking.
#define GRPCC_MAX_METHOD_SIZE  64

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
