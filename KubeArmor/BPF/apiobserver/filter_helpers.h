/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Authors of KubeArmor
 *
 * filter_helpers.h — Traffic filtering helpers.
 * Helper functions to determine if a packet should be traced or dropped at the
 * kernel layer.
 *
 */

#pragma once

#include "common/macros.h"

static __attribute__((always_inline)) int is_http_traffic(const char *buf,
                                                          u32 len) {
  if (len < MIN_HTTP_SIZE)
    return 0;
  u32 w = READ_WORD_LE(buf, 0);
  return (w == HTTP_GET_INT || w == HTTP_POST_INT || w == HTTP_PUT_INT ||
          w == HTTP_DEL_INT || w == HTTP_HEAD_INT || w == HTTP_PATC_INT ||
          w == HTTP_OPTI_INT || w == HTTP_HTTP_INT);
}

/*
 * is_health_check — trie-based, zero false positives
 *
 * Paths filtered:
 *   /debug    
 *   /health  
 *   /livez   
 *   /metrics 
 *   /ping   
 *   /readyz
 */
static __attribute__((always_inline)) int is_health_check(const char *buf, u32 len) {
  if (len < 16) {
    return 0;
  }

  char b[16] = {0};
  __builtin_memcpy(b, buf, 16);

  if (b[0] != 'G' || b[1] != 'E' || b[2] != 'T' || b[3] != ' ' || b[4] != '/') {
    return 0;
  }

  switch (b[5]) {

  case 'd': // debug*
    return b[6] == 'e' && b[7] == 'b' && b[8] == 'u' && b[9] == 'g';

  case 'h': // health*
    return b[6] == 'e' && b[7] == 'a' && b[8] == 'l' && b[9] == 't' &&
           b[10] == 'h';

  case 'l': // livez*
    return b[6] == 'i' && b[7] == 'v' && b[8] == 'e' && b[9] == 'z';

  case 'm': // metrics*
    return b[6] == 'e' && b[7] == 't' && b[8] == 'r' && b[9] == 'i' &&
           b[10] == 'c' && b[11] == 's';

  case 'p': // ping*
    return b[6] == 'i' && b[7] == 'n' && b[8] == 'g';

  case 'r': //readyz*
    return b[6] == 'e' && b[7] == 'a' && b[8] == 'd' && b[9] == 'y' &&
           b[10] == 'z';
  }

  return 0;
}

// Port exclusion via BPF map lookup — configurable from userspace.
// Returns 1 (trace) if port is NOT in the exclusion map, 0 (drop) if excluded.
static __attribute__((always_inline)) int should_trace_port(u16 port) {
  u8 *excluded = bpf_map_lookup_elem(&port_exclusion_map, &port);
  return excluded == NULL;  // trace if NOT excluded
}

// Loopback check: returns 1 if IP is in 127.0.0.0/8.
// skc_rcv_saddr is __be32 (network byte order). BPF_CORE_READ_INTO copies
// raw bytes into a native u32. On all supported little-endian architectures
// (x86_64/AMD64, arm64), the first IP octet lands in the lowest byte.
static __attribute__((always_inline)) int is_loopback(__u32 ip) {
  return (ip & 0xFF) == 0x7F;
}

// Namespace (K8s) filter — cgroup-ID based.
// Returns 1 (drop) if the current task's cgroup should be filtered,
// 0 (allow) otherwise. When filter is disabled, always returns 0.
#define NS_FILTER_DISABLED  0
#define NS_FILTER_ALLOWLIST 1
#define NS_FILTER_BLOCKLIST 2

static __attribute__((always_inline)) int is_ns_filtered(void) {
  __u32 zero = 0;
  __u8 *mode = bpf_map_lookup_elem(&ns_filter_config, &zero);
  if (!mode || *mode == NS_FILTER_DISABLED)
    return 0;

  __u64 cgroup_id = bpf_get_current_cgroup_id();
  __u8 *found = bpf_map_lookup_elem(&ns_cgroup_map, &cgroup_id);

  if (*mode == NS_FILTER_ALLOWLIST)
    return found == NULL ? 1 : 0;

  return found != NULL ? 1 : 0;
}
