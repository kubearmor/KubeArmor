/* SPDX-License-Identifier: GPL-2.0
 * Copyright 2026 Authors of KubeArmor
 *
 * maps.h — Shared BPF map definitions for the API Observer.
 *
 * OWNERSHIP RULE: Each header file owns its own maps.
 *   ks_ssl_common.h      : ks_openssl_*_context, ks_heap, ks_chunks_buffer, etc.
 *   go_http2_trace.h     : go_http2_events, ongoing_grpc_*, go_h2_*
 *   go_http2_symaddrs.h  : go_offsets_map, go_h2_transport_events, etc.
 *   grpc_c_trace.h       : grpcc_events, grpcc_symaddrs_map
 *   cgroup_target.h      : ka_cgroup_ids, ka_excluded_cgroup_ids, ka_settings
 *   packet_sniffer.h     : ka_pkts_buffer, ka_pkt_heap
 *
 * This file defines ONLY the maps that are shared and have no owning header:
 *   port_exclusion_map, ns_cgroup_map, ns_filter_config
 */

#pragma once

#include "structs.h"

/* =========================================================================
 * Port exclusion and namespace filter maps
 * Written by Go userspace (populatePortExclusions / populateNsFilter).
 * Read by filter_helpers.h (is_excluded_port / should_trace_ns).
 * ========================================================================= */

/* Port exclusion map: port (u16) -> excluded (u8). Loaded at startup. */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 64);
  __type(key, __u16);
  __type(value, __u8);
} port_exclusion_map SEC(".maps");

/* Namespace filter: cgroup ID map for K8s namespace-based filtering. */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 16384);
  __type(key, __u64);
  __type(value, __u8);
} ns_cgroup_map SEC(".maps");

/* Namespace filter mode: 0=disabled, 1=allowlist, 2=blocklist. */
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, __u8);
} ns_filter_config SEC(".maps");
