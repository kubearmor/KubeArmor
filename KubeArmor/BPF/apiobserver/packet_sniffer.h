/* SPDX-License-Identifier: GPL-2.0
 * Copyright 2026 Authors of KubeArmor
 *
 * packet_sniffer.h — cgroup_skb packet capture for API Observer.
 *
 * Ported from kubeshark/tracer bpf/packet_sniffer.c (GPL-3.0).
 *
 * Strategy: attach cgroup_skb/ingress + cgroup_skb/egress programs to each
 * targeted pod's cgroup. The kernel calls these for every packet entering or
 * leaving a socket in the cgroup. Packets are chunked (PKT_PART_LEN bytes per
 * perf event) to stay within BPF stack limits and sent via ka_pkts_buffer.
 *
 * Userspace (poller/packets.go) reassembles chunks by packet ID and calls the
 * gopacket dissector pipeline.
 */

#pragma once

#include "common/macros.h"
#include "common/structs.h"
#include "cgroup_target.h"
#include "filter_helpers.h"

/* ---- Packet chunk constants ---- */
/* PKT_PART_LEN must fit in a perf event (≤ 64 KB).
 * We use 4080 bytes: 4096 - 16 bytes for overhead. This gives us
 * 16 full chunks per 64 KB max packet. */
#ifndef PKT_PART_LEN
#define PKT_PART_LEN  4080
#endif

/* Maximum packet length we can handle. 16 chunks × 4080 = ~65 KB.
 * Enough for any Ethernet MTU. */
#ifndef PKT_MAX_LEN
#define PKT_MAX_LEN   (PKT_PART_LEN * 16)
#endif

/* Packet directions — must match Go-side unixpacket.PacketDirection */
#define PKT_DIR_RECEIVED 0
#define PKT_DIR_SENT     1

/* ---- Packet chunk struct ---- */
/* Emitted to ka_pkts_buffer. Userspace reassembles by (id, num). */
struct ka_pkt {
    __u64 timestamp;
    __u64 cgroup_id;
    __u64 id;       /* monotonic per-CPU packet ID */
    __u32 len;      /* bytes in buf[] for this chunk */
    __u32 tot_len;  /* total uncompressed packet length */
    __u32 counter;  /* remaining bytes (decremented as chunks are emitted) */
    __u16 num;      /* chunk sequence number (0-based) */
    __u16 last;     /* 1 if this is the final chunk of the packet */
    __u16 ip_hdr_type; /* ETH_P_IP (0x0800) or ETH_P_IPV6 (0x86DD) */
    __u8  direction;   /* PKT_DIR_RECEIVED or PKT_DIR_SENT */
    __u8  _pad[1];
    __u8  buf[PKT_PART_LEN];
};

/* ---- BPF Maps ---- */

/* Per-CPU scratch space for packet chunk assembly. */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, int);
    __type(value, struct ka_pkt);
} ka_pkt_heap SEC(".maps");

/* Per-packet-ID in-flight chunk state (multi-chunk packets only). */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64); /* packet ID */
    __type(value, struct ka_pkt);
} ka_pkt_heap_hash SEC(".maps");

/* Atomic packet ID counter per CPU. */
struct ka_pkt_id_t {
    __u64 id;
    struct bpf_spin_lock lock;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, int);
    __type(value, struct ka_pkt_id_t);
} ka_pkt_id SEC(".maps");

/* Per-packet-ID socket → cgroup mapping.
 * Needed when bpf_skb_cgroup_id() is not reliable (cgroup v1). */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u64);   /* socket cookie (bpf_get_socket_cookie) */
    __type(value, __u64); /* cgroup_id */
} ka_socket_cgroups SEC(".maps");

/* Main output buffer: BPF → userspace packet poller.
 * Large perf event array (4096 slots) to handle bursts. */
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, 4096);
    __type(key, int);
    __type(value, __u32);
} ka_pkts_buffer SEC(".maps");

/* ---- Protocol constants ---- */
#define ETH_P_IP    0x0800
#define ETH_P_IPV6  0x86DD

/* ---- Internal helpers ---- */

/*
 * ka_save_packet — slice a raw skb into ka_pkt chunks and emit them.
 *
 * Uses the per-CPU ka_pkt_heap for scratch, then moves to ka_pkt_heap_hash
 * for multi-chunk packets (to avoid re-zeroing on each perf_event_output).
 */
static __noinline int ka_save_packet(struct __sk_buff *skb, __u64 cgroup_id,
                                     __u8 direction)
{
    int zero = 0;
    int ret  = 0;

    /* Allocate monotonic packet ID. */
    struct ka_pkt_id_t *pid_ptr = bpf_map_lookup_elem(&ka_pkt_id, &zero);
    if (!pid_ptr) return 1;

    bpf_spin_lock(&pid_ptr->lock);
    __u64 packet_id = ++pid_ptr->id;
    bpf_spin_unlock(&pid_ptr->lock);

    /* Grab the per-CPU scratch buffer. */
    struct ka_pkt *pzero = bpf_map_lookup_elem(&ka_pkt_heap, &zero);
    if (!pzero) return 1;

    /* Clone into hash map to avoid stack allocation. */
    if (bpf_map_update_elem(&ka_pkt_heap_hash, &packet_id, pzero, BPF_ANY))
        return 1;
    struct ka_pkt *p = bpf_map_lookup_elem(&ka_pkt_heap_hash, &packet_id);
    if (!p) return 1;

    /* Validate packet size. */
    __u32 tot_len = skb->len;
    if (tot_len == 0 || tot_len > PKT_MAX_LEN) {
        ret = 1;
        goto cleanup;
    }

    p->timestamp   = bpf_ktime_get_ns();
    p->cgroup_id   = cgroup_id;
    p->id          = packet_id;
    p->tot_len     = tot_len;
    p->counter     = tot_len;
    p->direction   = direction;
    p->num         = 0;
    p->len         = 0;
    p->last        = 0;
    p->ip_hdr_type = bpf_ntohs(skb->protocol);

#pragma unroll
    for (__u32 i = 0; (i < (PKT_MAX_LEN / PKT_PART_LEN)) && p->counter; i++) {
        p->len     = (p->counter <= PKT_PART_LEN) ? p->counter : PKT_PART_LEN;
        p->num     = i;
        p->counter -= p->len;
        p->last    = (p->counter == 0) ? 1 : 0;

        /* Verifier-friendly: branch on exact vs. partial chunk. */
        if (p->len == PKT_PART_LEN) {
            if (bpf_skb_load_bytes(skb, i * PKT_PART_LEN, &p->buf[0], PKT_PART_LEN) != 0) {
                ret = 1;
                goto cleanup;
            }
        } else {
            __u16 plen = p->len;
            if (plen < 1 || plen > PKT_PART_LEN) { ret = 1; goto cleanup; }
            plen -= 1; /* verifier bound */
            if (plen + 1 < sizeof(p->buf)) {
                if (bpf_skb_load_bytes(skb, i * PKT_PART_LEN, &p->buf[0], plen + 1) != 0) {
                    ret = 1;
                    goto cleanup;
                }
            }
        }

        long err = bpf_perf_event_output(skb, &ka_pkts_buffer, BPF_F_CURRENT_CPU,
                                         p, sizeof(struct ka_pkt));
        if (err && !ret) ret = (int)err;
    }

cleanup:
    bpf_map_delete_elem(&ka_pkt_heap_hash, &packet_id);
    return ret;
}

/*
 * ka_filter_packets — core handler for both ingress and egress hooks.
 *
 * 1. Resolve cgroup ID (cgroup v2: bpf_skb_cgroup_id; v1: socket cookie cache).
 * 2. Check ka_should_target_cgroup().
 * 3. Check port_exclusion_map.
 * 4. Call ka_save_packet() to chunk and emit.
 */
static __always_inline int ka_filter_packets(struct __sk_buff *skb, __u8 direction)
{
    struct bpf_sock *sk = skb->sk;
    if (!sk) return 1; /* pass: not a socket packet */

    /* Cgroup resolution. */
    __u64 cgroup_id = bpf_skb_cgroup_id(skb);
    if (cgroup_id == 0) {
        /* Fallback: look up socket-to-cgroup cache (cgroup v1 nodes). */
        __u64 cookie = bpf_get_socket_cookie(skb);
        __u64 *c = bpf_map_lookup_elem(&ka_socket_cgroups, &cookie);
        if (c && *c) {
            cgroup_id = *c;
        } else {
            return 1; /* cannot identify cgroup — skip */
        }
    } else {
        /* Cache for cgroup v1 fallback on the same node. */
        __u64 cookie = bpf_get_socket_cookie(skb);
        bpf_map_update_elem(&ka_socket_cgroups, &cookie, &cgroup_id, BPF_ANY);
    }

    /* Cgroup targeting check. */
    if (!ka_should_target_cgroup(cgroup_id)) return 1;

    /* Port exclusion check (BPF-level, loaded from port_exclusion_map). */
    if (ka_is_port_excluded(skb)) return 1;

    ka_save_packet(skb, cgroup_id, direction);
    return 1; /* always return 1 (pass) for cgroup_skb programs */
}

/* ---- Probe entry points (SEC definitions in api_observer.bpf.c) ---- */

static __always_inline int handle_ingress_packets(struct __sk_buff *skb) {
    return ka_filter_packets(skb, PKT_DIR_RECEIVED);
}

static __always_inline int handle_egress_packets(struct __sk_buff *skb) {
    return ka_filter_packets(skb, PKT_DIR_SENT);
}
