/* SPDX-License-Identifier: GPL-2.0
 * Copyright 2026 Authors of KubeArmor
 *
 * cgroup_target.h — cgroup targeting for the API Observer.
 *
 * Ported from kubeshark/tracer bpf/include/cgroups.h (GPL-3.0).
 *
 * Provides:
 *   - cgroup_ids BPF map — set of cgroup IDs to trace (pod targeting)
 *   - excluded_cgroup_ids BPF map — cgroup IDs to explicitly exclude
 *   - settings BPF map — global configuration flags
 *   - should_target_cgroup() — returns 1 if this cgroup should be observed
 */

#pragma once

/* ---- Configuration flags ---- */
#define CONFIGURATION_CAPTURE_STOPPED     (1 << 0)
#define CONFIGURATION_PASS_ALL_CGROUPS    (1 << 1)

/* Global configuration struct. Written by userspace on startup and
 * on pod targeting changes. */
struct ka_configuration {
    __u32 flags;
    __u32 _pad;
};

/* ---- BPF Maps ---- */

/* cgroup_ids — set of cgroup IDs to capture traffic from.
 * Key: cgroup_id (u64, from bpf_skb_cgroup_id or bpf_get_current_cgroup_id).
 * Value: u32 marker (value not meaningful, only existence matters).
 * Updated by userspace via CgroupController.TargetCgroup(). */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, __u64);
    __type(value, __u32);
} ka_cgroup_ids SEC(".maps");

/* excluded_cgroup_ids — cgroup IDs to explicitly skip even in PASS_ALL mode.
 * Used when some pods in a namespace need to be excluded (e.g., KubeArmor
 * system pods, Envoy proxies, etc.). */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, __u64);
    __type(value, __u32);
} ka_excluded_cgroup_ids SEC(".maps");

/* ka_settings — global control flags. Array of 1 entry, index 0. */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct ka_configuration);
} ka_settings SEC(".maps");

/* ---- Targeting Helper ---- */

/*
 * should_target_cgroup — returns 1 if cgroup_id should be observed.
 *
 * Logic:
 *   - If PASS_ALL_CGROUPS is set: observe all cgroups EXCEPT those in
 *     excluded_cgroup_ids (used when the whole cluster is targeted).
 *   - Otherwise: observe only cgroups in cgroup_ids (default selective mode).
 */
static __always_inline int ka_should_target_cgroup(__u64 cgroup_id) {
    __u32 zero = 0;
    struct ka_configuration *s = bpf_map_lookup_elem(&ka_settings, &zero);
    if (s && (s->flags & CONFIGURATION_PASS_ALL_CGROUPS)) {
        /* Pass-all mode: exclude only explicitly excluded cgroups. */
        return bpf_map_lookup_elem(&ka_excluded_cgroup_ids, &cgroup_id) ? 0 : 1;
    }
    /* Selective mode: only trace cgroups in the target set. */
    return bpf_map_lookup_elem(&ka_cgroup_ids, &cgroup_id) ? 1 : 0;
}
