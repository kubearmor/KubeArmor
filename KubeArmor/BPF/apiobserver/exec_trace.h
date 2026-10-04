/* SPDX-License-Identifier: GPL-2.0
 * Copyright 2026 Authors of KubeArmor
 *
 * exec_trace.h — Exec-triggered SSL uprobe attachment.
 *
 * Problem: the 30-second /proc poll misses ephemeral processes (curl, wget)
 * that exit before the next scan tick. This header wires up two BPF programs
 * that together fire immediately after any execve() completes on the host:
 *
 *   1. raw_tracepoint/sched_process_fork  — fires on fork(); saves the child's
 *      cgroup_id + tgid into ka_fork_info keyed by the child TGID.  We capture
 *      the cgroup here because it is inherited from the parent and is always
 *      correct at fork time.
 *
 *   2. kretprobe/sys_execve              — fires after execve() returns in the
 *      new binary context.  At this point all shared libraries (including
 *      libssl.so.3) are already mapped.  We look up ka_fork_info for the current
 *      TGID and emit a ka_found_pid_events perf record so the Go ExecWatcher can
 *      immediately call DiscoverSSLLibsForPID() and attach uprobes.
 *
 * Design notes (adapted from kubeshark/tracer bpf/pids_probes.c):
 *   - fork() carries the cgroup context; execve() does not reset it.
 *   - We use TGID (thread-group ID) as the map key — that is the "process ID"
 *     visible to userspace and to /proc/<pid>/maps.
 *   - hostPID: true is set on the KubeArmor DaemonSet, so bpf_get_current_pid_tgid()
 *     already returns host-namespace TGIDs.  No PID-namespace translation needed.
 *   - ka_fork_info is LRU_HASH to bound memory.  Entries are removed immediately
 *     after the matching execve, so the map stays near-empty at steady state.
 *
 * Go-side counterpart: apiObserver/exec_watcher.go → ExecWatcher.
 */

#pragma once

#include "common/macros.h"
#include "common/structs.h"

/* =========================================================================
 * Struct emitted to userspace on each successful execve.
 *
 * MUST stay in sync with kaFoundPid in exec_watcher.go.
 * ========================================================================= */
struct ka_found_pid {
    __u64 cgroup_id;  /* cgroupv2 ID of the new process */
    __u32 tgid;       /* host-namespace TGID (= PID visible in /proc) */
    __u32 __pad;
};

/* =========================================================================
 * Maps owned by this header.
 * ========================================================================= */

/* Scratch map: fork TGID → ka_found_pid.
 * Entries live from fork() until the matching execve() return.
 * LRU ensures the map self-heals if execve is never called (e.g. fork+exit). */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key,   __u32);              /* child TGID */
    __type(value, struct ka_found_pid);
} ka_fork_info SEC(".maps");

/* Perf event array: carries ka_found_pid records to the Go ExecWatcher. */
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, 1024);
    __type(key,   int);
    __type(value, __u32);
} ka_found_pid_events SEC(".maps");

/* =========================================================================
 * Program 1: raw_tracepoint/sched_process_fork
 *
 * Fires synchronously in the parent's context immediately after fork().
 * We capture the cgroup ID from the child task_struct (it inherits the
 * parent's cgroup at fork time) and stash it in ka_fork_info.
 * ========================================================================= */
SEC("raw_tracepoint/sched_process_fork")
int ka_sched_process_fork(struct bpf_raw_tracepoint_args *ctx)
{
    /* ctx->args[0] = parent task_struct*, ctx->args[1] = child task_struct* */
    struct task_struct *child = (struct task_struct *)ctx->args[1];

    /* Read the child's TGID (= its own PID in host-ns after execve). */
    __u32 child_tgid = BPF_CORE_READ(child, tgid);

    /* Capture cgroup ID from the child's task — it inherits parent's cgroup. */
    __u64 cgroup_id = bpf_get_current_cgroup_id();

    struct ka_found_pid p = {
        .cgroup_id = cgroup_id,
        .tgid      = child_tgid,
        .__pad     = 0,
    };

    bpf_map_update_elem(&ka_fork_info, &child_tgid, &p, BPF_ANY);
    return 0;
}

/* =========================================================================
 * Program 2: kretprobe/sys_execve
 *
 * Fires after execve() returns successfully in the new binary context.
 * At this point:
 *   - The ELF binary + all PT_LOAD segments are mapped.
 *   - The dynamic linker has run — libssl.so.3 (and friends) are mapped.
 *   - /proc/<tgid>/maps already contains the SSL library entries.
 *
 * We emit a ka_found_pid event so the Go ExecWatcher can immediately
 * scan /proc/<tgid>/maps and attach SSL uprobes — well within the window
 * before the first SSL_write/SSL_read call.
 *
 * Note: we use kretprobe (not raw_tracepoint/sched_process_exec) because
 * sched_process_exec fires before the ld.so runs and maps shared libs.
 * kretprobe/sys_execve fires after the binary is fully set up.
 * ========================================================================= */
SEC("kretprobe/sys_execve")
int BPF_KRETPROBE(ka_kretprobe_sys_execve)
{
    /* Only handle successful execve calls (return value 0). */
    long ret = PT_REGS_RC(ctx);
    if (ret != 0)
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid     = (__u32)(pid_tgid >> 32);

    struct ka_found_pid *p = bpf_map_lookup_elem(&ka_fork_info, &tgid);
    if (!p)
        return 0;

    /* Emit to the Go perf reader. */
    bpf_perf_event_output(ctx, &ka_found_pid_events,
                          BPF_F_CURRENT_CPU, p, sizeof(*p));

    /* Remove immediately — one execve per fork. */
    bpf_map_delete_elem(&ka_fork_info, &tgid);
    return 0;
}
