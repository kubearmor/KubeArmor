// +build ignore
/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2026 Authors of KubeArmor */

#include "shared.h"

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u32);
    __type(value, struct outer_key);
    __uint(max_entries, 10240);
} ns_transition SEC(".maps");

static __always_inline void save_cmd_args_to_buffer(const char *const *ptr)
{
    struct cmd_args_key key;
    key.tgid = bpf_get_current_pid_tgid();

#pragma unroll
    for (u8 i = 0; i <= MAX_STR_ARR_ELEM; i++)
    {
        key.ind = i;
        const char *const *curr_ptr = (void *)&ptr[i];
        const char *argp = NULL;
        bpf_probe_read(&argp, sizeof(argp), curr_ptr);
        if (argp)
        {
            struct argVal temp;
            bpf_probe_read_str(&temp.argsArray, sizeof(temp.argsArray), argp);
            bpf_map_update_elem(&kubearmor_args_store, &key, &temp, BPF_ANY);
        }
        else
        {
            break;
        }
    }
}

SEC("kprobe/__x64_sys_execve")
int kprobe__args_execve(struct pt_regs *ctx)
{
    struct pt_regs *ctx2 = (struct pt_regs *)PT_REGS_PARM1(ctx);
    unsigned long argv = READ_KERN(PT_REGS_PARM2(ctx2));

    if (get_kubearmor_config(_MATCH_ARGS))
    {
        save_cmd_args_to_buffer((const char *const *)argv);
    }
    return 0;
}

struct tracepoint_raw_sys_enter
{
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    long id;
    unsigned long args[6];
};

SEC("tracepoint/syscalls/sys_enter_setns")
int sys_enter_setns(struct tracepoint_raw_sys_enter *ctx)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    struct task_struct *t = (struct task_struct *)bpf_get_current_task();

    struct outer_key data = {};
    data.pid_ns = get_task_pid_ns_id(t);
    data.mnt_ns = get_task_mnt_ns_id(t);

    bpf_map_update_elem(&ns_transition, &pid, &data, BPF_ANY);

    return 0;
}

struct tracepoint_raw_sys_exit
{
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    int __syscall_nr;
    long ret;
};

SEC("tracepoint/syscalls/sys_exit_setns")
int sys_exit_setns(struct tracepoint_raw_sys_exit *ctx)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    struct outer_key *pre_ns_data;

    pre_ns_data = bpf_map_lookup_elem(&ns_transition, &pid);
    if (!pre_ns_data)
        return 0;

    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    u32 new_pid_ns = get_task_pid_ns_id(t);
    u32 new_mnt_ns = get_task_mnt_ns_id(t);

    if (pre_ns_data->mnt_ns != new_mnt_ns ||
        pre_ns_data->pid_ns != new_pid_ns)
    {

        struct outer_key key = {};
        key.mnt_ns = new_mnt_ns;
        key.pid_ns = new_pid_ns;

        void *matches = bpf_map_lookup_elem(&kubearmor_containers, &key);
        u64 exec_id = bpf_ktime_get_ns() | pid;
        if (matches)
        {
            bpf_map_update_elem(&kubearmor_exec_pids, &pid, &exec_id, BPF_ANY);
        }
    }
    bpf_map_delete_elem(&ns_transition, &pid);
    return 0;
}

struct tracepoint_sched_process_fork
{
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;

    char parent_comm[16];
    pid_t parent_pid;
    char child_comm[16];
    pid_t child_pid;
};

SEC("tracepoint/sched/sched_process_fork")
int sched_process_fork(struct tracepoint_sched_process_fork *ctx)
{
    u32 parent_pid = bpf_get_current_pid_tgid() >> 32;
    u32 child_pid = ctx->child_pid;

    u32 *exists = bpf_map_lookup_elem(&kubearmor_exec_pids, &parent_pid);
    if (exists)
    {
        u32 val = *exists;
        bpf_map_update_elem(&kubearmor_exec_pids, &child_pid, &val, BPF_ANY);
    }

    return 0;
}

struct tracepoint_sched_process_exit
{
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;

    char comm[16];
    pid_t pid;
    int prio;
};

SEC("tracepoint/sched/sched_process_exit")
int sched_process_exit(struct tracepoint_sched_process_exit *ctx)
{
    u64 tgid = bpf_get_current_pid_tgid();
    bpf_map_delete_elem(&kubearmor_exec_pids, &tgid);
    return 0;
}
