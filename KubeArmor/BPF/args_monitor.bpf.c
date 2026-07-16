// +build ignore
/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2026 Authors of KubeArmor */

#include "shared.h"

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