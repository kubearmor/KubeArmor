/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2022 Authors of KubeArmor */

#ifndef KBUILD_MODNAME
#define KBUILD_MODNAME "kubearmor_syscall_check"
#endif

#ifdef BTF_SUPPORTED
#include "vmlinux.h"
#else
#include <linux/bpf.h>
#endif

#include <bpf_helpers.h>

// CFlag=-DTRACEPOINT_EXIT_OPENAT
SEC("tracepoint/syscalls/sys_exit_openat")
int sys_exit_openat(struct pt_regs *ctx){
        return 0;
}
