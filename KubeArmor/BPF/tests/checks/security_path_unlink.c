/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2022 Authors of KubeArmor */

#ifndef KBUILD_MODNAME
#define KBUILD_MODNAME "kubearmor_syscall_check"
#endif

#include <linux/bpf.h>
#include <bpf_helpers.h>

// CFlag=-DSECURITY_PATH
SEC("kprobe/security_path_unlink")
int kprobe__security_path_unlink(struct pt_regs *ctx){
        return 0;
}
