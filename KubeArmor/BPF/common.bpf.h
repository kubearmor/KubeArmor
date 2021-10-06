/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2021 Authors of KubeArmor */

#ifndef __COMMON_BPF_H
#define __COMMON_BPF_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#define __packed __attribute__((packed))

#define task_get_host_pid() ((u32)bpf_get_current_pid_tgid())

static inline u32
task_get_pid_ns(void)
{
	struct task_struct *task;
	task = (struct task_struct *) bpf_get_current_task();
	return BPF_CORE_READ(task, nsproxy, pid_ns_for_children, ns).inum;
}

static inline u32
task_get_mnt_ns(void)
{
	struct task_struct *task;
	task = (struct task_struct *) bpf_get_current_task();
	return BPF_CORE_READ(task, nsproxy, mnt_ns, ns).inum;
}

#endif /* __COMMON_BPF_H */
