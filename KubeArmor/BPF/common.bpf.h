/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2021 Authors of KubeArmor */

#ifndef __COMMON_BPF_H
#define __COMMON_BPF_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#include "shared.h"

#define __packed __attribute__((packed))

#define get_dynamic_array(entry, field) \
	((void *) entry + (entry->__data_loc_##field & 0xffff))

/* current_task structure */
struct current_task {
	u32  pid;
	u32  tid;
	u32  pid_ns;
	u32  mnt_ns;
	char comm[TASK_COMM_LEN];
	char filename[MAX_FILENAME_LEN];
	u32  filename_hash;
};

/* strlen determines the length of a fixed-size string */
static size_t
strnlen(const char *str, size_t maxlen)
{
	if (!str || !maxlen)
		return 0;
	if (maxlen == __SIZE_MAX__)
		maxlen--;

	size_t i = 0;

	while (i < maxlen && str[i])
		i++;

	return i;
}

/* task_get_host_pid returns current task host pid */
static u32
task_get_host_pid(void)
{
	return (u32) bpf_get_current_pid_tgid();
}

/* task_get_pid_ns returns current task pidns */
static u32
task_get_pid_ns(struct task_struct *task)
{
	if (!task)
		task = (struct task_struct *) bpf_get_current_task();

	return BPF_CORE_READ(task, nsproxy, pid_ns_for_children, ns).inum;
}

/* task_get_mnt_ns returns current task mntns */
static u32
task_get_mnt_ns(struct task_struct *task)
{
	if (!task)
		task = (struct task_struct *) bpf_get_current_task();

	return BPF_CORE_READ(task, nsproxy, mnt_ns, ns).inum;
}

/* task_get_filename fills dst with task filename */
static long
task_get_filename(char *dst, size_t maxlen,
		  const struct trace_event_raw_sched_process_exec *ctx)
{
	if (!dst || !ctx || !maxlen)
		return -1;

	return bpf_core_read_str(dst, maxlen, get_dynamic_array(ctx, filename));
}

/* task_get_ids fills ctask with task ids */
static inline void
task_get_ids(struct current_task *ctask)
{
	if (!ctask)
		return;

	u64 id;

	id	   = bpf_get_current_pid_tgid();
	ctask->pid = id >> 32;
	ctask->tid = (u32) id;

	struct task_struct *task;

	task	      = (struct task_struct *) bpf_get_current_task();
	ctask->pid_ns = task_get_pid_ns(task);
	ctask->mnt_ns = task_get_mnt_ns(task);
}

#endif /* __COMMON_BPF_H */
