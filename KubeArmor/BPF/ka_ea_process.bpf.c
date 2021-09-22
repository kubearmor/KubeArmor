// SPDX-License-Identifier: GPL-2.0
// Copyright 2021 Authors of KubeArmor

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#include "maps.bpf.h"

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct pattern_key);
	__type(value, struct pattern_value);
	__uint(max_entries, 1 << 10);
} ka_ea_pattern_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct process_spec_key);
	__type(value, struct process_spec_value);
	__uint(max_entries, 1 << 10);
} ka_ea_process_spec_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct process_filter_key);
	__type(value, struct process_filter_value);
	__uint(max_entries, 1 << 10);
} ka_ea_process_filter_map SEC(".maps");

// get_task_context fills *tctx with task and event data;
// with latter only if it's not NULL
static __always_inline
long get_task_context(struct task_context *tctx,
					  const struct trace_event_raw_sched_process_exec *ectx)
{
	if (!tctx)
		return -1;

	long ret;

	ret = bpf_get_current_comm(&tctx->comm, sizeof(tctx->comm));
	if (ret < 0)
		return ret;

	struct task_struct *task;
	u64 id;

	task = (struct task_struct *) bpf_get_current_task();
	tctx->pid_ns = BPF_CORE_READ(task, nsproxy, pid_ns_for_children, ns).inum;
	tctx->mnt_ns = BPF_CORE_READ(task, nsproxy, mnt_ns, ns).inum;
	id = bpf_get_current_pid_tgid();
	tctx->pid = id >> 32;
	tctx->tid = (u32) id;

	if (!ectx)
		return 0;
	ret = bpf_core_read_str(&tctx->filename, sizeof(tctx->filename),
							get_dynamic_array(ectx, filename));
	if (ret < 0)
		return ret;

	return 0;
}

// basename returns pointer from a filename basename if filename is a path,
// otherwise returns filename pointer
static __always_inline
const char *basename(const char *filename)
{
	if (!filename)
		return NULL;

	const char *base = filename;

	// we should iterate up to i < MAX_FILENAME_LEN,
	// but increasing loop iterations results in "BPF program is too large"
	for (int i = 0; i < 32; i++) {
		if (!filename[i])
			break;
		if (filename[i] == '/')
			base = filename + i;
	}

	if (base == filename)
		return filename;

	base++;
	if (!*base)
		return filename;

	return base;
}

// task_auditable checks if task must be audited
static __always_inline
bool task_auditable(const struct task_context *tctx)
{
	if (!tctx)
		return false;

	struct pattern_value *pvalue;

	// we are just checking if a plain process filename (base) is auditable,
	// disregarding globs
	pvalue = bpf_map_lookup_elem(&ka_ea_pattern_map, basename(tctx->filename));
	if (!pvalue)
		return false;

	struct process_spec_key pskey = {
		.pid_ns     = tctx->pid_ns,
		.mnt_ns     = tctx->mnt_ns,
		.pattern_id = pvalue->pattern_id,
	};

	return !!bpf_map_lookup_elem(&ka_ea_process_spec_map, &pskey);
}

// task_audited checks if task is being audited
static __always_inline
bool task_audited(const struct task_context *tctx)
{
	if (!tctx)
		return false;

	struct process_filter_key pfkey = {
		.pid_ns   = tctx->pid_ns,
		.mnt_ns   = tctx->mnt_ns,
		.host_pid = tctx->pid,
	};

	return !!bpf_map_lookup_elem(&ka_ea_process_filter_map, &pfkey);
}

// set_task_for_audit set task for audit updating process filter map
static __always_inline
long set_task_for_audit(const struct task_context *tctx)
{
	if (!tctx)
		return 0;

	struct process_filter_key pfkey = {
		.pid_ns   = tctx->pid_ns,
		.mnt_ns   = tctx->mnt_ns,
		.host_pid = tctx->pid,
	};

	struct process_filter_value pfvalue = {
		.inspect = true,
	};

	return bpf_map_update_elem(&ka_ea_process_filter_map, &pfkey, &pfvalue, BPF_ANY);
}

// unset_task_for_audit unset task for audit deleting from process filter map
static __always_inline
long unset_task_for_audit(const struct task_context *tctx)
{
	if (!tctx)
		return 0;

	struct process_filter_key pfkey = {
		.pid_ns   = tctx->pid_ns,
		.mnt_ns   = tctx->mnt_ns,
		.host_pid = tctx->pid,
	};

	return bpf_map_delete_elem(&ka_ea_process_filter_map, &pfkey);
}

SEC("tp/sched/sched_process_exec")
int ka_ea_sched_process_exec(struct trace_event_raw_sched_process_exec *ectx)
{
	struct task_context tctx = {};

	if (get_task_context(&tctx, ectx) < 0)
		return 0;

	if (!task_auditable(&tctx))
		return 0;

	if (set_task_for_audit(&tctx) < 0)
		bpf_printk("[ka-ea]: failure setting for audit");
	else
		bpf_printk("[ka-ea]: set for audit");

	return 0;
}

SEC("tp/sched/sched_process_exit")
int ka_ea_sched_process_exit(struct trace_event_raw_sched_process_template *ectx)
{
	struct task_context tctx = {};

	if (get_task_context(&tctx, NULL) < 0)
		return 0;

	// disregard threads
	if (tctx.pid != tctx.tid)
		return 0;

	if (!task_audited(&tctx))
		return 0;

	if (unset_task_for_audit(&tctx) < 0)
		bpf_printk("[ka-ea]: failure unsetting for audit");
	else
		bpf_printk("[ka-ea]: unset for audit");

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
