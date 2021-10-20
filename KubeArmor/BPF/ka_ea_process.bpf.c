// SPDX-License-Identifier: GPL-2.0
// Copyright 2021 Authors of KubeArmor

#include "common.bpf.h"
#include "maps.bpf.h"
#include "hash.h"

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct filename_key);
	__type(value, struct filename_value);
	__uint(max_entries, 1 << 10);
} ka_ea_filename_map SEC(".maps");

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

/* task_auditable checks if task must be audited */
static bool
task_auditable(const struct current_task *ctask)
{
	if (!ctask)
		return false;

	struct filename_key    fnkey;
	struct filename_value *fnvalue;

	fnkey.hash = ctask->filename_hash;
	fnvalue	   = bpf_map_lookup_elem(&ka_ea_filename_map, &fnkey);
	if (!fnvalue)
		return false;

	struct process_spec_key pskey = {
		.pid_ns	       = ctask->pid_ns,
		.mnt_ns	       = ctask->mnt_ns,
		.filename_hash = ctask->filename_hash,
	};

	return !!bpf_map_lookup_elem(&ka_ea_process_spec_map, &pskey);
}

/* task_set_for_audit set task for audit updating process filter map */
static long
task_set_for_audit(const struct current_task *ctask)
{
	if (!ctask)
		return -1;

	struct process_filter_key pfkey = {
		.pid_ns	  = ctask->pid_ns,
		.mnt_ns	  = ctask->mnt_ns,
		.host_pid = ctask->pid,
	};

	struct process_filter_value pfvalue = {
		.inspect = true,
	};

	return bpf_map_update_elem(&ka_ea_process_filter_map, &pfkey, &pfvalue,
				   BPF_ANY);
}

SEC("tp/sched/sched_process_exec")
int
ka_ea_sched_process_exec(struct trace_event_raw_sched_process_exec *ctx)
{
	struct current_task ctask = {};

	if (task_get_filename(ctask.filename, sizeof(ctask.filename), ctx) < 0)
		return 0;

	ctask.filename_hash = jenkins_hash(
		ctask.filename, strnlen(ctask.filename, MAX_FILENAME_LEN), 0);
	if (!ctask.filename_hash)
		return 0;

	if (bpf_get_current_comm(&ctask.comm, sizeof(ctask.comm)) < 0)
		return 0;

	task_get_ids(&ctask);

	if (!task_auditable(&ctask))
		return 0;

	if (task_set_for_audit(&ctask) < 0)
		bpf_printk("[ka-ea-process]: failure setting %s (%u) for audit",
			   ctask.filename, ctask.pid);
	else
		bpf_printk("[ka-ea-process]: %s (%u) set for audit",
			   ctask.filename, ctask.pid);

	return 0;
}

SEC("tp/sched/sched_process_exit")
int
ka_ea_sched_process_exit(void)
{
	struct current_task ctask = {};

	task_get_ids(&ctask);
	if (ctask.pid != ctask.tid) /* disregard threads */
		return 0;

	struct process_filter_key pfkey = {
		.pid_ns	  = ctask.pid_ns,
		.mnt_ns	  = ctask.mnt_ns,
		.host_pid = ctask.pid,
	};

	if (!bpf_map_lookup_elem(&ka_ea_process_filter_map, &pfkey))
		return 0;

	if (bpf_map_delete_elem(&ka_ea_process_filter_map, &pfkey) < 0)
		bpf_printk("[ka-ea-process]: failure unsetting %u for audit",
			   ctask.pid);
	else
		bpf_printk("[ka-ea-process]: %u unset for audit", ctask.pid);

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
