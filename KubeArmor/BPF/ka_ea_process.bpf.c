// SPDX-License-Identifier: GPL-2.0
// Copyright 2021 Authors of KubeArmor

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#include "maps.bpf.h"

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__type(key, u32);
	__type(value, u32);
	__uint(max_entries, 2);
} ka_ea_process_jmp_map SEC(".maps");

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

unsigned int pid;
unsigned int tid;
unsigned int pid_ns;
unsigned int mnt_ns;
char comm[TASK_COMM_LEN];
char filename[MAX_FILENAME_LEN];
u32 pattern_id;

// get_task_filename fills global variable (.bss map) with task filename
static
long get_task_filename(const struct trace_event_raw_sched_process_exec *ctx)
{
	long ret;

	ret = bpf_core_read_str(filename, sizeof(filename),
				get_dynamic_array(ctx, filename));
	if (ret < 0)
		return ret;

	return 0;
}

// get_task_ids fills global variables (.bss map) with task ids
static
long get_task_ids(const struct trace_event_raw_sched_process_exec *ctx)
{
	long ret;

	ret = bpf_get_current_comm(comm, sizeof(comm));
	if (ret < 0)
		return ret;

	u64 id;

	id = bpf_get_current_pid_tgid();
	pid = id >> 32;
	tid = (u32) id;

	struct task_struct *task;

	task = (struct task_struct *) bpf_get_current_task();
	pid_ns = BPF_CORE_READ(task, nsproxy, pid_ns_for_children, ns).inum;
	mnt_ns = BPF_CORE_READ(task, nsproxy, mnt_ns, ns).inum;

	return 0;
}

// match was inspired by the Krauss and Kurts wildcard algorithms
// https://github.com/kirkjkrauss/MatchingWildcards/blob/master/Listing1.cpp
// http://dodobyte.com/wildcard.html
static
bool match(const char *pat, const char *str)
{
	int i = 0;
	int j = 0;
	int str_track = -1;
	int pat_track = -1;

	while (j < MAX_PATTERN_LEN) {
		// this check makes verifier happy
		if (i >= MAX_FILENAME_LEN)
			return false;
		if (!pat[j] && !str[i])
			return true;

		if (pat[j] == '*') {
			if (!str[i]) {
				while (j < MAX_PATTERN_LEN-1 && pat[j] == '*')
					j++;
				return !pat[j];
			}
			str_track = i;
			pat_track = j;
			j++;
			continue;
		}

		if (pat[j] != '?' && pat[j] != str[i]) {
			if (pat_track == -1)
				return false;
			str_track++;
			i = str_track;
			j = pat_track;
			continue;
		}

		i++;
		j++;
	}

	return false;
}

// callback_ctx struct is used as check_hash_elem handler input/output
struct callback_ctx {
	const char *filename;
	struct pattern_value *pvalue;
};

// check_hash_elem is the handler required by bpf_for_each_map_elem iterator
static
u64 check_hash_elem(struct bpf_map *map,
		    struct pattern_key *key, struct pattern_value *val,
		    struct callback_ctx *data)
{
	if (!key || !val || !data)
		return 0;

	if (match(key->pattern, data->filename)) {
		data->pvalue->pattern_id = val->pattern_id;
		return 1; // stop the iteration
	}

	return 0;
}

// task_auditable checks if task must be audited (phase 0)
static
bool task_auditable_0(void)
{
	struct pattern_value pvalue = {
		.pattern_id = 0,
	};
	struct callback_ctx data = {
		.filename = (const char *) &filename,
		.pvalue = &pvalue,
	};

	// https://lwn.net/Articles/846504/
	long elem_num = bpf_for_each_map_elem(&ka_ea_pattern_map,
					      check_hash_elem, &data, 0);
	if (elem_num < 0 || !data.pvalue->pattern_id)
		return false;

	pattern_id = data.pvalue->pattern_id;

	return true;
}

// task_auditable checks if task must be audited (phase 1)
static
bool task_auditable_1(const struct trace_event_raw_sched_process_exec *ctx)
{
	if (get_task_ids(ctx) < 0)
		return false;

	struct process_spec_key pskey = {
		.pid_ns     = pid_ns,
		.mnt_ns     = mnt_ns,
		.pattern_id = pattern_id,
	};

	return !!bpf_map_lookup_elem(&ka_ea_process_spec_map, &pskey);
}

// set_task_for_audit set task for audit updating process filter map
static
long set_task_for_audit(void)
{
	struct process_filter_key pfkey = {
		.pid_ns   = pid_ns,
		.mnt_ns   = mnt_ns,
		.host_pid = pid,
	};

	struct process_filter_value pfvalue = {
		.inspect = true,
	};

	return bpf_map_update_elem(&ka_ea_process_filter_map, &pfkey, &pfvalue, BPF_ANY);
}

SEC("tp/sched/sched_process_exec/1")
int ka_ea_sched_process_exec_1(struct trace_event_raw_sched_process_exec *ctx)
{
	if (!task_auditable_1(ctx))
		return 0;

	if (set_task_for_audit() < 0)
		bpf_printk("[ka-ea-process]: failure setting %s for audit", filename);
	else
		bpf_printk("[ka-ea-process]: %s set for audit", filename);

	return 0;
}

SEC("tp/sched/sched_process_exec/0")
int ka_ea_sched_process_exec_0(struct trace_event_raw_sched_process_exec *ctx)
{
	if (!task_auditable_0())
		return 0;

	bpf_tail_call(ctx, &ka_ea_process_jmp_map, 1);

	return 0;
}

SEC("tp/sched/sched_process_exec")
int ka_ea_sched_process_exec(struct trace_event_raw_sched_process_exec *ctx)
{
	if (get_task_filename(ctx) < 0)
		return 0;

	// don't access the value returned from bpf_tail_call()
	// although the doc states that it is negative in case of an error,
	// one can get 'R0 !read_ok' when the call is successful
	bpf_tail_call(ctx, &ka_ea_process_jmp_map, 0);

	return 0;
}

SEC("tp/sched/sched_process_exit")
int ka_ea_sched_process_exit(struct trace_event_raw_sched_process_template *ctx)
{
	if (get_task_ids(NULL) < 0)
		return 0;

	// disregard threads
	if (pid != tid)
		return 0;

	struct process_filter_key pfkey = {
		.pid_ns   = pid_ns,
		.mnt_ns   = mnt_ns,
		.host_pid = pid,
	};

	if (!bpf_map_lookup_elem(&ka_ea_process_filter_map, &pfkey))
		return 0;

	if (bpf_map_delete_elem(&ka_ea_process_filter_map, &pfkey) < 0)
		bpf_printk("[ka-ea-process]: failure unsetting %u for audit", pid);
	else
		bpf_printk("[ka-ea-process]: %u unset for audit", pid);

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
