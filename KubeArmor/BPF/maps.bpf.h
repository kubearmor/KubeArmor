/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2021 Authors of KubeArmor */

#ifndef __MAPS_BPF_H
#define __MAPS_BPF_H

#include "vmlinux.h"
#include "shared.h"

struct filename_key {
	u32 hash;
};

struct filename_value {
	bool inspect;
};

struct pattern_key {
	char pattern[MAX_PATTERN_LEN];
};

struct pattern_value {
	__u32 pattern_id;
};

struct process_spec_key {
	u32 pid_ns;
	u32 mnt_ns;
	u32 filename_hash;
};

struct process_spec_value {
	bool inspect;
};

struct process_filter_key {
	__u32 pid_ns;
	__u32 mnt_ns;
	__u32 host_pid;
};

struct process_filter_value {
	bool inspect;
};

struct event_filter_key {
	__u32 pid_ns;
	__u32 mnt_ns;
	__u32 event_id;
};

struct event_filter_value {
	__u32 jmp_idx;
};

#endif /* __MAPS_BPF_H */
