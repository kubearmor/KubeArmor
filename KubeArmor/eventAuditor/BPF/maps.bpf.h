// Copyright 2021 Authors of KubeArmor
// SPDX-License-Identifier: Apache-2.0

#ifndef __MAPS_BPF_H
#define __MAPS_BPF_H

#include "vmlinux.h"
#include "shared.h"

struct pattern_key {
	char pattern[PATTERN_MAX_LEN];
};

struct pattern_value {
	__u32 pattern_id;
};

struct process_spec_key {
	__u32 pid_ns;
	__u32 mnt_ns;
	__u32 pattern_id;
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

#endif /* __MAPS_BPF_H */
