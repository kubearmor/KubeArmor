// SPDX-License-Identifier: GPL-2.0
// Copyright 2021 Authors of KubeArmor

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#include "maps.bpf.h"

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 1 << 16);
} ka_ea_event_jmp_table SEC(".maps");

char LICENSE[] SEC("license") = "GPL";
