// SPDX-License-Identifier: GPL-2.0
// Copyright 2021 Authors of KubeArmor

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#include "maps.bpf.h"

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct event_filter_key);
	__type(value, struct event_filter_value);
	__uint(max_entries, 1 << 10);
} ka_ea_event_filter_map SEC(".maps");

char LICENSE[] SEC("license") = "GPL";
