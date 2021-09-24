// SPDX-License-Identifier: GPL-2.0
// Copyright 2021 Authors of KubeArmor

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#include "maps.bpf.h"

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, uint32_t);
	__type(value, uint32_t);
	__uint(max_entries, 1 << 10);
} ka_ea_event_map SEC(".maps");

char LICENSE[] SEC("license") = "GPL";
