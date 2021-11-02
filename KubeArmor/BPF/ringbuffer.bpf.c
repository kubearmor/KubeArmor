// SPDX-License-Identifier: GPL-2.0
// Copyright 2021 Authors of KubeArmor

#include "common.bpf.h"

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24 );
} ka_ea_ringbuff_map SEC(".maps");

char LICENSE[] SEC("license") = "GPL";
