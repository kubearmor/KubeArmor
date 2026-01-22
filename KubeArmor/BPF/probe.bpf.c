// +build ignore
/* SPDX-License-Identifier: GPL-2.0    */
/* Copyright 2026 Authors of KubeArmor */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

typedef struct {
  bool exec;
} event;

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 24);
} kubearmor_events SEC(".maps");

// Force emitting struct event into the ELF.
const event *unused __attribute__((unused));

SEC("lsm/mmap_file")
int test_memfd() {
  event *task_info;

  task_info = bpf_ringbuf_reserve(&kubearmor_events, sizeof(event), 0);
  if (!task_info) {
    return 0;
  }

  task_info->exec = true;

  bpf_ringbuf_submit(task_info, 0);

  return 0;
}