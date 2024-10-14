// +build ignore
/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2023 Authors of KubeArmor */

#include "shared.h"

typedef struct {
  u32 pid;
  u32 pid_ns;
  u32 mnt_ns;
  char comm[80];
} pevent;

const pevent *unused __attribute__((unused));

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 24);
} events SEC(".maps");

struct preset_map protectenv_preset_containers SEC(".maps");

#define DIR_PROC "/proc/"
#define FILE_ENVIRON "/environ"

static __always_inline int isProcDir(char *path) {
  return string_prefix_match(path, DIR_PROC, sizeof(DIR_PROC));
}

static __always_inline int isEnviron(char *path) {
  return string_prefix_match(path, FILE_ENVIRON, sizeof(FILE_ENVIRON));
}

SEC("lsm/file_open")
int BPF_PROG(enforce_file, struct file *file) {

  struct task_struct *t = (struct task_struct *)bpf_get_current_task();

  struct outer_key okey;
  get_outer_key(&okey, t);

  u32 *present = bpf_map_lookup_elem(&protectenv_preset_containers, &okey);

  if (!present) {
    return 0;
  }

  u64 id = bpf_get_current_pid_tgid();
  u32 tgid = id >> 32;

  char path[80];
  bpf_d_path(&file->f_path, path, 80);

  if (!isProcDir(path)) {
    return 0;
  }

  long envpid;
  int count = bpf_strtol(path + sizeof(DIR_PROC) - 1, 10, 0, &envpid);
  if (count < 0) {
    return 0;
  }
  u8 envstart = sizeof(DIR_PROC) + count - 1;
  if (envstart < 80 && !isEnviron(path + envstart)) {
    return 0;
  }

  long pid = get_task_ns_tgid(t);

  if (envpid != pid) {

    pevent *task_info;

    task_info = bpf_ringbuf_reserve(&events, sizeof(pevent), 0);
    if (!task_info) {
      return 0;
    }
    task_info->pid = pid;
    task_info->pid_ns = okey.pid_ns;
    task_info->mnt_ns = okey.mnt_ns;
    bpf_ringbuf_submit(task_info, 0);
    return -EPERM;
  }

  return 0;
}