// +build ignore
/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2026 Authors of KubeArmor */

#include "shared.h"

const event *unused __attribute__((unused));

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 24);
} events SEC(".maps");

struct preset_map kubearmor_protectenv_preset_containers SEC(".maps");

#define DIR_PROC "/proc/"
#define FILE_ENVIRON "/environ"
#define PATH_BUF_SIZE 80

static __always_inline int isProcDir(char *path) {
  return string_prefix_match(path, DIR_PROC, sizeof(DIR_PROC));
}

static __always_inline int isEnviron(char *path) {
  return string_prefix_match(path, FILE_ENVIRON, sizeof(FILE_ENVIRON));
}

SEC("lsm/file_open")
int BPF_PROG(env_preset_enforce_file, struct file *file) {

  struct task_struct *t = (struct task_struct *)bpf_get_current_task();

  struct outer_key okey;
  get_outer_key(&okey, t);

  u32 *present = bpf_map_lookup_elem(&kubearmor_protectenv_preset_containers, &okey);

  if (!present) {
    return 0;
  }

  u64 id = bpf_get_current_pid_tgid();
  u32 tgid = id >> 32;

  bufs_k *path_store = get_full_path_from_file_ptr(file);
  if (path_store == NULL){
    return 0;
  }

  if (!isProcDir(path_store->path)) {
    return 0;
  }

  long envpid;
  int count = strtol(path_store->path + sizeof(DIR_PROC) - 1, 10, &envpid);
  if (count < 0) {
    return 0;
  }
  u8 envstart = sizeof(DIR_PROC) + count - 1;
  if (envstart < 80 && !isEnviron(path_store->path + envstart)) {
    return 0;
  }

  long pid = get_task_ns_tgid(t);

  if (envpid != pid) {
    
    struct file *file_p = get_task_file(t);  
    if (file_p == NULL)
      return 0;

    bufs_k *source_store = get_full_path_from_file_ptr(file_p);
    if (source_store == NULL){
      return 0;
    }

    event *event_data;
    event_data = bpf_ringbuf_reserve(&events, sizeof(event), 0);

    if (!event_data) {
      return 0;
    }

    __builtin_memset(event_data->data.path, 0, sizeof(event_data->data.path));
    __builtin_memset(event_data->data.source, 0, sizeof(event_data->data.source));

    bpf_probe_read_str(event_data->data.path, 80, path_store->path);
    bpf_probe_read_str(event_data->data.source, MAX_STRING_SIZE, source_store->path);
    
    init_context(event_data);
    event_data->event_id = PROTECT_ENV;
    
    if (*present == BLOCK) {
      event_data->retval = -13;
      bpf_ringbuf_submit(event_data, 0);
      return -EPERM;
    } else {
      event_data->retval = 0;
      bpf_ringbuf_submit(event_data, 0);
      return 0;
    }
  }
  return 0;
}