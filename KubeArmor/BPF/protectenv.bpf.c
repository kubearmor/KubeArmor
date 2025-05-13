// +build ignore
/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2023 Authors of KubeArmor */

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

struct pathname {
  char path[256];
};

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

  char path[PATH_BUF_SIZE] = {};
  bpf_d_path(&file->f_path, path, sizeof(path));

  if (!isProcDir(path)) {
    return 0;
  }

  long envpid;
  int count = strtol(path + sizeof(DIR_PROC) - 1, 10, &envpid);
  if (count < 0) {
    return 0;
  }
  u8 envstart = sizeof(DIR_PROC) + count - 1;
  if (envstart < 80 && !isEnviron(path + envstart)) {
    return 0;
  }

  long pid = get_task_ns_tgid(t);

  if (envpid != pid) {
    struct pathname path_data = {};
    
    struct file *file_p = get_task_file(t);   
    if (file_p == NULL)
      return 0;

    bufs_t *path_buf = get_buf(PATH_BUFFER);
    if (path_buf == NULL)
      return 0;

    struct path f_src = BPF_CORE_READ(file_p, f_path);
    if (!prepend_path(&f_src, path_buf)){
      return 0;
    } else {
      u32 *path_offset = get_buf_off(PATH_BUFFER);
      if (path_offset == NULL)
        return 0;
      void *path_ptr = &path_buf->buf[*path_offset];
      bpf_probe_read_str(path_data.path, MAX_STRING_SIZE, path_ptr);
    }

    event *event_data;
    event_data = bpf_ringbuf_reserve(&events, sizeof(event), 0);

    if (!event_data) {
      return 0;
    }

    __builtin_memset(event_data->data.path, 0, sizeof(event_data->data.path));
    __builtin_memset(event_data->data.source, 0, sizeof(event_data->data.source));

    bpf_probe_read_str(event_data->data.path, 80, path);
    bpf_probe_read_str(event_data->data.source, MAX_STRING_SIZE, path_data.path);
    
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