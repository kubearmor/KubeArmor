// +build ignore
/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2023 Authors of KubeArmor */

#include "shared.h"

const event *unused __attribute__((unused));

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 24);
} events SEC(".maps");

struct preset_map protectproc_preset_containers SEC(".maps");

#define DIR_PROC "/proc/"

static __always_inline int isProcDir(char *path) {
  return string_prefix_match(path, DIR_PROC, sizeof(DIR_PROC));
}

struct pathname {
  char path[256];
};

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __type(key, u64);
  __type(value, struct pathname);
  __uint(max_entries, 1024);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} proc_file_access SEC(".maps");

SEC("lsm/file_open")
int BPF_PROG(enforce_file, struct file *file) {

  struct task_struct *t = (struct task_struct *)bpf_get_current_task();

  struct outer_key okey;
  get_outer_key(&okey, t);

  u32 *present = bpf_map_lookup_elem(&protectproc_preset_containers, &okey);

  if (!present) {
    return 0;
  }

  u64 id = bpf_get_current_pid_tgid();
  u32 tgid = id >> 32;

  char path[80] = {};
  bpf_d_path(&file->f_path, path, 80);

  if (!isProcDir(path)) {
    struct pathname *sym = bpf_map_lookup_elem(&proc_file_access, &tgid);
    if (sym) {
        bpf_probe_read((void *)path, sizeof(path), &sym->path);
    } else {
      bpf_map_delete_elem(&proc_file_access, &id);
      return 0;
    }
  }
  bpf_map_delete_elem(&proc_file_access, &id);

  long procpid;
  int count = strtol(path + sizeof(DIR_PROC) - 1, 10, &procpid);
  if (count < 0) {
    return 0;
  }

  long pid = get_task_ns_tgid(t);
  if (procpid != pid) {
    struct pathname src = {};
    
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
      bpf_probe_read_str(src.path, MAX_STRING_SIZE, path_ptr);
    }

    event *event_data;
    event_data = bpf_ringbuf_reserve(&events, sizeof(event), 0);

    if (!event_data) {
      return 0;
    }

    __builtin_memset(event_data->data.path, 0, sizeof(event_data->data.path));
    __builtin_memset(event_data->data.source, 0, sizeof(event_data->data.source));

    bpf_probe_read_str(event_data->data.path, 80, path);
    bpf_probe_read_str(event_data->data.source, MAX_STRING_SIZE, src.path);
    
    init_context(event_data);
    event_data->event_id = PROTECT_PROC;
    
    if (*present == BLOCK) {
      event_data->retval = -EPERM;
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