// +build ignore
/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2023 Authors of KubeArmor */

#include "shared.h"


struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 24);
} events SEC(".maps");


// Force emitting struct mmap_event into the ELF.
const event *unused __attribute__((unused));

struct preset_map kubearmor_fileless_exec_preset_containers SEC(".maps");

#define MEMFD "memfd:"
#define RUN_SHM "/run/shm/"
#define DEV_SHM "/dev/shm/"

static __always_inline int is_memfd(char *name) {
  return string_prefix_match(name, MEMFD, sizeof(MEMFD));
}

static __always_inline int is_run_shm(char *name) {
  return string_prefix_match(name, RUN_SHM, sizeof(RUN_SHM));
}

static __always_inline int is_dev_shm(char *name) {
  return string_prefix_match(name, DEV_SHM, sizeof(DEV_SHM));
}

struct pathname {
  char path[256];
};

SEC("lsm/bprm_check_security")
int BPF_PROG(fileless_preset_bprm_check_security, struct linux_binprm *bprm){

  struct task_struct *t = (struct task_struct *)bpf_get_current_task();

  struct outer_key okey;
  get_outer_key(&okey, t);

  u32 *present = bpf_map_lookup_elem(&kubearmor_fileless_exec_preset_containers, &okey);

  if (!present) {
    return 0;
  }

  struct pathname path_data = {};

  struct file *file = BPF_CORE_READ(bprm, file);
  if (file == NULL)
    return 0;

  bufs_t *path_buf = get_buf(PATH_BUFFER);
  if (path_buf == NULL)
    return 0;

  // prepend path is needed to capture /dev/shm and /run/shm paths
  if (!prepend_path(&(file->f_path), path_buf)){
    // memfd files have no path in the filesystem -> extract their name
    struct dentry *dentry = BPF_CORE_READ(&file->f_path, dentry);
    struct qstr d_name = BPF_CORE_READ(dentry, d_name);
    bpf_probe_read_kernel_str(path_data.path, MAX_STRING_SIZE, (void *) d_name.name);
  } else {
    u32 *path_offset = get_buf_off(PATH_BUFFER);
    if (path_offset == NULL)
      return 0;

    void *path_ptr = &path_buf->buf[*path_offset];
    bpf_probe_read_str(path_data.path, MAX_STRING_SIZE, path_ptr);
  }

  const char *filename = BPF_CORE_READ(bprm, filename);

  if (is_memfd(path_data.path) || is_run_shm(path_data.path) || is_dev_shm(path_data.path)) {
    event *event_data;
    event_data = bpf_ringbuf_reserve(&events, sizeof(event), 0);

    if (!event_data) {
      return 0;
    }

    __builtin_memset(event_data->data.path, 0, sizeof(event_data->data.path));
    __builtin_memset(event_data->data.source, 0, sizeof(event_data->data.source));

    bpf_probe_read_str(event_data->data.path, MAX_STRING_SIZE, path_data.path);
    bpf_probe_read_str(event_data->data.source, MAX_STRING_SIZE, filename);
    
    init_context(event_data);
    event_data->event_id = FILELESS_EXEC;
    
    // mapping not backed by any file with executable permission, denying mapping
    if (*present == BLOCK) {
      event_data->retval = -13;
      bpf_ringbuf_submit(event_data, 0);
      // bpf_printk("[bprm] fileless execution detected with pid %d, denying execution", event_data->pid);
      return -13;
    } else {
      event_data->retval = 0;
      bpf_ringbuf_submit(event_data, 0);
      return 0;
    }
  }
  
  return 0;
}