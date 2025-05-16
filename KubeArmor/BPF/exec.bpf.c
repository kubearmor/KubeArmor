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

struct preset_map kubearmor_exec_preset_containers SEC(".maps");

struct pathname {
    char path[256];
    char source[256];
};

SEC("lsm/bprm_check_security")
int BPF_PROG(exec_preset_bprm_check_security, struct linux_binprm *bprm){

  struct task_struct *t = (struct task_struct *)bpf_get_current_task();

  struct outer_key okey;
  get_outer_key(&okey, t);

  u32 *present = bpf_map_lookup_elem(&kubearmor_exec_preset_containers, &okey);

  if (!present) {
    return 0;
  }

  // currently exec preset only target execution with tty attached
  // check if tty is attached
  struct signal_struct *signal; 
  bpf_probe_read(&signal, sizeof(signal), &t->signal);
  if (signal != NULL){
      struct tty_struct *tty;
      bpf_probe_read(&tty, sizeof(tty), &signal->tty);
      if (tty == NULL){
          return 0;
      }
  } else {
    return 0;
  }

  u32 host_pid = bpf_get_current_pid_tgid() >> 32;
  u64 *exec_id = bpf_map_lookup_elem(&kubearmor_exec_pids, &host_pid);
  if (!exec_id) {
    return 0;
  }


  u32 zero = 0;
  bufs_k *z = bpf_map_lookup_elem(&bufk, &zero);
  if (z == NULL)
    return 0;

  u32 one = 1;
  bufs_k *store = bpf_map_lookup_elem(&bufk, &one);
  if (store == NULL)
    return 0;

  bpf_map_update_elem(&bufk, &one, z, BPF_ANY);

  u32 two = 2;
  bufs_k *pk = bpf_map_lookup_elem(&bufk, &two);
  if (pk == NULL)
    return 0;

  struct file *file = BPF_CORE_READ(bprm, file);
  if (file == NULL)
    return 0;

  bufs_t *path_buf = get_buf(PATH_BUFFER);
  if (path_buf == NULL)
    return 0;

  if (!prepend_path(&(file->f_path), path_buf)){
    return 0;
  } else {
    u32 *path_offset = get_buf_off(PATH_BUFFER);
    if (path_offset == NULL)
      return 0;

    void *path_ptr = &path_buf->buf[*path_offset];
    bpf_probe_read_str(store->path, MAX_STRING_SIZE, path_ptr);
  }

  struct task_struct *parent_task = BPF_CORE_READ(t, parent);
  struct file *file_p = get_task_file(parent_task);
  if (file_p == NULL)
    return 0;
  bufs_t *src_buf = get_buf(PATH_BUFFER);
  if (src_buf == NULL)
    return 0;
  struct path f_src = BPF_CORE_READ(file_p, f_path);
  if (!prepend_path(&f_src, src_buf))
    return 0;
  u32 *src_offset = get_buf_off(PATH_BUFFER);
  if (src_offset == NULL)
    return 0;
  void *src_ptr;
  if (src_buf->buf[*src_offset]) {
    src_ptr = &src_buf->buf[*src_offset];
  }
  if (src_ptr == NULL)
    return 0;
  bpf_probe_read_str(store->source, MAX_STRING_SIZE, src_ptr);

  const char *filename = BPF_CORE_READ(bprm, filename);

  event *event_data;
  event_data = bpf_ringbuf_reserve(&events, sizeof(event), 0);

  if (!event_data) {
      return 0;
  }

  __builtin_memset(event_data->data.path, 0, sizeof(event_data->data.path));
  __builtin_memset(event_data->data.source, 0, sizeof(event_data->data.source));

  bpf_probe_read_str(event_data->data.path, MAX_STRING_SIZE, store->path);
  bpf_probe_read_str(event_data->data.source, MAX_STRING_SIZE, store->source);

  init_context(event_data);
    
  event_data->event_id = EXEC;

  if (*present == BLOCK) {
      event_data->retval = -EPERM;
      bpf_ringbuf_submit(event_data, 0);
      return -EPERM;
  } 
  event_data->retval = 0;
  bpf_ringbuf_submit(event_data, 0);
  return 0;
}

