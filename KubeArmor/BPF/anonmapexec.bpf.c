// +build ignore
/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2023 Authors of KubeArmor */

#include "shared.h"

#define PROT_EXEC 0x4  /* page can be executed */
#define MAP_ANONYMOUS 0x20
#define MAP_ANON MAP_ANONYMOUS

#define S_IFIFO 0010000

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 24);
} events SEC(".maps");

typedef struct {
  u64 ts;

  u32 pid_id;
  u32 mnt_id;

  u32 host_ppid;
  u32 host_pid;

  u32 ppid;
  u32 pid;
  u32 uid;

  u32 event_id;
  s64 retval;

  u8 comm[TASK_COMM_LEN];

  unsigned long args[6];
} mmap_event;

static __always_inline u32 init_mmap_context(mmap_event *event_data) {
  struct task_struct *task = (struct task_struct *)bpf_get_current_task();

  event_data->ts = bpf_ktime_get_ns();

  event_data->host_ppid = get_task_ppid(task);
  event_data->host_pid = bpf_get_current_pid_tgid() >> 32;

  u32 pid = get_task_ns_tgid(task);
  if (event_data->host_pid == pid) { // host
    event_data->pid_id = 0;
    event_data->mnt_id = 0;

    event_data->ppid = get_task_ppid(task);
    event_data->pid = bpf_get_current_pid_tgid() >> 32;
  } else { // container
    event_data->pid_id = get_task_pid_ns_id(task);
    event_data->mnt_id = get_task_mnt_ns_id(task);

    event_data->ppid = get_task_ns_ppid(task);
    event_data->pid = pid;
  }

  event_data->uid = bpf_get_current_uid_gid();

  // Clearing array to avoid garbage values
  __builtin_memset(event_data->comm, 0, sizeof(event_data->comm));
  bpf_get_current_comm(&event_data->comm, sizeof(event_data->comm));

  return 0;
}


// Force emitting struct mmap_event into the ELF.
const mmap_event *unused __attribute__((unused));

struct preset_map kubearmor_anon_map_exec_preset_containers SEC(".maps");


SEC("lsm/mmap_file")
int BPF_PROG(enforce_mmap_file, struct file *file, unsigned long reqprot,
	 unsigned long prot, unsigned long flags){

  struct task_struct *t = (struct task_struct *)bpf_get_current_task();

  struct outer_key okey;
  get_outer_key(&okey, t);

  u32 *present = bpf_map_lookup_elem(&kubearmor_anon_map_exec_preset_containers, &okey);

  if (!present) {
    return 0;
  }

  // only if PROT_EXEC is assigned
  if (prot & PROT_EXEC) {
    if (flags & MAP_ANONYMOUS) {
      mmap_event *event_data;
      event_data = bpf_ringbuf_reserve(&events, sizeof(mmap_event), 0);

      if (!event_data) {
      return 0;
      }

      init_mmap_context(event_data);

      __builtin_memset(event_data->args, 0, sizeof(event_data->args));

      event_data->args[0] = reqprot;
      event_data->args[1] = prot;
      event_data->args[2] = flags;
      event_data->event_id = ANON_MAP_EXEC;
      if (*present == BLOCK) {
        event_data->retval = -EPERM;
      } else {
        event_data->retval = 0;
      }
      bpf_ringbuf_submit(event_data, 0);
      // mapping not backed by any file with executable permission, denying mapping
      if (*present == BLOCK) {
        return -EPERM;
      } else {
        return 0;
      }
    }
  }
  return 0;
}