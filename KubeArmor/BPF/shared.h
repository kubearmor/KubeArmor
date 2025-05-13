/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2023 Authors of KubeArmor */

#ifndef __SHARED_H
#define __SHARED_H

#include "vmlinux.h"
#include "vmlinux_macro.h"
#include "syscalls.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "throttling.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";
#define EPERM 13

#define MAX_BUFFER_SIZE 32768
#define MAX_STRING_SIZE 256
#define MAX_COMBINED_LENGTH 4096
#define MAX_BUFFERS 1
#define PATH_BUFFER 0
#define TASK_COMM_LEN 80
#define AUDIT_POSTURE 140
#define BLOCK_POSTURE 141
#define CAPABLE_KEY 200

enum {
  IPPROTO_ICMPV6 = 58
};

enum file_hook_type { dpath = 0, dfileread, dfilewrite };

enum deny_by_default {
  dproc = 101,
  dfile,
  dnet,
  dcap
}; // check if the list is whitelist/blacklist
enum network_check_type {
  sock_type = 2,
  sock_proto
}; // configure to check for network protocol or socket type

typedef struct buffers {
  char buf[MAX_BUFFER_SIZE];
} bufs_t;

typedef struct bufkey {
  char path[MAX_STRING_SIZE];
  char source[MAX_STRING_SIZE];
} bufs_k;

#undef container_of
#define container_of(ptr, type, member)                                        \
  ({                                                                           \
    const typeof(((type *)0)->member) *__mptr = (ptr);                         \
    (type *)((char *)__mptr - offsetof(type, member));                         \
  })
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, u32);
  __type(value, bufs_t);
  __uint(max_entries, MAX_BUFFERS);
} bufs SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, u32);
  __type(value, u32);
  __uint(max_entries, MAX_BUFFERS);
} bufs_off SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, u32);
  __type(value, bufs_k);
  __uint(max_entries, 3);
} bufk SEC(".maps");

// ============
// match prefix
// ============

static __always_inline int string_prefix_match(const char *name, const char *prefix, size_t prefix_len) {
    int i = 0;
    while (i < prefix_len - 1 && name[i] != '\0' && name[i] == prefix[i]) {
        i++;
    }
    return (i == prefix_len - 1) ? 1 : 0;
}

// ============
// == preset ==
// ============

enum preset_action {
  AUDIT = 1,
  BLOCK
};

enum preset_type {
  FILELESS_EXEC = 1001,
  ANON_MAP_EXEC,
  PROTECT_ENV,
  EXEC,
};

struct preset_map {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 256);
  __uint(key_size, sizeof(struct outer_key));
  __uint(value_size, sizeof(u32));
  __uint(pinning, LIBBPF_PIN_BY_NAME);
};

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

  bufs_k data;

  // exec event
  u64 exec_id;
} event;

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 24);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} kubearmor_events SEC(".maps");

#define RULE_EXEC 1 << 0
#define RULE_WRITE 1 << 1
#define RULE_READ 1 << 2
#define RULE_OWNER 1 << 3
#define RULE_DIR 1 << 4
#define RULE_RECURSIVE 1 << 5
#define RULE_HINT 1 << 6
#define RULE_DENY 1 << 7

#define MASK_WRITE 0x00000002
#define MASK_READ 0x00000004
#define MASK_APPEND 0x00000008

struct data_t {
  u8 processmask;
  u8 filemask;
};

enum
{
    _ALERT_THROTTLING = 3,
    _MAX_ALERT_PER_SEC = 4,
    _THROTTLE_SEC = 5,
};

struct kaconfig
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, u32);
    __uint(max_entries, 16);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
};

struct kaconfig kubearmor_config SEC(".maps");

struct outer_hash {
  __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
  __uint(max_entries, 256);
  __uint(key_size, sizeof(struct outer_key));
  __uint(value_size, sizeof(u32));
  __uint(pinning, LIBBPF_PIN_BY_NAME);
};

struct outer_hash kubearmor_containers SEC(".maps");

struct exec_pid_map
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u32);
    __type(value, u64);
    __uint(max_entries, 10240);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
};

struct exec_pid_map kubearmor_exec_pids SEC(".maps");

static __always_inline bufs_t *get_buf(int idx) {
  return bpf_map_lookup_elem(&bufs, &idx);
}

static __always_inline void set_buf_off(int buf_idx, u32 new_off) {
  bpf_map_update_elem(&bufs_off, &buf_idx, &new_off, BPF_ANY);
}

static __always_inline u32 *get_buf_off(int buf_idx) {
  return bpf_map_lookup_elem(&bufs_off, &buf_idx);
}

static inline struct mount *real_mount(struct vfsmount *mnt) {
  return container_of(mnt, struct mount, mnt);
}

static __always_inline bool prepend_path(struct path *path, bufs_t *string_p) {
  char slash = '/';
  char null = '\0';
  int offset = MAX_COMBINED_LENGTH;

  if (path == NULL || string_p == NULL) {
    return false;
  }

  struct dentry *dentry = BPF_CORE_READ(path, dentry);
  struct vfsmount *vfsmnt = BPF_CORE_READ(path, mnt);

  struct mount *mnt = real_mount(vfsmnt);

  struct dentry *parent;
  struct dentry *mnt_root;
  struct mount *m;
  struct qstr d_name;

#pragma unroll
  for (int i = 0; i < 20; i++) {
    parent = BPF_CORE_READ(dentry, d_parent);
    mnt_root = BPF_CORE_READ(vfsmnt, mnt_root);

    if (dentry == mnt_root) {
      m = BPF_CORE_READ(mnt, mnt_parent);
      if (mnt != m) {
        dentry = BPF_CORE_READ(mnt, mnt_mountpoint);
        mnt = BPF_CORE_READ(mnt, mnt_parent);
        vfsmnt = &mnt->mnt;
        continue;
      }
      break;
    }

    if (dentry == parent) {
      break;
    }

    // get d_name
    d_name = BPF_CORE_READ(dentry, d_name);

    offset -= (d_name.len + 1);
    if (offset < 0)
      break;

    int sz = bpf_probe_read_str(
        &(string_p->buf[(offset) & (MAX_COMBINED_LENGTH - 1)]),
        (d_name.len + 1) & (MAX_COMBINED_LENGTH - 1), d_name.name);
    if (sz > 1) {
      bpf_probe_read(
          &(string_p->buf[(offset + d_name.len) & (MAX_COMBINED_LENGTH - 1)]),
          1, &slash);
    } else {
      offset += (d_name.len + 1);
    }

    dentry = parent;
  }

  if (offset == MAX_COMBINED_LENGTH) {
    return false;
  }

  bpf_probe_read(&(string_p->buf[MAX_COMBINED_LENGTH - 1]), 1, &null);
  offset--;

  bpf_probe_read(&(string_p->buf[offset & (MAX_COMBINED_LENGTH - 1)]), 1,
                 &slash);
  set_buf_off(PATH_BUFFER, offset);
  return true;
}

static __always_inline long strtol(const char *buf, size_t buf_len, long *res) {
  long val = 0;
  size_t i = 0;
  size_t consumed = 0;
    
#pragma unroll
  for (int j = 0; j < 10; j++) {
    if (j >= buf_len)
      break;
    // https://github.com/torvalds/linux/blob/586de92313fcab8ed84ac5f78f4d2aae2db92c59/tools/include/nolibc/ctype.h#L65
    if (((unsigned int)buf[i] == ' ') || (unsigned int)(buf[i] - 0x09) < 5)
      i++;
    else
      break;
  }

#pragma unroll
  for (int j = 0; j < 10; j++) {
      if (j >= buf_len)
        break;
      if (i < buf_len) {
        if (buf[i] >= '0' && buf[i] <= '9') {
            val = val * 10 + (buf[i] - '0');
            i++;
            consumed++;
        } else {
            break;
        }
      }
  }
    
  *res = val;
  return consumed;
}

static __always_inline u32 get_task_pid_ns_id(struct task_struct *task) {
  return BPF_CORE_READ(task, nsproxy, pid_ns_for_children, ns).inum;
}

static __always_inline u32 get_task_mnt_ns_id(struct task_struct *task) {
  return BPF_CORE_READ(task, nsproxy, mnt_ns, ns).inum;
}

static __always_inline u32 get_task_pid_vnr(struct task_struct *task) {
  struct pid *pid = BPF_CORE_READ(task, thread_pid);
  unsigned int level = BPF_CORE_READ(pid, level);
  return BPF_CORE_READ(pid, numbers[level].nr);
}

static __always_inline u32 get_task_ns_ppid(struct task_struct *task) {
  struct task_struct *real_parent = BPF_CORE_READ(task, real_parent);
  return get_task_pid_vnr(real_parent);
}

static __always_inline u32 get_task_ns_tgid(struct task_struct *task) {
  struct task_struct *group_leader = BPF_CORE_READ(task, group_leader);
  return get_task_pid_vnr(group_leader);
}

static __always_inline u32 get_task_ppid(struct task_struct *task) {
  return BPF_CORE_READ(task, parent, pid);
}

static struct file *get_task_file(struct task_struct *task) {
  return BPF_CORE_READ(task, mm, exe_file);
}

static inline void get_outer_key(struct outer_key *pokey,
                                 struct task_struct *t) {
  pokey->pid_ns = get_task_pid_ns_id(t);
  pokey->mnt_ns = get_task_mnt_ns_id(t);
  // TODO: Use cgroup ns as well for host process identification to support enforcement on deployments using hostpidns
  // u32 cg_ns = BPF_CORE_READ(t, nsproxy, cgroup_ns, ns).inum;
  // if (pokey->pid_ns == PROC_PID_INIT_INO && cg_ns == PROC_CGROUP_INIT_INO) {
  if (pokey->pid_ns == PROC_PID_INIT_INO) {
    pokey->pid_ns = 0;
    pokey->mnt_ns = 0;
  }
}

// == Context Management == //

static __always_inline u32 init_context(event *event_data) {
  struct task_struct *task = (struct task_struct *)bpf_get_current_task();

  event_data->ts = bpf_ktime_get_ns();

  event_data->host_ppid = get_task_ppid(task);
  u32 host_pid = bpf_get_current_pid_tgid() >> 32;
  event_data->host_pid = host_pid;

  struct outer_key okey;
  get_outer_key(&okey, task);
  event_data->pid_id = okey.pid_ns;
  event_data->mnt_id = okey.mnt_ns;

  event_data->ppid = get_task_ppid(task);
  event_data->pid =  get_task_ns_tgid(task);

  event_data->uid = bpf_get_current_uid_gid();

  // Clearing array to avoid garbage values
  __builtin_memset(event_data->comm, 0, sizeof(event_data->comm));
  bpf_get_current_comm(&event_data->comm, sizeof(event_data->comm));

  // check if process is part of exec
  __builtin_memset((void *)&event_data->exec_id, 0, sizeof(event_data->exec_id));
  u64 *exec_id = bpf_map_lookup_elem(&kubearmor_exec_pids, &host_pid);
  if (exec_id) {
      event_data->exec_id = *exec_id;
  }

  return 0;
}


static __always_inline u32 get_kubearmor_config(u32 config)
{
    u32 *value = bpf_map_lookup_elem(&kubearmor_config, &config);
    if (!value)
    {
        return 0;
    }

    return *value;
}

// To check if subsequent alerts should be dropped per container
static __always_inline bool should_drop_alerts_per_container(struct outer_key okey) {
  u64 current_timestamp = bpf_ktime_get_ns();

  struct outer_key key = {
    .pid_ns = okey.pid_ns,
    .mnt_ns = okey.mnt_ns
  };

  struct alert_throttle_state *state = bpf_map_lookup_elem(&kubearmor_alert_throttle, &key);

  if (!state) {
    struct alert_throttle_state new_state = {
      .event_count = 1,
      .first_event_timestamp = current_timestamp,
      .throttle = 0
    };

    bpf_map_update_elem(&kubearmor_alert_throttle, &key, &new_state, BPF_ANY);
    return false;
  }

  u64 throttle_sec = (u64)get_kubearmor_config(_THROTTLE_SEC); 
  u64 throttle_nsec = throttle_sec * 1000000000L; 
  u64 maxAlert = (u64)get_kubearmor_config(_MAX_ALERT_PER_SEC); 

  if (state->throttle) {
    u64 time_difference = current_timestamp - state->first_event_timestamp;
    if (time_difference < throttle_nsec) {
      return true;
    }
  }

  u64 time_difference = current_timestamp - state->first_event_timestamp;

  if (time_difference >= 1000000000L) { // 1 second
    state->first_event_timestamp = current_timestamp;
    state->event_count = 1;
    state->throttle = 0;
  } else {
    state->event_count++;
  }

  if (state->event_count > maxAlert) {
    state->event_count = 0;
    state->throttle = 1;
    bpf_map_update_elem(&kubearmor_alert_throttle, &key, state, BPF_ANY);

    // Generating Throttling Alert 
    event *event_data = bpf_ringbuf_reserve(&kubearmor_events, sizeof(event), 0);
    if (!event_data) {
      // Failed to reserve
      return true;
    }
    init_context(event_data);
    event_data->event_id = _DROPPING_ALERT;
    event_data->retval = 0; 
    bpf_ringbuf_submit(event_data, 0);

    return true; 
  }

  bpf_map_update_elem(&kubearmor_alert_throttle, &key, state, BPF_ANY);
  return false; 
}

static bool is_owner(struct file *file_p) {
  kuid_t owner = BPF_CORE_READ(file_p, f_inode, i_uid);
  unsigned int z = bpf_get_current_uid_gid();
  if (owner.val != z)
    return false;
  return true;
}

static bool is_owner_path(struct dentry *dent) {
  kuid_t owner = BPF_CORE_READ(dent, d_inode, i_uid);
  unsigned int z = bpf_get_current_uid_gid();
  if (owner.val != z)
    return false;
  return true;
}

static inline int match_and_enforce_path_hooks(struct path *f_path, u32 id,
                                               u32 eventID) {
  struct task_struct *t = (struct task_struct *)bpf_get_current_task();

  event *task_info;

  int retval = 0;

  bool match = false;

  struct outer_key okey;
  get_outer_key(&okey, t);

  u32 *inner = bpf_map_lookup_elem(&kubearmor_containers, &okey);

  if (!inner) {
    return 0;
  }

  // "z" is a zero value map key which is used to reset values of other keys
  // which are inturn used and updated to lookup the Rule Map

  // "store" stores informaton needed to do a lookup to our Rule Map

  // "pk" is a map key which is used for all kinds of matching and lookups, We
  // needed a third key because we need to copy contents from store and keep
  // resetting the contents of this key so data in store needs to persist

  u32 zero = 0;
  bufs_k *z = bpf_map_lookup_elem(&bufk, &zero);
  if (z == NULL)
    return 0;

  u32 one = 1;
  bufs_k *store = bpf_map_lookup_elem(&bufk, &one);
  if (store == NULL)
    return 0;

  // Reset value for store
  bpf_map_update_elem(&bufk, &one, z, BPF_ANY);

  u32 two = 2;
  bufs_k *pk = bpf_map_lookup_elem(&bufk, &two);
  if (pk == NULL)
    return 0;

  /* Extract full path from file structure provided by LSM Hook */
  bufs_t *path_buf = get_buf(PATH_BUFFER);
  if (path_buf == NULL)
    return 0;

  if (!prepend_path(f_path, path_buf))
    return 0;

  u32 *path_offset = get_buf_off(PATH_BUFFER);
  if (path_offset == NULL)
    return 0;

  void *path_ptr = &path_buf->buf[*path_offset];
  bpf_probe_read_str(store->path, MAX_STRING_SIZE, path_ptr);

  struct data_t *val = bpf_map_lookup_elem(inner, store);
  struct data_t *dirval;
  bool recursivebuthint = false;
  bool fromSourceCheck = true;

  /* Extract full path of the source binary from the task structure */
  struct file *file_p = get_task_file(t);
  if (file_p == NULL)
    fromSourceCheck = false;
  bufs_t *src_buf = get_buf(PATH_BUFFER);
  if (src_buf == NULL)
    fromSourceCheck = false;
  struct path f_src = BPF_CORE_READ(file_p, f_path);
  if (!prepend_path(&f_src, src_buf))
    fromSourceCheck = false;

  u32 *src_offset = get_buf_off(PATH_BUFFER);
  if (src_offset == NULL)
    fromSourceCheck = false;

  void *src_ptr;
  if (src_buf->buf[*src_offset]) {
    src_ptr = &src_buf->buf[*src_offset];
  }
  if (src_ptr == NULL)
    fromSourceCheck = false;

  if (fromSourceCheck) {
    bpf_probe_read_str(store->source, MAX_STRING_SIZE, src_ptr);

    val = bpf_map_lookup_elem(inner, store);

    if (val && (val->filemask & RULE_READ)) {
      match = true;
      goto decision;
    }

#pragma unroll
    for (int i = 0; i < 64; i++) {
      if (store->path[i] == '\0')
        break;

      if (store->path[i] == '/') {
        bpf_map_update_elem(&bufk, &two, z, BPF_ANY);

        match = false;

        bpf_probe_read_str(pk->path, i + 2, store->path);
        /* Check Subdir with From Source */
        bpf_probe_read_str(pk->source, MAX_STRING_SIZE, store->source);
        dirval = bpf_map_lookup_elem(inner, pk);
        if (dirval) {
          if ((dirval->filemask & RULE_DIR) && (dirval->filemask & RULE_READ)) {
            match = true;
            if ((dirval->filemask &
                 RULE_RECURSIVE)) { /* true directory match and */
                                    /* not a hint suggests */
              /* there are no possibility of child dir */
              val = dirval;
              if (dirval->filemask & RULE_HINT) {
                recursivebuthint = true;
                continue;
              } else {
                goto decision;
              }
            } else {
              continue; /* We continue the loop to see if we have more nested
                         */
                        /* directories and set match to false */
            }
          }
        } else {
          break;
        }
      }
    }

    if (recursivebuthint) {
      match = true;
      goto decision;
    }
    if (match) {
      if (dirval) { /* to please the holy verifier */
        val = dirval;
        goto decision;
      }
    }
  }
  bpf_map_update_elem(&bufk, &two, z, BPF_ANY);
  bpf_probe_read_str(pk->path, MAX_STRING_SIZE, store->path);

  val = bpf_map_lookup_elem(inner, pk);

  if (val && (val->filemask & RULE_READ)) {
    match = true;
    goto decision;
  }

  recursivebuthint = false;

#pragma unroll
  for (int i = 0; i < 64; i++) {
    if (store->path[i] == '\0')
      break;

    if (store->path[i] == '/') {
      bpf_map_update_elem(&bufk, &two, z, BPF_ANY);
      match = false;
      bpf_probe_read_str(pk->path, i + 2, store->path);
      dirval = bpf_map_lookup_elem(inner, pk);
      if (!dirval) {
        break;
      }
      if ((dirval->filemask & RULE_DIR) && (dirval->filemask & RULE_READ)) {
        match = true;
        if (!(dirval->filemask & RULE_RECURSIVE)) {
          continue; /* continue the loop to see if we have more nested dirs */
        }
        /* true directory match and not a hint suggests */
        /* there are no possibility of child dir */
        val = dirval;
        if (dirval->filemask & RULE_HINT) {
          recursivebuthint = true;
          continue;
        }
        goto decision;
      }
    }
  }

  if (recursivebuthint) {
    match = true;
    goto decision;
  } else if (match && dirval) {
    val = dirval;
    goto decision;
  }

decision:

  if (id == dpath) { // Path Hooks
    if (match) {
      if (val && (val->filemask & RULE_OWNER)) {
        struct dentry *dent ;
        if(eventID  == _FILE_MKNOD || eventID == _FILE_MKDIR){
          dent = BPF_CORE_READ(f_path , dentry , d_parent);
        } else {
          dent = f_path->dentry ;
        }
        if (!is_owner_path(dent)) {
          retval = -EPERM;
        } else {
          return 0;
        }
      }
      if (val && (val->filemask & RULE_DENY)) {
        retval = -EPERM;
      }
    }

    bpf_map_update_elem(&bufk, &two, z, BPF_ANY);
    pk->path[0] = dfile;
    struct data_t *allow = bpf_map_lookup_elem(inner, pk);
    
    if (retval == -EPERM && !(allow && !fromSourceCheck)) {
      goto ringbuf;
    }

    if (allow) {
      if (!match) {
        if (allow->processmask == BLOCK_POSTURE) {
          retval = -EPERM;
        }
        goto ringbuf;
      }
    }

  } else if (id == dfileread) { // file open
    if (match) {
      if (val && (val->filemask & RULE_OWNER)) {
        if (!is_owner_path(f_path->dentry)) {
          retval = -EPERM;
          goto ringbuf;
        } else {
          return 0;
        }
      }
      if (val && (val->filemask & RULE_READ) && !(val->filemask & RULE_WRITE)) {
        // Read Only Policy, Decision making will be done in lsm/file_permission
        return 0;
      }
      if (val && (val->filemask & RULE_DENY)) {
        retval = -EPERM;
      }
    }

 

    bpf_map_update_elem(&bufk, &two, z, BPF_ANY);
    pk->path[0] = dfile;
    struct data_t *allow = bpf_map_lookup_elem(inner, pk);

    if (retval == -EPERM && !(allow && !fromSourceCheck)) {
      goto ringbuf;
    }

    if (allow) {
      if (!match) {
        if (allow->processmask == BLOCK_POSTURE) {
          retval = -EPERM;
        }
        goto ringbuf;
      }
    }
  } else if (id == dfilewrite) { // file write
    if (match) {
      if (val && (val->filemask & RULE_OWNER)) {
        if (!is_owner_path(f_path->dentry)) {
          retval = -EPERM;
          goto ringbuf;
        }
      }
      if (val && (val->filemask & RULE_READ) && !(val->filemask & RULE_WRITE)) {
          retval = -EPERM;
          goto ringbuf;
      }
    }

    bpf_map_update_elem(&bufk, &two, z, BPF_ANY);
    pk->path[0] = dfile;
    struct data_t *allow = bpf_map_lookup_elem(inner, pk);

    if (allow) {
      if (!match) {
        if (allow->processmask == BLOCK_POSTURE) {
          retval = -EPERM;
        }
        goto ringbuf;
      }
    }
  }

  return 0;

ringbuf:
  if (get_kubearmor_config(_ALERT_THROTTLING) && should_drop_alerts_per_container(okey)) {
    return retval;
  }

  task_info = bpf_ringbuf_reserve(&kubearmor_events, sizeof(event), 0);
  if (!task_info) {
    // Failed to reserve, doing policy enforcement without alert
    return retval;
  }

  init_context(task_info);
  // Clearing arrays to avoid garbage values
  __builtin_memset(task_info->data.path, 0, sizeof(task_info->data.path));
  __builtin_memset(task_info->data.source, 0, sizeof(task_info->data.source));

  bpf_probe_read_str(&task_info->data.path, MAX_STRING_SIZE, store->path);
  bpf_probe_read_str(&task_info->data.source, MAX_STRING_SIZE, store->source);

  task_info->event_id = eventID;
  task_info->retval = retval;
  bpf_ringbuf_submit(task_info, 0);
  return retval;
}

/*
  How do we check what to deny or not?

  We match in the the following order:
  - entity + source
  -? directory matching + source
  - entity
  -? directory

  Once matched
  -? Owner Check
  - Deny Check
  - Check if WhiteList i.e. DefaultPosture for entity is block
  - if not match deny

  ? => Indicates optional check, like network hooks don't have owner or
       directory checks
*/

#endif /* __SHARED_H */