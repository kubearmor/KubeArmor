// +build ignore

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";
#define EPERM 1

#define MAX_BUFFER_SIZE 32768
#define MAX_STRING_SIZE 256
#define MAX_BUFFERS 1
#define PATH_BUFFER 0

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

struct outer_key {
  u32 pid_ns;
  u32 mnt_ns;
};

struct data_t {
  bool owner;
  bool read;
  bool write;
  bool exec;
  bool dir;
  bool recursive;
  bool hint;
};

struct outer_hash {
  __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
  __uint(max_entries, 256);
  __uint(key_size, sizeof(struct outer_key));
  __uint(value_size, sizeof(u32));
  __uint(pinning, LIBBPF_PIN_BY_NAME);
};

struct outer_hash kubearmor_containers SEC(".maps");

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
  int offset = MAX_STRING_SIZE;

  if (path == NULL || string_p == NULL) {
    return false;
  }

  struct dentry *dentry = path->dentry;
  struct vfsmount *vfsmnt = path->mnt;

  struct mount *mnt = real_mount(vfsmnt);

  struct dentry *parent;
  struct dentry *mnt_root;
  struct mount *m;
  struct qstr d_name;

#pragma unroll
  for (int i = 0; i < 30; i++) {
    parent = BPF_CORE_READ(dentry, d_parent);
    mnt_root = BPF_CORE_READ(vfsmnt, mnt_root);

    if (dentry == mnt_root) {
      m = BPF_CORE_READ(mnt, mnt_parent);
      if (mnt != m) {
        dentry = BPF_CORE_READ(mnt, mnt_mountpoint);
        mnt = m;
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
        &(string_p->buf[(offset) & (MAX_STRING_SIZE - 1)]),
        (d_name.len + 1) & (MAX_STRING_SIZE - 1), d_name.name);
    if (sz > 1) {
      bpf_probe_read(
          &(string_p->buf[(offset + d_name.len) & (MAX_STRING_SIZE - 1)]), 1,
          &slash);
    } else {
      offset += (d_name.len + 1);
    }

    dentry = parent;
  }

  if (offset == MAX_STRING_SIZE) {
    return false;
  }

  bpf_probe_read(&(string_p->buf[MAX_STRING_SIZE - 1]), 1, &null);
  offset--;

  bpf_probe_read(&(string_p->buf[offset & (MAX_STRING_SIZE - 1)]), 1, &slash);
  set_buf_off(PATH_BUFFER, offset);
  return true;
}

static __always_inline u32 get_task_pid_ns_id(struct task_struct *task) {
  return BPF_CORE_READ(task, nsproxy, pid_ns_for_children, ns).inum;
}

static __always_inline u32 get_task_mnt_ns_id(struct task_struct *task) {
  return BPF_CORE_READ(task, nsproxy, mnt_ns, ns).inum;
}

static struct file *get_task_file(struct task_struct *task) {
  return BPF_CORE_READ(task, mm, exe_file);
}

static bool is_owner(struct file *file_p) {
  kuid_t owner = BPF_CORE_READ(file_p, f_inode, i_uid);
  unsigned int z = bpf_get_current_uid_gid();
  if (owner.val != z)
    return false;
  return true;
}

SEC("lsm/bprm_check_security")
int BPF_PROG(enforce_proc, struct linux_binprm *bprm, int ret) {
  struct task_struct *t = (struct task_struct *)bpf_get_current_task();

  bool match = false;

  struct outer_key okey = {.pid_ns = get_task_pid_ns_id(t),
                           .mnt_ns = get_task_mnt_ns_id(t)};

  if (okey.pid_ns == PROC_PID_INIT_INO) {
    return 0;
  }

  u32 *inner = bpf_map_lookup_elem(&kubearmor_containers, &okey);

  if (!inner) {
    return 0;
  }

  u32 zero = 0;
  u32 one = 1;
  bufs_k *p = bpf_map_lookup_elem(&bufk, &zero);
  if (p == NULL)
    return 0;

  bufs_k *z = bpf_map_lookup_elem(&bufk, &one);
  if (z == NULL)
    return 0;

  bpf_map_update_elem(&bufk, &zero, z, BPF_ANY);

  u32 two = 2;
  bufs_k *dir = bpf_map_lookup_elem(&bufk, &two);
  if (dir == NULL)
    return 0;

  bufs_t *path_buf = get_buf(PATH_BUFFER);
  if (path_buf == NULL)
    return 0;
  struct path f_path = BPF_CORE_READ(bprm->file, f_path);
  if (!prepend_path(&f_path, path_buf))
    return 0;

  u32 *path_offset = get_buf_off(PATH_BUFFER);
  if (path_offset == NULL)
    return 0;

  void *path_ptr = &path_buf->buf[*path_offset];
  bpf_probe_read_str(p->path, MAX_STRING_SIZE, path_ptr);

  struct data_t *val = bpf_map_lookup_elem(inner, p);

  if (val && val->exec) {
    match = true;
    goto decision;
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

  void *ptr = &src_buf->buf[*src_offset];
  bpf_probe_read_str(p->source, MAX_STRING_SIZE, ptr);

  val = bpf_map_lookup_elem(inner, p);

  if (val && val->exec) {
    match = true;
    goto decision;
  }

#pragma unroll
  for (int i = 0; i < 64; i++) {
    if (p->path[i] == '\0')
      break;

    if (p->path[i] == '/') {
      bpf_map_update_elem(&bufk, &two, z, BPF_ANY);

      match = false;

      bpf_probe_read_str(dir->path, i + 2, p->path);
      val = bpf_map_lookup_elem(inner, dir);
      if (val) {
        if (val->dir && val->exec) {
          match = true;
          bpf_printk("dir match %s with recursive %d \n", dir, val->recursive);
          if (val->recursive) {
            goto decision;
          } else {
            continue; // We continue the loop to see if we have more nested
                      // directories and set match to false
          }
        }
        if (val->hint == 0) {
          break;
        }
      } else {
        // Check Subdir with From Source
        bpf_probe_read_str(dir->source, MAX_STRING_SIZE, p->source);
        val = bpf_map_lookup_elem(inner, dir);
        if (val) {
          if (val->dir && val->exec) {
            match = true;
            bpf_printk("dir match %s with recursive %d and from source %S \n",
                       dir->path, val->recursive, dir->source);
            if (val->recursive) {
              goto decision;
            } else {
              continue; // We continue the loop to see if we have more nested
                        // directories and set match to false
            }
          }
          if (val->hint == 0) {
            break;
          }
        } else {
          break;
        }
      }
    }
  }

decision:

  if (match) {
    if (val && val->owner) {
      if (!is_owner(bprm->file)) {
        bpf_printk("denying proc %s due to not owner \n", p);
        return -EPERM;
      } else {
        bpf_printk("allowing proc %s for owner \n", p);
        return ret;
      }
    }
  }

  bpf_map_update_elem(&bufk, &two, z, BPF_ANY);
  dir->path[0] = 101;
  struct data_t *allow = bpf_map_lookup_elem(inner, dir);

  if (allow) {
    if (!match) {
      bpf_printk("denying proc %s due to not in allowlist, source -> %s \n",
                 p->path, p->source);
      return -EPERM;
    }
  } else {
    if (match) {
      bpf_printk("denying proc %s due to in blacklist \n", p->path);
      return -EPERM;
    }
  }

  return ret;
}

SEC("lsm/file_open")
int BPF_PROG(enforce_file, struct file *file) { // check if ret code available
  struct task_struct *t = (struct task_struct *)bpf_get_current_task();

  bool match = false;

  struct outer_key okey = {.pid_ns = get_task_pid_ns_id(t),
                           .mnt_ns = get_task_mnt_ns_id(t)};

  if (okey.pid_ns == PROC_PID_INIT_INO) {
    return 0;
  }

  u32 *inner = bpf_map_lookup_elem(&kubearmor_containers, &okey);

  if (!inner) {
    return 0;
  }

  // bpf_printk("monitoring %u,%u", okey.pid_ns, okey.mnt_ns);

  // bpf_for_each_map_elem(inner, cb_check_path, 0, 0);

  u32 zero = 0;
  u32 one = 1;
  bufs_k *p = bpf_map_lookup_elem(&bufk, &zero);
  if (p == NULL)
    return 0;

  bufs_k *z = bpf_map_lookup_elem(&bufk, &one);
  if (z == NULL)
    return 0;

  bpf_map_update_elem(&bufk, &zero, z, BPF_ANY);

  u32 two = 2;
  bufs_k *dir = bpf_map_lookup_elem(&bufk, &two);
  if (dir == NULL)
    return 0;

  bufs_t *path_buf = get_buf(PATH_BUFFER);
  if (path_buf == NULL)
    return 0;
  struct path f_path = BPF_CORE_READ(file, f_path);
  if (!prepend_path(&f_path, path_buf))
    return 0;

  u32 *path_offset = get_buf_off(PATH_BUFFER);
  if (path_offset == NULL)
    return 0;

  void *path_ptr = &path_buf->buf[*path_offset];
  bpf_probe_read_str(p->path, MAX_STRING_SIZE, path_ptr);

  struct data_t *val = bpf_map_lookup_elem(inner, p);

  if (val && val->read) {
    match = true;
    goto decision;
  }

  struct file *file_p = get_task_file(t);
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

  void *ptr = &src_buf->buf[*src_offset];
  bpf_probe_read_str(p->source, MAX_STRING_SIZE, ptr);

  val = bpf_map_lookup_elem(inner, p);

  if (val && val->read) {
    match = true;
    goto decision;
  }

#pragma unroll
  for (int i = 0; i < 64; i++) {
    if (p->path[i] == '\0')
      break;

    if (p->path[i] == '/') {
      bpf_map_update_elem(&bufk, &two, z, BPF_ANY);

      match = false;

      bpf_probe_read_str(dir->path, i + 2, p->path);
      // bpf_printk("file access of %s", dir->path);
      val = bpf_map_lookup_elem(inner, dir);
      if (val) {
        if (val->dir && val->read) {
          match = true;
          bpf_printk("dir match %s with recursive %d \n", dir, val->recursive);
          if (val->recursive) {
            goto decision;
          } else {
            continue; // We continue the loop to see if we have more nested
                      // directories and set match to false
          }
        }
        if (val->hint == 0) {
          break;
        }
      } else {
        // Check Subdir with From Source
        bpf_probe_read_str(dir->source, MAX_STRING_SIZE, p->source);
        // bpf_printk("file access from %s", dir->source);

        val = bpf_map_lookup_elem(inner, dir);
        if (val) {
          if (val->dir && val->read) {
            match = true;
            bpf_printk("dir match %s with recursive %d and from source %s \n",
                       dir->path, val->recursive, dir->source);
            if (val->recursive) {
              goto decision;
            } else {
              continue; // We continue the loop to see if we have more nested
                        // directories and set match to false
            }
          }
          if (val->hint == 0) {
            break;
          }
        } else {
          break;
        }
      }
    }
  }

decision:

  if (match) {
    if (val && val->owner) {
      if (!is_owner(file)) {
        bpf_printk("denying file %s due to not owner \n", p);
        return -EPERM;
      } else {
        bpf_printk("allowing file %s for owner \n", p);
        return 0;
      }
    }
  }

  bpf_map_update_elem(&bufk, &two, z, BPF_ANY);
  dir->path[0] = 102;
  struct data_t *allow = bpf_map_lookup_elem(inner, dir);

  if (allow) {
    if (!match) {
      bpf_printk("denying file %s due to not in allowlist, source -> %s \n",
                 p->path, p->source);
      return -EPERM;
    }
  } else {
    if (match) {
      bpf_printk("denying file %s due to in blacklist \n", p);
      return -EPERM;
    }
  }

  return 0;
}

SEC("lsm/socket_connect")
int BPF_PROG(enforce_net, struct socket *sock, struct sockaddr *address,
             int addrlen) {
  struct task_struct *t = (struct task_struct *)bpf_get_current_task();

  bool match = false;

  struct outer_key okey = {.pid_ns = get_task_pid_ns_id(t),
                           .mnt_ns = get_task_mnt_ns_id(t)};

  if (okey.pid_ns == PROC_PID_INIT_INO) {
    return 0;
  }

  u32 *inner = bpf_map_lookup_elem(&kubearmor_containers, &okey);

  if (!inner) {
    return 0;
  }

  u32 zero = 0;
  u32 one = 1;
  bufs_k *p = bpf_map_lookup_elem(&bufk, &zero);
  if (p == NULL)
    return 0;

  bufs_k *z = bpf_map_lookup_elem(&bufk, &one);
  if (z == NULL)
    return 0;

  bpf_map_update_elem(&bufk, &zero, z, BPF_ANY);

  p->path[0] = 3; // Protocol Check
  p->path[1] = sock->sk->sk_protocol;

  struct data_t *val = bpf_map_lookup_elem(inner, p);

  if (val) {
    match = true;
    goto decision;
  }

  struct file *file_p = get_task_file(t);
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

  void *ptr = &src_buf->buf[*src_offset];
  bpf_probe_read_str(p->source, MAX_STRING_SIZE, ptr);

  val = bpf_map_lookup_elem(inner, p);

  if (val) {
    match = true;
    goto decision;
  }

  bpf_map_update_elem(&bufk, &zero, z, BPF_ANY);

  p->path[0] = 2; // Type Check
  p->path[1] = sock->type;

  val = bpf_map_lookup_elem(inner, p);

  if (val) {
    match = true;
    goto decision;
  }

  bpf_probe_read_str(p->source, MAX_STRING_SIZE, ptr);

  val = bpf_map_lookup_elem(inner, p);

  if (val) {
    match = true;
    goto decision;
  }
decision:

  bpf_map_update_elem(&bufk, &zero, z, BPF_ANY);
  p->path[0] = 103;
  struct data_t *allow = bpf_map_lookup_elem(inner, p);

  if (allow) {
    if (!match) {
      bpf_printk("denying sock type %d, family %d, protocol %d due to not in "
                 "allowlist \n",
                 sock->type, address->sa_family, sock->sk->sk_protocol);
      return -EPERM;
    }
  } else {
    if (match) {
      bpf_printk("denying sock type %d, family %d, protocol %d due to in "
                 "blacklist \n",
                 sock->type, address->sa_family, sock->sk->sk_protocol);
      return -EPERM;
    }
  }
  return 0;
}
