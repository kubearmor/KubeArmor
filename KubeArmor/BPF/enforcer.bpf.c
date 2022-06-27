// +build ignore

#include "hash.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";
#define EPERM 1

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
  __uint(max_entries, 1024);
  __uint(key_size, sizeof(struct outer_key));
  __uint(value_size, sizeof(u32));
  __uint(pinning, LIBBPF_PIN_BY_NAME);
};

struct outer_hash kubearmor_containers SEC(".maps");

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

/* strlen determines the length of a fixed-size string */
static size_t strnlen(const char *str, size_t maxlen) {
  if (!str || !maxlen)
    return 0;

  if (maxlen == __SIZE_MAX__)
    maxlen--;

  size_t i = 0;

  while (i < maxlen && str[i])
    i++;

  return i;
}

static u64 cb_check_path(struct bpf_map *map, u32 *key, char *path, int t) {
  bpf_printk("Found key %u", *key);
  return 0;
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

  // bpf_printk("monitoring %u,%u", okey.pid_ns, okey.mnt_ns);

  // bpf_for_each_map_elem(inner, cb_check_path, 0, 0);

  char p[64] = {};

  u32 sz = bpf_probe_read_kernel_str(&p, 64, bprm->filename);
  if (sz < 0) {
    return ret;
  }


// TODO handle full path
  u32 k = jenkins_hash(p, strnlen(p, 64), 0);

  // bpf_printk("for string %s length is %d and hash is %u \n", p, sz - 1, k);

  struct data_t *val = bpf_map_lookup_elem(inner, &k);

  if (val && val->exec) {
    match = true;
    goto decision;
  }

  char dir[64] = {};
  u32 fp = 0;

#pragma unroll
  for (int i = 0; i < 64; i++) {
    if (p[i] == '\0')
      break;

    if (p[i] == '/') {
      __builtin_memset(&dir, 0, sizeof(dir));
      bpf_probe_read_str(&dir, i + 2, p);

      fp = jenkins_hash(dir, i + 1, 0);
      // bpf_printk("for string %s length is %d and hash is %u \n", dir, i + 1,
      //            fp);

      match = false;

      val = bpf_map_lookup_elem(inner, &fp);
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
        break;
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

  u32 apk = 101;
  struct data_t *allow = bpf_map_lookup_elem(inner, &apk);

  if (allow) {
    if (!match) {
      bpf_printk("denying proc %s due to not in allowlist \n", p);
      return -EPERM;
    }
  } else {
    if (match) {
      bpf_printk("denying proc %s due to in blacklist \n", p);
      return -EPERM;
    }
  }

  return ret;
}

SEC("lsm/file_open")
int BPF_PROG(enforce_file, struct file *file) {
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

  char p[64] = {};

  u32 sz = bpf_d_path(&file->f_path, p, 64);
  if (sz < 0) {
    return 0;
  }

  u32 k = jenkins_hash(p, strnlen(p, 64), 0);

  // bpf_printk("for string %s length is %d and hash is %u \n", p, sz - 1, k);

  struct data_t *val = bpf_map_lookup_elem(inner, &k);

  if (val && val->read) {
    match = true;
    goto decision;
  }

  char dir[64] = {};
  u32 fp = 0;

#pragma unroll
  for (int i = 0; i < 64; i++) {
    if (p[i] == '\0')
      break;

    if (p[i] == '/') {
      __builtin_memset(&dir, 0, sizeof(dir));
      bpf_probe_read_str(&dir, i + 2, p);

      fp = jenkins_hash(dir, i + 1, 0);
      // bpf_printk("for string %s length is %d and hash is %u \n", dir, i + 1,
      //            fp);

      match = false;

      val = bpf_map_lookup_elem(inner, &fp);
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
        break;
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

  u32 afk = 102;
  struct data_t *allow = bpf_map_lookup_elem(inner, &afk);

  if (allow) {
    if (!match) {
      bpf_printk("denying file %s due to not in allowlist \n", p);
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

  u32 k;

  k = 0xdeadbeef + sock->sk->sk_protocol;

  if (bpf_map_lookup_elem(inner, &k)) {
    match = true;
  }

  u32 ank = 103;
  struct data_t *allow = bpf_map_lookup_elem(inner, &ank);

  if (allow) {
    if (!match) {
      bpf_printk("denying sock type %d, family %d, protocol %d due to not in "
                 "allowlist \n",
                 sock->type, address->sa_family, sock->sk->sk_protocol);
      return -EPERM;
    }
  } else {
    if (match) {
      bpf_printk(
          "denying sock type %d, family %d, protocol %d due to in blacklist \n",
          sock->type, address->sa_family, sock->sk->sk_protocol);
      return -EPERM;
    }
  }
  return 0;
}
