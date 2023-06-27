// +build ignore
/* SPDX-License-Identifier: GPL-2.0    */
/* Copyright 2023 Authors of KubeArmor */

#include "shared.h"

SEC("lsm/bprm_check_security")
int BPF_PROG(enforce_proc, struct linux_binprm *bprm, int ret) {
  struct task_struct *t = (struct task_struct *)bpf_get_current_task();

  bool match = false;

  struct outer_key okey;
  get_outer_key(&okey, t);

  u32 *inner = bpf_map_lookup_elem(&kubearmor_containers, &okey);

  if (!inner) {
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

  // Extract full path from file structure provided by LSM Hook
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
  bpf_probe_read_str(store->path, MAX_STRING_SIZE, path_ptr);

  // Extract full path of the source binary from the parent task structure
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

  void *src_ptr = &src_buf->buf[*src_offset];
  bpf_probe_read_str(store->source, MAX_STRING_SIZE, src_ptr);

  struct data_t *val = bpf_map_lookup_elem(inner, store);

  if (val && (val->processmask & RULE_EXEC)) {
    match = true;
    goto decision;
  }

  struct data_t *dirval;
  bool recursivebuthint = false;

#pragma unroll
  for (int i = 0; i < 64; i++) {
    if (store->path[i] == '\0')
      break;

    if (store->path[i] == '/') {
      bpf_map_update_elem(&bufk, &two, z, BPF_ANY);

      match = false;

      bpf_probe_read_str(pk->path, i + 2, store->path);
      // Check Subdir with From Source
      bpf_probe_read_str(pk->source, MAX_STRING_SIZE, store->source);
      dirval = bpf_map_lookup_elem(inner, pk);
      if (dirval) {
        if ((dirval->processmask & RULE_DIR) &&
            (dirval->processmask & RULE_EXEC)) {
          match = true;
          bpf_printk("dir match %s with recursive %d and hint %d ", pk,
                     (dirval->processmask & RULE_RECURSIVE),
                     (dirval->processmask & RULE_HINT));
          bpf_printk("and from source %s\n", pk->source);
          if ((dirval->processmask & RULE_RECURSIVE) &&
              (~dirval->processmask &
               RULE_HINT)) { // true directory match and not a hint suggests
                             // there are no possibility of child dir
            val = dirval;
            goto decision;
          } else if (dirval->processmask &
                     RULE_RECURSIVE) { // It's a directory match but also a
                                       // hint, it's possible that a
                                       // subdirectory exists that can also
                                       // match so we continue the loop to look
                                       // for a true match in subdirectories
            recursivebuthint = true;
            val = dirval;
          } else {
            continue; // We continue the loop to see if we have more nested
                      // directories and set match to false
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
    if (dirval) { // to please the holy verifier
      val = dirval;
      goto decision;
    }
  }

  bpf_map_update_elem(&bufk, &two, z, BPF_ANY);
  bpf_probe_read_str(pk->path, MAX_STRING_SIZE, store->path);

  val = bpf_map_lookup_elem(inner, pk);

  if (val && (val->processmask & RULE_EXEC)) {
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
      if (dirval) {
        if ((dirval->processmask & RULE_DIR) &&
            (dirval->processmask & RULE_EXEC)) {
          match = true;
          bpf_printk("dir match %s with recursive %d and hint %d\n", pk,
                     (dirval->processmask & RULE_RECURSIVE),
                     (dirval->processmask & RULE_HINT));
          if ((dirval->processmask & RULE_RECURSIVE) &&
              (~dirval->processmask &
               RULE_HINT)) { // true directory match and not a hint suggests
                             // there are no possibility of child dir match
            val = dirval;
            goto decision;
          } else if (dirval->processmask & RULE_RECURSIVE) {
            recursivebuthint = true;
            val = dirval;
          } else {
            continue; // We continue the loop to see if we have more nested
                      // directories and set match to false
          }
        }
        if (~dirval->processmask & RULE_HINT) {
          break;
        }
      } else {
        break;
      }
    }
  }

  if (recursivebuthint) {
    match = true;
    goto decision;
  } else {
    if (match && dirval) {
      val = dirval;
      goto decision;
    }
  }

decision:

  if (match) {
    if (val && (val->processmask & RULE_OWNER)) {
      if (!is_owner(bprm->file)) {
        bpf_printk("denying proc %s due to not owner\n", store);
        return -EPERM;
      } else {
        bpf_printk("allowing proc %s for owner\n", store);
        return ret;
      }
    }
    if (val && (val->processmask & RULE_DENY)) {
      bpf_printk("denying proc %s due to in blacklist\n", store->path);
      return -EPERM;
    }
  }

  bpf_map_update_elem(&bufk, &two, z, BPF_ANY);
  pk->path[0] = dproc;
  struct data_t *allow = bpf_map_lookup_elem(inner, pk);

  if (allow) {
    if (!match) {
      bpf_printk("denying proc %s due to not in allowlist, source -> %s\n",
                 store->path, store->source);
      return -EPERM;
    }
  }

  return ret;
}

static inline int match_net_rules(int type, int protocol, char *string) {
  struct task_struct *t = (struct task_struct *)bpf_get_current_task();

  bool match = false;

  struct outer_key okey;
  get_outer_key(&okey, t);

  u32 *inner = bpf_map_lookup_elem(&kubearmor_containers, &okey);

  if (!inner) {
    return 0;
  }

  u32 zero = 0;
  bufs_k *z = bpf_map_lookup_elem(&bufk, &zero);
  if (z == NULL)
    return 0;

  u32 one = 1;
  bufs_k *p = bpf_map_lookup_elem(&bufk, &one);
  if (p == NULL)
    return 0;

  u32 two = 2;
  bufs_k *store = bpf_map_lookup_elem(&bufk, &two);
  if (store == NULL)
    return 0;

  bpf_map_update_elem(&bufk, &one, z, BPF_ANY);

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

  int p0;
  int p1;

  if (type == SOCK_STREAM && (protocol == IPPROTO_TCP || protocol == 0)) {
    p0 = sock_proto;
    p1 = IPPROTO_TCP;
  } else if (type == SOCK_DGRAM && (protocol == IPPROTO_UDP || protocol == 0)) {
    p0 = sock_proto;
    p1 = IPPROTO_UDP;
  } else if (protocol == IPPROTO_ICMP &&
             (type == SOCK_DGRAM || type == SOCK_RAW)) {
    p0 = sock_proto;
    p1 = IPPROTO_ICMP;
  } else if (type == SOCK_RAW && protocol == 0) {
    p0 = sock_type;
    p1 = SOCK_RAW;
  } else {
    p0 = sock_proto;
    p1 = protocol;
  }

  p->path[0] = p0;
  p->path[1] = p1;

  struct data_t *val = bpf_map_lookup_elem(inner, p);

  if (val) {
    match = true;
    goto decision;
  }

  val = bpf_map_lookup_elem(inner, p);

  bpf_map_update_elem(&bufk, &one, z, BPF_ANY);

  p->path[0] = p0;
  p->path[1] = p1;

  val = bpf_map_lookup_elem(inner, p);

  if (val) {
    match = true;
    goto decision;
  }

decision:

  bpf_map_update_elem(&bufk, &one, z, BPF_ANY);
  p->path[0] = dnet;
  struct data_t *allow = bpf_map_lookup_elem(inner, p);

  if (allow) {
    if (!match) {
      bpf_printk("denying sock %s - type %d, protocol %d due "
                 "to not in allowlist\n",
                 string, type, protocol);
      if (p->source[0] != '\0') {
        bpf_printk("denying from source from %s", store->source);
      }
      return -EPERM;
    }
  } else {
    if (match) {
      if (val && (val->processmask & RULE_DENY)) {
        bpf_printk("denying sock %s - type %d, protocol %d due to in "
                   "blacklist\n",
                   string, type, protocol);
        return -EPERM;
      }
    }
  }
  return 0;
}

SEC("lsm/socket_create")
int BPF_PROG(enforce_net_create, int family, int type, int protocol) {
  return match_net_rules(type, protocol, "create");
}

#define LSM_NET(name, string)                                                  \
  int BPF_PROG(name, struct socket *sock) {                                    \
    int type = sock->type;                                                     \
    int protocol = sock->sk->sk_protocol;                                      \
    return match_net_rules(type, protocol, string);                            \
  }

SEC("lsm/socket_connect")
LSM_NET(enforce_net_connect, "connect");

SEC("lsm/socket_accept")
LSM_NET(enforce_net_accept, "accept");

SEC("lsm/file_open")
int BPF_PROG(enforce_file, struct file *file) { // check if ret code available
  struct path f_path = BPF_CORE_READ(file, f_path);
  return match_and_enforce_path_hooks(&f_path, dfileread);
}

SEC("lsm/file_permission")
int BPF_PROG(enforce_file_perm, struct file *file, int mask) {
  if (!(mask & (MASK_WRITE | MASK_APPEND))) {
    // only relevant when write events triggered, since rest is blocked by
    // file_open
    return 0;
  }

  struct path f_path = BPF_CORE_READ(file, f_path);
  return match_and_enforce_path_hooks(&f_path, dfilewrite);
}