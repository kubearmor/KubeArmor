// +build ignore
/* SPDX-License-Identifier: GPL-2.0    */
/* Copyright 2026 Authors of KubeArmor */

#include "shared.h"
#include "syscalls.h"

SEC("lsm/bprm_check_security")
int BPF_PROG(enforce_proc, struct linux_binprm *bprm, int ret) {
  struct task_struct *t = (struct task_struct *)bpf_get_current_task();
  event *task_info;
  int retval = ret;

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

  struct data_t *val = bpf_map_lookup_elem(inner, store);
  struct data_t *dirval;
  bool recursivebuthint = false;
  bool fromSourceCheck = true;
  bool goToDecision = false ;

  // Extract full path of the source binary from the parent task structure
  struct task_struct *parent_task = BPF_CORE_READ(t, parent);
  struct file *file_p = get_task_file(parent_task);
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
    if (val && (val->processmask & RULE_EXEC)) {
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
        // Check Subdir with From Source
        bpf_probe_read_str(pk->source, MAX_STRING_SIZE, store->source);
        dirval = bpf_map_lookup_elem(inner, pk);
        if (dirval) {
          if ((dirval->processmask & RULE_DIR) &&
              (dirval->processmask & RULE_EXEC)) {
            match = true;
            if ((dirval->processmask & RULE_RECURSIVE) &&
                (~dirval->processmask &
                 RULE_HINT)) { // true directory match and not a hint suggests
                               // there are no possibility of child dir
              val = dirval;
              goToDecision = true; // to please the holy verifier
              break;
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

    if (recursivebuthint || goToDecision) {
      match = true;
      goto decision;
    }
    if (match) {
      if (dirval) { // to please the holy verifier
        val = dirval;
        goto decision;
      }
    }
  }
  bpf_map_update_elem(&bufk, &two, z, BPF_ANY);
  bpf_probe_read_str(pk->path, MAX_STRING_SIZE, store->path);

  val = bpf_map_lookup_elem(inner, pk);

  if (val && (val->processmask & RULE_EXEC)) {
    match = true;
    goto decision;
  }

  // match exec name
  struct qstr d_name;
  d_name = BPF_CORE_READ(f_path.dentry, d_name);
  bpf_map_update_elem(&bufk, &two, z, BPF_ANY);
  bpf_probe_read_str(pk->path, MAX_STRING_SIZE, d_name.name);

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
        retval = -EPERM;
      } else {
        // Owner Only Rule Match, No need to enforce
        return ret;
      }
    }
    if (val && (val->processmask & RULE_DENY)) {
      retval = -EPERM;
    }
  }

  if (retval == -EPERM) {
    goto ringbuf;
  }

  bpf_map_update_elem(&bufk, &two, z, BPF_ANY);
  pk->path[0] = dproc;
  struct data_t *allow = bpf_map_lookup_elem(inner, pk);

  if (allow) {
    if (!match) {
      if (allow->processmask == BLOCK_POSTURE) {
        retval = -EPERM;
      }
      goto ringbuf;
    }
  }

  return ret;

ringbuf:
  if (get_kubearmor_config(_ALERT_THROTTLING) && should_drop_alerts_per_container(okey)) {
    return retval;
  }

  task_info = bpf_ringbuf_reserve(&kubearmor_events, sizeof(event), 0);
  if (!task_info) {
    // Failed to reserve, doing policy enforcement without alert
    return retval;
  }

  // Clearing arrays to avoid garbage values
  __builtin_memset(task_info->data.path, 0, sizeof(task_info->data.path));
  __builtin_memset(task_info->data.source, 0, sizeof(task_info->data.source));

  init_context(task_info);
  bpf_probe_read_str(&task_info->data.path, MAX_STRING_SIZE, store->path);
  bpf_probe_read_str(&task_info->data.source, MAX_STRING_SIZE, store->source);
  task_info->event_id = _SECURITY_BPRM_CHECK;
  task_info->retval = retval;
  bpf_ringbuf_submit(task_info, 0);
  return retval;
}

static inline int match_net_rules(int type, int protocol, u32 eventID) {
  event *task_info;
  int retval = 0;

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
  int p0_t, p1_t;
  int p0_p, p1_p;
  struct data_t *val = bpf_map_lookup_elem(inner, p);
  bool fromSourceCheck = true;

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


  // socket type check
  if (type == SOCK_STREAM || type == SOCK_DGRAM || type == SOCK_RAW || type == SOCK_RDM || type == SOCK_SEQPACKET || type == SOCK_DCCP || type == SOCK_PACKET) {
    p0_t = sock_type;
    p1_t = type;
  }
  
  // protocol check
  if (type == SOCK_STREAM && (protocol == IPPROTO_TCP || protocol == 0)) {
    p0_p = sock_proto;
    p1_p = IPPROTO_TCP;
  } else if (type == SOCK_DGRAM && (protocol == IPPROTO_UDP || protocol == 0)) {
    p0_p = sock_proto;
    p1_p = IPPROTO_UDP;
  } else if (protocol == IPPROTO_ICMP &&
             (type == SOCK_DGRAM || type == SOCK_RAW)) {
    p0_p = sock_proto;
    p1_p = IPPROTO_ICMP;
  } else if (protocol == IPPROTO_ICMPV6 &&
             (type == SOCK_DGRAM || type == SOCK_RAW)) {
    p0_p = sock_proto;
    p1_p = IPPROTO_ICMPV6;
  } else if ((type == SOCK_STREAM || type == SOCK_SEQPACKET) && (protocol == IPPROTO_SCTP || protocol == 0)) {
    p0_p = sock_proto;
    p1_p = IPPROTO_SCTP;
  } else {
    p0_p = sock_proto;
    p1_p = protocol;
  }

  // socket type fromsource check
  if (fromSourceCheck) {
    void *ptr = &src_buf->buf[*src_offset];
    bpf_probe_read_str(p->source, MAX_STRING_SIZE, ptr);
    p->path[0] = p0_t;
    p->path[1] = p1_t;
    bpf_probe_read_str(store->source, MAX_STRING_SIZE, p->source);
    val = bpf_map_lookup_elem(inner, p);
    if (val) {
      match = true;
      goto decision;
    }
  }

  // protocol fromsource check
  if (fromSourceCheck) {
    void *ptr = &src_buf->buf[*src_offset];
    bpf_probe_read_str(p->source, MAX_STRING_SIZE, ptr);
    p->path[0] = p0_p;
    p->path[1] = p1_p;
    bpf_probe_read_str(store->source, MAX_STRING_SIZE, p->source);
    val = bpf_map_lookup_elem(inner, p);
    if (val) {
      match = true;
      goto decision;
    }
  }

  // check for type rules without fromSource
  bpf_map_update_elem(&bufk, &one, z, BPF_ANY);
  p->path[0] = p0_t;
  p->path[1] = p1_t;

  val = bpf_map_lookup_elem(inner, p);

  if (val) {
    match = true;
    goto decision;
  }

  // check for protocol rules without fromSource
  bpf_map_update_elem(&bufk, &one, z, BPF_ANY);
  p->path[0] = p0_p;
  p->path[1] = p1_p;

  val = bpf_map_lookup_elem(inner, p);

  if (val) {
    match = true;
    goto decision;
  }

decision:

  bpf_probe_read_str(store->path, MAX_STRING_SIZE, p->path);
  if (match) {
    if (val && (val->processmask & RULE_DENY)) {
      retval = -EPERM;
      goto ringbuf;
    }
  }

  bpf_map_update_elem(&bufk, &one, z, BPF_ANY);
  p->path[0] = dnet;

  struct data_t *allow = bpf_map_lookup_elem(inner, p);

  if (allow) {
    if (!match) {
      if (allow->processmask == BLOCK_POSTURE) {
        retval = -EPERM;
      }
      goto ringbuf;
    }
  }

  return 0;

ringbuf:
  if (get_kubearmor_config(_ALERT_THROTTLING) && should_drop_alerts_per_container(okey)) {
    return retval;
  }

  task_info = bpf_ringbuf_reserve(&kubearmor_events, sizeof(event), 0);
  if (!task_info) {
    return retval;
  }
  
  // Clearing arrays to avoid garbage values to be parsed
  __builtin_memset(task_info->data.path, 0, sizeof(task_info->data.path));
  __builtin_memset(task_info->data.source, 0, sizeof(task_info->data.source));

  init_context(task_info);
  bpf_probe_read_str(&task_info->data.path, MAX_STRING_SIZE, store->path);
  bpf_probe_read_str(&task_info->data.source, MAX_STRING_SIZE, store->source);

  task_info->event_id = eventID;

  task_info->retval = retval;
  bpf_ringbuf_submit(task_info, 0);
  return retval;
}

SEC("lsm/socket_create")
int BPF_PROG(enforce_net_create, int family, int type, int protocol) {
  return match_net_rules(type, protocol, _SOCKET_CREATE);
}

#define LSM_NET(name, ID)                                                      \
  int BPF_PROG(name, struct socket *sock) {                                    \
    int sock_type = BPF_CORE_READ(sock, type);                                 \
    struct sock *sk;                                                           \
    sk = BPF_CORE_READ(sock, sk);                                              \
    int protocol = BPF_CORE_READ(sk, sk_protocol);                             \
    return match_net_rules(sock_type, protocol, ID);                           \
  }

SEC("lsm/socket_connect")
LSM_NET(enforce_net_connect, _SOCKET_CONNECT);

SEC("lsm/socket_accept")
LSM_NET(enforce_net_accept, _SOCKET_ACCEPT);

SEC("lsm/file_open")
int BPF_PROG(enforce_file, struct file *file) { // check if ret code available
  struct path f_path = BPF_CORE_READ(file, f_path);
  return match_and_enforce_path_hooks(&f_path, dfileread, _FILE_OPEN);
}

SEC("lsm/file_permission")
int BPF_PROG(enforce_file_perm, struct file *file, int mask) {
  if (!(mask & (MASK_WRITE | MASK_APPEND))) {
    // only relevant when write events triggered, since rest is blocked by
    // file_open
    return 0;
  }

  struct path f_path = BPF_CORE_READ(file, f_path);
  return match_and_enforce_path_hooks(&f_path, dfilewrite, _FILE_PERMISSION);
}
SEC("lsm/capable")
int BPF_PROG(enforce_cap, const struct cred *cred, struct user_namespace *ns,
             int cap, int ret) {

  event *task_info;
  int retval = 0;

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
  int p0;
  int p1;
  struct data_t *val = bpf_map_lookup_elem(inner, p);
  bool fromSourceCheck = true;

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

  void *ptr = &src_buf->buf[*src_offset];
  p0 = CAPABLE_KEY;
  p1 = cap;

  if (fromSourceCheck) {
    bpf_probe_read_str(p->source, MAX_STRING_SIZE, ptr);
    bpf_probe_read_str(store->source, MAX_STRING_SIZE, p->source);
    p->path[0] = p0;
    p->path[1] = p1;
    val = bpf_map_lookup_elem(inner, p);

    if (val) {
      match = true;
      goto decision;
    }
  }

  bpf_map_update_elem(&bufk, &one, z, BPF_ANY);
  // check for rules without fromsource
  p->path[0] = p0;
  p->path[1] = p1;

  val = bpf_map_lookup_elem(inner, p);

  if (val) {
    match = true;
    goto decision;
  }

decision:
  bpf_probe_read_str(store->path, MAX_STRING_SIZE, p->path);
  if (match) {
    if (val && (val->processmask & RULE_DENY)) {
      retval = -EPERM;
      goto ringbuf;
    }
  }

  bpf_map_update_elem(&bufk, &one, z, BPF_ANY);
  p->path[0] = dcap;
  struct data_t *allow = bpf_map_lookup_elem(inner, p);

  if (allow) {
    if (!match) {
      if (allow->processmask == BLOCK_POSTURE) {
        retval = -EPERM;
      }
      goto ringbuf;
    }
  }

  return 0;

ringbuf:
  if (get_kubearmor_config(_ALERT_THROTTLING) && should_drop_alerts_per_container(okey)) {
    return retval;
  }

  task_info = bpf_ringbuf_reserve(&kubearmor_events, sizeof(event), 0);
  if (!task_info) {
    return retval;
  }

  // Clearing arrays to avoid garbage values to be parsed
  __builtin_memset(task_info->data.path, 0, sizeof(task_info->data.path));
  __builtin_memset(task_info->data.source, 0, sizeof(task_info->data.source));

  init_context(task_info);
  bpf_probe_read_str(&task_info->data.path, MAX_STRING_SIZE, store->path);
  bpf_probe_read_str(&task_info->data.source, MAX_STRING_SIZE, store->source);

  task_info->event_id = _CAPABLE;

  task_info->retval = retval;
  bpf_ringbuf_submit(task_info, 0);
  return retval;
}