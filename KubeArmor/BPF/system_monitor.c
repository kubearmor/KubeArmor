/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2022 Authors of KubeArmor */

#ifndef KBUILD_MODNAME
#define KBUILD_MODNAME "kubearmor_system_monitor"
#endif

// ========================================================== //
// KubeArmor utilizes Tracee's system call handling functions //
// developed by Aqua Security (https://aquasec.com).          //
// ========================================================== //

#ifdef asm_inline
#undef asm_inline
#define asm_inline asm
#endif

#ifdef asm_volatile_goto
#undef asm_volatile_goto
#define asm_volatile_goto(x...) asm volatile("invalid use of asm_volatile_goto")
#pragma clang diagnostic ignored "-Wunused-label"
#endif

#ifdef BTF_SUPPORTED
#include "vmlinux.h"
#include "vmlinux_macro.h"
#include <bpf_core_read.h>
#define __user
#else
#include <linux/nsproxy.h>
#include <linux/ns_common.h>
#include <linux/pid_namespace.h>
#include <linux/proc_ns.h>
#include <linux/mount.h>
#include <linux/binfmts.h>

#include <linux/un.h>
#include <net/inet_sock.h>

#include <linux/bpf.h>
#include <linux/version.h>
#include <linux/sched/signal.h>
#include <linux/tty.h>

#endif

#include <bpf_helpers.h>
#include <bpf_tracing.h>
#include "syscalls.h"
#include "throttling.h"


#ifdef RHEL_RELEASE_CODE
#if (RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(8, 0))
#define RHEL_RELEASE_GT_8_0
#endif
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0)
#error Minimal required kernel version is 4.14
#endif

#undef container_of
#define container_of(ptr, type, member)                    \
    ({                                                     \
        const typeof(((type *)0)->member) *__mptr = (ptr); \
        (type *)((char *)__mptr - offsetof(type, member)); \
    })

// == Structures == //

#define TASK_COMM_LEN 16
#define CWD_LEN 80
#define TTY_LEN 64

#define MAX_BUFFER_SIZE 32768
#define MAX_STRING_SIZE 4096
#define MAX_STR_ARR_ELEM 20
#define MAX_LOOP_LIMIT 25

#define NONE_T 0UL
#define INT_T 1UL
#define STR_T 10UL
#define STR_ARR_T 11UL
#define SOCKADDR_T 12UL
#define OPEN_FLAGS_T 13UL
#define EXEC_FLAGS_T 14UL
#define SOCK_DOM_T 15UL
#define SOCK_TYPE_T 16UL
#define FILE_TYPE_T 17UL
#define UNLINKAT_FLAG_T 19UL
#define PTRACE_REQ_T 23UL
#define MOUNT_FLAG_T 24UL
#define UMOUNT_FLAG_T 25UL

#define MAX_ARGS 6
#define ENC_ARG_TYPE(n, type) type << (8 * n)
#define ARG_TYPE0(type) ENC_ARG_TYPE(0, type)
#define ARG_TYPE1(type) ENC_ARG_TYPE(1, type)
#define ARG_TYPE2(type) ENC_ARG_TYPE(2, type)
#define ARG_TYPE3(type) ENC_ARG_TYPE(3, type)
#define ARG_TYPE4(type) ENC_ARG_TYPE(4, type)
#define ARG_TYPE5(type) ENC_ARG_TYPE(5, type)
#define DEC_ARG_TYPE(n, type) ((type >> (8 * n)) & 0xFF)

#define AF_UNIX 1
#define AF_INET 2
#define AF_INET6 10

#if defined(bpf_target_x86)
#define PT_REGS_PARM6(x) ((x)->r9)
#elif defined(bpf_target_arm64)
#define PT_REGS_PARM6(x) ((x)->regs[5])
#endif

#define UNDEFINED_SYSCALL 1000

#if defined(bpf_target_x86)
enum
{
    // file
    _SYS_OPEN = 2,
    _SYS_OPENAT = 257,
    _SYS_CLOSE = 3,
    _SYS_UNLINK = 87,
    _SYS_UNLINKAT = 263,
    _SYS_CHOWN = 92,
    _SYS_FCHOWNAT = 260,
    _SYS_SETUID = 105,
    _SYS_SETGID = 106,
    _SYS_MOUNT = 165,
    _SYS_UMOUNT = 166,

    // network
    _SYS_SOCKET = 41,
    _SYS_CONNECT = 42,
    _SYS_ACCEPT = 43,
    _SYS_BIND = 49,
    _SYS_LISTEN = 50,

    // process
    _SYS_EXECVE = 59,
    _SYS_EXECVEAT = 322,
};
#elif defined(bpf_target_arm64)
enum
{
    // file
    _SYS_OPEN = UNDEFINED_SYSCALL,
    _SYS_OPENAT = 56,
    _SYS_CLOSE = 57,
    _SYS_UNLINK = UNDEFINED_SYSCALL,
    _SYS_UNLINKAT = 35,
    _SYS_CHOWN = UNDEFINED_SYSCALL,
    _SYS_FCHOWNAT = 54,
    _SYS_SETUID = 146,
    _SYS_SETGID = 144,
    _SYS_MOUNT = 165,
    _SYS_UMOUNT = 166,

    // network
    _SYS_SOCKET = 198,
    _SYS_CONNECT = 203,
    _SYS_ACCEPT = 202,
    _SYS_BIND = 200,
    _SYS_LISTEN = 201,

    // process
    _SYS_EXECVE = 221,
    _SYS_EXECVEAT = 281,
};
#endif

// common event_ids
enum
{
    _DO_EXIT = 351,
    _SYS_RMDIR = 84,

    _SYS_PTRACE = 101,

    // accept/connect
    _TCP_CONNECT = 400,
    _TCP_ACCEPT = 401,
    _TCP_CONNECT_v6 = 402,
    _TCP_ACCEPT_v6 = 403,
};

#ifndef BTF_SUPPORTED
struct mnt_namespace
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 11, 0)
    atomic_t count;
#endif
    struct ns_common ns;
};

struct fs_struct {
	struct path pwd;
};

struct mount
{
    struct hlist_node mnt_hash;
    struct mount *mnt_parent;
    struct dentry *mnt_mountpoint;
    struct vfsmount mnt;
};
#endif

typedef struct __attribute__((__packed__)) sys_context
{
    u64 ts;

    u32 pid_id;
    u32 mnt_id;

    u32 host_ppid;
    u32 host_pid;

    u32 ppid;
    u32 pid;
    u32 uid;

    u32 event_id;
    u32 argnum;
    s64 retval;

    char comm[TASK_COMM_LEN];
    char cwd[CWD_LEN];
    char tty[TTY_LEN];
    u32 oid; // owner id
    // exec event will have non-zero execID
    u64 exec_id;
} sys_context_t;

#define BPF_MAP(_name, _type, _key_type, _value_type, _max_entries) \
    struct {                                                        \
  __uint(type, _type);                                              \
  __type(key, _key_type);                                           \
  __type(value, _value_type);                                       \
  __uint(max_entries, _max_entries);                                \
} _name SEC(".maps");                                              

#define BPF_HASH(_name, _key_type, _value_type) \
    BPF_MAP(_name, BPF_MAP_TYPE_HASH, _key_type, _value_type, 10240)

#define BPF_LRU_HASH(_name, _key_type, _value_type) \
    BPF_MAP(_name, BPF_MAP_TYPE_LRU_HASH, _key_type, _value_type, 10240)

#define BPF_ARRAY(_name, _value_type, _max_entries) \
    BPF_MAP(_name, BPF_MAP_TYPE_ARRAY, u32, _value_type, _max_entries)

#define BPF_PERCPU_ARRAY(_name, _value_type, _max_entries) \
    BPF_MAP(_name, BPF_MAP_TYPE_PERCPU_ARRAY, u32, _value_type, _max_entries)

#define BPF_PROG_ARRAY(_name, _max_entries) \
    BPF_MAP(_name, BPF_MAP_TYPE_PROG_ARRAY, u32, u32, _max_entries)

#define BPF_PERF_OUTPUT(_name) \
    BPF_MAP(_name, BPF_MAP_TYPE_PERF_EVENT_ARRAY, int, __u32, 1024)

BPF_LRU_HASH(pid_ns_map, u32, u32);

#ifdef BTF_SUPPORTED
#define GET_FIELD_ADDR(field) __builtin_preserve_access_index(&field)

#define READ_KERN(ptr)                                    \
    ({                                                    \
        typeof(ptr) _val;                                 \
        __builtin_memset((void *)&_val, 0, sizeof(_val)); \
        bpf_core_read((void *)&_val, sizeof(_val), &ptr); \
        _val;                                             \
    })
#else
#define GET_FIELD_ADDR(field) &field

#define READ_KERN(ptr)                                     \
    ({                                                     \
        typeof(ptr) _val;                                  \
        __builtin_memset((void *)&_val, 0, sizeof(_val));  \
        bpf_probe_read((void *)&_val, sizeof(_val), &ptr); \
        _val;                                              \
    })
#endif

typedef struct args
{
    unsigned long args[6];
} args_t;

BPF_LRU_HASH(args_map, u64, args_t);
BPF_LRU_HASH(file_map, u64, struct path);

typedef struct buffers
{
    u8 buf[MAX_BUFFER_SIZE];
} bufs_t;

BPF_PERCPU_ARRAY(bufs, bufs_t, 4);
BPF_PERCPU_ARRAY(bufs_offset, u32, 4);

BPF_PERF_OUTPUT(sys_events);

// == Visibility == //

enum
{
    _FILE_PROBE = 0,
    _PROCESS_PROBE = 1,
    _NETWORK_PROBE = 2,
    _CAPS_PROBE = 3,

    _TRACE_SYSCALL = 0,
    _IGNORE_SYSCALL = 1,
};

struct visibility
{
    __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
    __type(key, struct outer_key);
    __type(value, u32);
    /*
        https://github.com/kubernetes/community/blob/master/sig-scalability/configs-and-limits/thresholds.md#kubernetes-thresholds
        The link above mentions that a node can have a maximun of 110 pods.
    */
    __uint(max_entries, 65535);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
};

struct visibility kubearmor_visibility SEC(".maps");

#define DEFAULT_VISIBILITY_KEY 0xc0ffee

// == Config == //

enum
{
    _MONITOR_HOST = 0,
    _MONITOR_CONTAINER = 1,
    _ENFORCER_BPFLSM = 2,
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

// exec maps
BPF_LRU_HASH(ns_transition, u32, struct outer_key);

struct exec_pid_map
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u32);
    __type(value, u64);
    __uint(max_entries, 10240);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
};

struct exec_pid_map kubearmor_exec_pids SEC(".maps");

// == Kernel Helpers == //

static __always_inline u32 get_pid_ns_id(struct nsproxy *ns)
{
    struct pid_namespace *pidns = READ_KERN(ns->pid_ns_for_children);
    return READ_KERN(pidns->ns.inum);
}

static __always_inline u32 get_mnt_ns_id(struct nsproxy *ns)
{
    struct mnt_namespace *mntns = READ_KERN(ns->mnt_ns);
    return READ_KERN(mntns->ns.inum);
}

static inline struct mount *real_mount(struct vfsmount *mnt)
{
    return container_of(mnt, struct mount, mnt);
}

static __always_inline u32 get_task_pid_ns_id(struct task_struct *task)
{
    return get_pid_ns_id(READ_KERN(task->nsproxy));
}

static __always_inline u32 get_task_mnt_ns_id(struct task_struct *task)
{
    return get_mnt_ns_id(READ_KERN(task->nsproxy));
}

static __always_inline u32 get_task_pid_vnr(struct task_struct *task)
{
    struct pid *pid = NULL;

#if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 19, 0) && !defined(RHEL_RELEASE_GT_8_0) && !defined(BTF_SUPPORTED))
    pid = READ_KERN(task->pids[PIDTYPE_PID].pid);
#else
    pid = READ_KERN(task->thread_pid);
#endif

    unsigned int level = READ_KERN(pid->level);
    return READ_KERN(pid->numbers[level].nr);
}

static __always_inline u32 get_task_ns_tgid(struct task_struct *task)
{
    struct task_struct *group_leader = READ_KERN(task->group_leader);
    return get_task_pid_vnr(group_leader);
}

static __always_inline u32 get_task_ns_pid(struct task_struct *task)
{
    return get_task_pid_vnr(task);
}

static __always_inline u32 get_task_ns_ppid(struct task_struct *task)
{
    struct task_struct *real_parent = READ_KERN(task->real_parent);
    return get_task_pid_vnr(real_parent);
}

static __always_inline u32 get_task_ppid(struct task_struct *task)
{
    struct task_struct *parent = READ_KERN(task->parent);
    return READ_KERN(parent->pid);
}

static struct file *get_task_file(struct task_struct *task)
{
    struct mm_struct *mm = READ_KERN(task->mm);
    return READ_KERN(mm->exe_file);
}

static __always_inline void get_outer_key(struct outer_key *pokey,
                                          struct task_struct *t)
{
    pokey->pid_ns = get_task_pid_ns_id(t);
    pokey->mnt_ns = get_task_mnt_ns_id(t);
    if (pokey->pid_ns == PROC_PID_INIT_INO)
    {
        pokey->pid_ns = 0;
        pokey->mnt_ns = 0;
    }
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

// == Pid NS Management == //

static __always_inline u32 add_pid_ns()
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    u32 one = 1;
    u32 pid_ns = get_task_pid_ns_id(task);
    if (pid_ns == PROC_PID_INIT_INO && get_kubearmor_config(_MONITOR_HOST))
    { // host
        u32 pid = bpf_get_current_pid_tgid() >> 32;
        if (!bpf_map_lookup_elem(&pid_ns_map, &pid))
        {
            // untracked host pid, adding to pid map
            bpf_map_update_elem(&pid_ns_map, &pid, &one, BPF_ANY);
        }

        return pid;
    }
    else if(get_kubearmor_config(_MONITOR_CONTAINER))
    { // container
        if (!bpf_map_lookup_elem(&pid_ns_map, &pid_ns))
        {
            // untracked pid ns, adding to pid ns map
            bpf_map_update_elem(&pid_ns_map, &pid_ns, &one, BPF_ANY);
        }
        
        return pid_ns;
    }

    return 0;
}

static __always_inline u32 remove_pid_ns()
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    u32 pid_ns = get_task_pid_ns_id(task);
    if (pid_ns == PROC_PID_INIT_INO && get_kubearmor_config(_MONITOR_HOST))
    { // host
        u32 pid = bpf_get_current_pid_tgid() >> 32;
        if (bpf_map_lookup_elem(&pid_ns_map, &pid) != 0)
        {
            bpf_map_delete_elem(&pid_ns_map, &pid);
            return 0;
        }
    }
    else if(get_kubearmor_config(_MONITOR_CONTAINER))
    { // container
        if (get_task_ns_pid(task) == 1)
        {
            u32 mnt_ns = get_task_mnt_ns_id(task);
            struct outer_key key = {
                .pid_ns = pid_ns,
                .mnt_ns = mnt_ns
            };
            bpf_map_delete_elem(&kubearmor_alert_throttle, &key);
            bpf_map_delete_elem(&pid_ns_map, &pid_ns);
            return 0;
        }
    }

    return 0;
}

static __always_inline u32 drop_syscall(u32 scope)
{
    struct outer_key okey;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    get_outer_key(&okey, task);

    // We try check global config to check if lookup for container fails do we need to ignore or trace a syscall
    // In case lookup for global config fails we continue the container check 
    // and choose to not drop events if either of them are not found

    u32 default_trace = _TRACE_SYSCALL;
    struct outer_key defaultvizkey;
    defaultvizkey.pid_ns = DEFAULT_VISIBILITY_KEY;
    defaultvizkey.mnt_ns = DEFAULT_VISIBILITY_KEY;
    u32 *d_visibility = bpf_map_lookup_elem(&kubearmor_visibility, &defaultvizkey);
    if (d_visibility) {
        u32 *d_on_off_switch = bpf_map_lookup_elem(d_visibility, &scope);
        if (d_on_off_switch)
            if (*d_on_off_switch)
                default_trace = _IGNORE_SYSCALL;
    }


    u32 *ns_visibility = bpf_map_lookup_elem(&kubearmor_visibility, &okey);
    if (!ns_visibility)
    {
        return default_trace;
    }

    u32 *on_off_switch = bpf_map_lookup_elem(ns_visibility, &scope);
    if (!on_off_switch)
    {
        return default_trace;
    }

    if (*on_off_switch)
        return _IGNORE_SYSCALL;

    return _TRACE_SYSCALL;
}

static __always_inline u32 skip_syscall()
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    u32 pid_ns = get_task_pid_ns_id(task);

    if (pid_ns == PROC_PID_INIT_INO && get_kubearmor_config(_MONITOR_HOST))
    { // host
        u32 pid = bpf_get_current_pid_tgid() >> 32;
        if (bpf_map_lookup_elem(&pid_ns_map, &pid) != 0)
        {
            return !add_pid_ns();
        }
    }
    else if(get_kubearmor_config(_MONITOR_CONTAINER))
    { // container
        if (bpf_map_lookup_elem(&pid_ns_map, &pid_ns) == 0)
        {
            return !add_pid_ns();
        }
    }

    return _TRACE_SYSCALL;
}

// == Buffer Management == //

#define DATA_BUF_TYPE 0
#define EXEC_BUF_TYPE 1
#define FILE_BUF_TYPE 2
#define CWD_BUF_TYPE 3

static __always_inline bufs_t *get_buffer(int buf_type)
{
    return bpf_map_lookup_elem(&bufs, &buf_type);
}

static __always_inline void set_buffer_offset(int buf_type, u32 off)
{
    bpf_map_update_elem(&bufs_offset, &buf_type, &off, BPF_ANY);
}

static __always_inline u32 *get_buffer_offset(int buf_type)
{
    return bpf_map_lookup_elem(&bufs_offset, &buf_type);
}

static __always_inline int save_context_to_buffer(bufs_t *bufs_p, void *ptr)
{
    if (bpf_probe_read(&(bufs_p->buf[0]), sizeof(sys_context_t), ptr) == 0)
    {
        return sizeof(sys_context_t);
    }

    return 0;
}

static __always_inline int save_str_to_buffer(bufs_t *bufs_p, void *ptr) {
    u32 *off = get_buffer_offset(DATA_BUF_TYPE);
    if (off == NULL) {
        return -1;
    }

    if (*off >= MAX_BUFFER_SIZE) {
        return 0;
    }

    u32 type_pos = *off;
    if (type_pos >= MAX_BUFFER_SIZE || type_pos + 1 > MAX_BUFFER_SIZE) {
        return 0;
    }

    if (MAX_BUFFER_SIZE - type_pos < (1 + sizeof(int) + 1)) {
        return 0;
    }

    u32 size_pos = type_pos + 1;
    if (size_pos >= MAX_BUFFER_SIZE || 
        size_pos + sizeof(int) > MAX_BUFFER_SIZE) {
        return 0;
    }

    u8 type_val = STR_T;
    if (bpf_probe_read(&(bufs_p->buf[type_pos]), sizeof(u8), &type_val) < 0) {
        return 0;
    }

    u32 str_pos = size_pos + sizeof(int);
    if (str_pos >= MAX_BUFFER_SIZE -1 || str_pos + MAX_STRING_SIZE > MAX_BUFFER_SIZE -1) {
        return 0;
    }

    u32 remaining_space = MAX_BUFFER_SIZE - str_pos;
    u32 read_size = remaining_space;
    if (read_size > MAX_STRING_SIZE) {
        read_size = MAX_STRING_SIZE;
    }

    if (read_size < MAX_STRING_SIZE) {
        return 0;
    }

    int sz = bpf_probe_read_str(&(bufs_p->buf[str_pos]), read_size, ptr);
    if (sz <= 0) {
        return 0;
    }

    if (bpf_probe_read(&(bufs_p->buf[size_pos]), sizeof(int), &sz) < 0) {
        return 0;
    }

    u32 new_off = str_pos + sz;
    if (new_off > MAX_BUFFER_SIZE) {
        return 0;
    }
    
    set_buffer_offset(DATA_BUF_TYPE, new_off);
    
    return sz + sizeof(int);
}

static __always_inline bool prepend_path(struct path *path, bufs_t *string_p, int buf_type)
{
    char slash = '/';
    char null = '\0';
    int offset = MAX_STRING_SIZE;

    if (path == NULL || string_p == NULL)
    {
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
    for (int i = 0; i < MAX_LOOP_LIMIT; i++)
    {
        bpf_probe_read(&parent, sizeof(struct dentry *), &dentry->d_parent);
        bpf_probe_read(&mnt_root, sizeof(struct dentry *), &vfsmnt->mnt_root);

        if (dentry == mnt_root)
        {
            bpf_probe_read(&m, sizeof(struct mount *), &mnt->mnt_parent);
            if (mnt != m)
            {
                bpf_probe_read(&dentry, sizeof(struct dentry *), &mnt->mnt_mountpoint);
                bpf_probe_read(&mnt, sizeof(struct mount *), &mnt->mnt_parent);
                vfsmnt = &mnt->mnt;
                continue;
            }

            /* Global root */
            break;
        }

        if (dentry == parent)
        {
            break;
        }

        // get d_name
        bpf_probe_read(&d_name, sizeof(struct qstr), &dentry->d_name);
        offset -= (d_name.len + 1);
        if (offset < 0)
            break;

        int sz = bpf_probe_read_str(&(string_p->buf[(offset) & (MAX_STRING_SIZE - 1)]), (d_name.len + 1) & (MAX_STRING_SIZE - 1), d_name.name);
        if (sz > 1)
        {
            bpf_probe_read(&(string_p->buf[(offset + d_name.len) & (MAX_STRING_SIZE - 1)]), 1, &slash);
        }
        else
        {
            offset += (d_name.len + 1);
        }

        dentry = parent;
    }

    if (offset == MAX_STRING_SIZE)
    {
        return false;
    }

    bpf_probe_read(&(string_p->buf[MAX_STRING_SIZE - 1]), 1, &null);
    offset--;

    bpf_probe_read(&(string_p->buf[offset & (MAX_STRING_SIZE - 1)]), 1, &slash);
    set_buffer_offset(buf_type, offset);

    return true;
}

static __always_inline struct path *load_file_p()
{
    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct path *p = bpf_map_lookup_elem(&file_map, &pid_tgid);
    bpf_map_delete_elem(&file_map, &pid_tgid);
    return p;
}

static __always_inline int save_file_to_buffer(bufs_t *bufs_p, void *ptr)
{
    struct path *path = load_file_p();

    bufs_t *string_p = get_buffer(FILE_BUF_TYPE);
    if (string_p == NULL)
        return save_str_to_buffer(bufs_p, ptr);

    if (!prepend_path(path, string_p, FILE_BUF_TYPE))
    {
        return save_str_to_buffer(bufs_p, ptr);
    }

    u32 *off = get_buffer_offset(FILE_BUF_TYPE);
    if (off == NULL)
        return save_str_to_buffer(bufs_p, ptr);

    return save_str_to_buffer(bufs_p, (void *)&string_p->buf[*off]);
}

static __always_inline int save_to_buffer(bufs_t *bufs_p, void *ptr, int size, u8 type)
{
// the biggest element that can be saved with this function should be defined here
#define MAX_ELEMENT_SIZE sizeof(struct sockaddr_un)

    if (type == 0)
    {
        return 0;
    }

    u32 *off = get_buffer_offset(DATA_BUF_TYPE);
    if (off == NULL)
    {
        return -1;
    }

    if (*off > MAX_BUFFER_SIZE - MAX_ELEMENT_SIZE)
    {
        return 0;
    }

    if (bpf_probe_read(&(bufs_p->buf[*off]), 1, &type) != 0)
    {
        return 0;
    }

    *off += 1;

    if (*off > MAX_BUFFER_SIZE - MAX_ELEMENT_SIZE)
    {
        return 0;
    }

    if (bpf_probe_read(&(bufs_p->buf[*off]), size, ptr) == 0)
    {
        *off += size;
        set_buffer_offset(DATA_BUF_TYPE, *off);
        return size;
    }

    return 0;
}

static __always_inline int save_argv(bufs_t *bufs_p, void *ptr)
{
    const char *argp = NULL;
    bpf_probe_read(&argp, sizeof(argp), ptr);

    if (argp)
    {
        return save_str_to_buffer(bufs_p, (void *)(argp));
    }

    return 0;
}

static __always_inline int save_str_arr_to_buffer(bufs_t *bufs_p, const char __user *const __user *ptr)
{
    save_to_buffer(bufs_p, NULL, 0, STR_ARR_T);

#pragma unroll
    for (int i = 0; i < MAX_STR_ARR_ELEM; i++)
    {
        if (save_argv(bufs_p, (void *)&ptr[i]) == 0)
        {
            goto out;
        }
    }

    char ellipsis[] = "...";
    save_str_to_buffer(bufs_p, (void *)ellipsis);

out:
    save_to_buffer(bufs_p, NULL, 0, STR_ARR_T);

    return 0;
}

static __always_inline int save_args_to_buffer(u64 types, args_t *args)
{
    if (types == 0)
    {
        return 0;
    }

    bufs_t *bufs_p = get_buffer(DATA_BUF_TYPE);
    if (bufs_p == NULL)
    {
        return 0;
    }

#pragma unroll
    for (int i = 0; i < MAX_ARGS; i++)
    {
        switch (DEC_ARG_TYPE(i, types))
        {
        case NONE_T:
            break;
        case INT_T:
            save_to_buffer(bufs_p, (void *)&(args->args[i]), sizeof(int), INT_T);
            break;
        case OPEN_FLAGS_T:
            save_to_buffer(bufs_p, (void *)&(args->args[i]), sizeof(int), OPEN_FLAGS_T);
            break;
        case FILE_TYPE_T:
            save_file_to_buffer(bufs_p, (void *)args->args[i]);
            break;
        case PTRACE_REQ_T:
            save_to_buffer(bufs_p, (void *)&(args->args[i]), sizeof(int), PTRACE_REQ_T);
            break;
        case MOUNT_FLAG_T:
            save_to_buffer(bufs_p, (void *)&(args->args[i]), sizeof(int), MOUNT_FLAG_T);
            break;
        case UMOUNT_FLAG_T:
            save_to_buffer(bufs_p, (void *)&(args->args[i]), sizeof(int), UMOUNT_FLAG_T);
            break;
        case STR_T:
            save_str_to_buffer(bufs_p, (void *)args->args[i]);
            break;
        case SOCK_DOM_T:
            save_to_buffer(bufs_p, (void *)&(args->args[i]), sizeof(int), SOCK_DOM_T);
            break;
        case SOCK_TYPE_T:
            save_to_buffer(bufs_p, (void *)&(args->args[i]), sizeof(int), SOCK_TYPE_T);
            break;
        case SOCKADDR_T:
            if (args->args[i])
            {
                short family = 0;
                bpf_probe_read(&family, sizeof(short), (void *)args->args[i]);
                switch (family)
                {
                case AF_UNIX:
                    save_to_buffer(bufs_p, (void *)(args->args[i]), sizeof(struct sockaddr_un), SOCKADDR_T);
                    break;
                case AF_INET:
                    save_to_buffer(bufs_p, (void *)(args->args[i]), sizeof(struct sockaddr_in), SOCKADDR_T);
                    break;
                case AF_INET6:
                    save_to_buffer(bufs_p, (void *)(args->args[i]), sizeof(struct sockaddr_in6), SOCKADDR_T);
                    break;
                default:
                    save_to_buffer(bufs_p, (void *)&family, sizeof(short), SOCKADDR_T);
                }
            }
            break;
        case UNLINKAT_FLAG_T:
            save_to_buffer(bufs_p, (void *)&(args->args[i]), sizeof(int), UNLINKAT_FLAG_T);
            break;
        }
    }

    return 0;
}

static __always_inline int events_perf_submit(struct pt_regs *ctx)
{
    bufs_t *bufs_p = get_buffer(DATA_BUF_TYPE);
    if (bufs_p == NULL)
        return -1;

    u32 *off = get_buffer_offset(DATA_BUF_TYPE);
    if (off == NULL)
        return -1;

    void *data = bufs_p->buf;
    int size = *off & (MAX_BUFFER_SIZE - 1);

    return bpf_perf_event_output(ctx, &sys_events, BPF_F_CURRENT_CPU, data, size);
}

// == Full Path == //

//  args:  const struct path *dir, struct dentry *dentry
static __always_inline int security_path__dir_path_args(struct pt_regs *ctx)
{
    struct path *dir = (struct path *)PT_REGS_PARM1(ctx);
    struct dentry *dentry = (struct dentry *)PT_REGS_PARM2(ctx);
    if (dir == NULL || dentry == NULL)
    {
        return 0;
    }

    struct path p;
    p.dentry = READ_KERN(dentry);
    p.mnt = READ_KERN(dir->mnt);

    u64 tgid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&file_map, &tgid, &p, BPF_ANY);

    return 0;
}

//  args:  struct task_struct *task
static __always_inline int security_path_task_arg(struct pt_regs *ctx)
{
    struct task_struct *task = (struct task_struct *)PT_REGS_PARM1(ctx);
    if (task == NULL)
    {
        return 0;
    }

    struct file *file_p = get_task_file(task);
    if (file_p == NULL)
        return 0;

    struct path p = READ_KERN(file_p->f_path);

    u64 tgid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&file_map, &tgid, &p, BPF_ANY);
    return 0;
}

// == Context Management == //

static __always_inline u32 init_context(sys_context_t *context)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    __builtin_memset((void *)&context->exec_id, 0, sizeof(context->exec_id));
    context->ts = bpf_ktime_get_ns();

    context->host_ppid = get_task_ppid(task);
    __u32 host_pid = bpf_get_current_pid_tgid() >> 32;
    context->host_pid = host_pid;

    u32 pid = get_task_ns_tgid(task);
    if (context->host_pid == pid)
    { // host
        context->pid_id = 0;
        context->mnt_id = 0;

        context->ppid = get_task_ppid(task);
        context->pid = bpf_get_current_pid_tgid() >> 32;
    }
    else
    { // container
        context->pid_id = get_task_pid_ns_id(task);
        context->mnt_id = get_task_mnt_ns_id(task);

        context->ppid = get_task_ns_ppid(task);
        context->pid = pid;
        
        // check if process is part of exec
        u64 *exec_id = bpf_map_lookup_elem(&kubearmor_exec_pids, &host_pid);
        if (exec_id) {
            context->exec_id = *exec_id;
        }
    }

    context->uid = bpf_get_current_uid_gid();

    bpf_get_current_comm(&context->comm, sizeof(context->comm));

    // check if tty is attached
    struct signal_struct *signal;
    signal = READ_KERN(task->signal);
    if (signal != NULL){
        struct tty_struct *tty = READ_KERN(signal->tty);
        if (tty != NULL){
            // a tty is attached
            bpf_probe_read_str(&context->tty, TTY_LEN, (void *)tty->name);
        }
    }

#if LINUX_VERSION_CODE > KERNEL_VERSION(5, 2, 0) // min version that supports 1 million instructions
    struct fs_struct *fs;
    fs = READ_KERN(task->fs);
    struct path path = READ_KERN(fs->pwd);

    bufs_t *string_p = get_buffer(CWD_BUF_TYPE);
    if (string_p == NULL)
        return 0;

    if (!prepend_path(&path, string_p, CWD_BUF_TYPE))
    {
        return 0;
    }

    u32 *off = get_buffer_offset(CWD_BUF_TYPE);
    if (off == NULL)
        return 0;

    bpf_probe_read_str(&context->cwd, CWD_LEN, (void *)&string_p->buf[*off]);
#endif
    return 0;
}

// == Alert Throttling == //

// To check if subsequent alerts should be dropped per container
static __always_inline bool should_drop_alerts_per_container(sys_context_t *context, struct pt_regs *ctx, u32 types, args_t *args) {
#if LINUX_VERSION_CODE > KERNEL_VERSION(5, 2, 0)

    // throttling for host in case of apparmor is handled in userspace
    if (context->pid_id == 0 && context->mnt_id == 0) {
        return false;
    }

    u64 current_timestamp = bpf_ktime_get_ns();

    struct outer_key key = {
        .pid_ns = context->pid_id,
        .mnt_ns = context->mnt_id
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
    u64 max = (u64)get_kubearmor_config(_MAX_ALERT_PER_SEC);

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

    if (state->event_count > max) {
        state->event_count = 0;
        state->throttle = 1;
        bpf_map_update_elem(&kubearmor_alert_throttle, &key, state, BPF_ANY);

        // Generating Throttling Alert 
        context->event_id = _DROPPING_ALERT;
        set_buffer_offset(DATA_BUF_TYPE, sizeof(sys_context_t));

        bufs_t *bufs_p = get_buffer(DATA_BUF_TYPE);
        if (bufs_p == NULL) {
            return 0;
        }

        save_context_to_buffer(bufs_p, (void *)context);

        if (types != 0) {
            save_args_to_buffer(types, args);
        }

        events_perf_submit(ctx);
        return true; 
    }

    bpf_map_update_elem(&kubearmor_alert_throttle, &key, state, BPF_ANY);
#endif
    return false; 
}

// ==== Container Exec Events ====

SEC("tracepoint/syscalls/sys_enter_setns")
int sys_enter_setns(struct trace_event_raw_sys_enter *ctx)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    struct task_struct *t = (struct task_struct *)bpf_get_current_task();

    struct outer_key data = {};
    data.pid_ns = get_task_pid_ns_id(t);
    data.mnt_ns = get_task_mnt_ns_id(t);

    bpf_map_update_elem(&ns_transition, &pid, &data, BPF_ANY);
    
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_setns")
int sys_exit_setns(struct trace_event_raw_sys_exit *ctx)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    struct outer_key *pre_ns_data;
    
    pre_ns_data = bpf_map_lookup_elem(&ns_transition, &pid);
    if (!pre_ns_data)
        return 0;
    
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    u32 new_pid_ns = get_task_pid_ns_id(t);
    u32 new_mnt_ns = get_task_mnt_ns_id(t);
    
    if (pre_ns_data->mnt_ns != new_mnt_ns || 
        pre_ns_data->pid_ns != new_pid_ns ) {
        
        struct outer_key key = {};
        key.mnt_ns = new_mnt_ns;
        key.pid_ns = new_pid_ns;
        
        u32 *matches = bpf_map_lookup_elem(&kubearmor_visibility, &key);
        u64 exec_id = bpf_ktime_get_ns() | pid;
        if (matches) {   
          bpf_map_update_elem(&kubearmor_exec_pids, &pid, &exec_id, BPF_ANY);
        }

    }
    bpf_map_delete_elem(&ns_transition, &pid);
    return 0;
}

SEC("tracepoint/sched/sched_process_fork")
int sched_process_fork(struct trace_event_raw_sched_process_fork *ctx)
{
    u32 parent_pid = bpf_get_current_pid_tgid() >> 32;
    u32 child_pid = ctx->child_pid;
    
    u32 *exists = bpf_map_lookup_elem(&kubearmor_exec_pids, &parent_pid);
    if (exists) {
        bpf_map_update_elem(&kubearmor_exec_pids, &child_pid, exists, BPF_ANY);
    }

    return 0;
}

SEC("kprobe/security_path_mknod")
int kprobe__security_path_mknod(struct pt_regs *ctx)
{
    if (skip_syscall())
        return 0;
    return security_path__dir_path_args(ctx);
}

SEC("kprobe/security_path_unlink")
int kprobe__security_path_unlink(struct pt_regs *ctx)
{
    if (skip_syscall())
        return 0;
    return security_path__dir_path_args(ctx);
}

SEC("kprobe/security_path_rmdir")
int kprobe__security_path_rmdir(struct pt_regs *ctx)
{
    if (skip_syscall())
        return 0;
    return security_path__dir_path_args(ctx);
}

SEC("kprobe/security_ptrace_access_check")
int kprobe__security_ptrace_access_check(struct pt_regs *ctx)
{
    if (skip_syscall())
        return 0;
    return security_path_task_arg(ctx);
}

SEC("kprobe/security_bprm_check")
int kprobe__security_bprm_check(struct pt_regs *ctx)
{
    if (skip_syscall())
        return 0;

    if (get_kubearmor_config(_ENFORCER_BPFLSM) && drop_syscall(_PROCESS_PROBE))
    {
        return 0;
    }
    sys_context_t context = {};

    //

    struct linux_binprm *bprm = (struct linux_binprm *)PT_REGS_PARM1(ctx);

    struct file *f = READ_KERN(bprm->file);
    if (f == NULL)
        return 0;

    struct path p;
    bpf_probe_read(&p, sizeof(struct path), GET_FIELD_ADDR(f->f_path));

    bufs_t *string_p = get_buffer(EXEC_BUF_TYPE);
    if (string_p == NULL)
        return -1;

    if (!prepend_path(&p, string_p, EXEC_BUF_TYPE))
    {
        return -1;
    }

    u32 *off = get_buffer_offset(EXEC_BUF_TYPE);
    if (off == NULL)
        return -1;

    //

    init_context(&context);

    context.event_id = _SECURITY_BPRM_CHECK;
    context.argnum = 1;
    context.retval = 0;

    set_buffer_offset(DATA_BUF_TYPE, sizeof(sys_context_t));

    bufs_t *bufs_p = get_buffer(DATA_BUF_TYPE);
    if (bufs_p == NULL)
        return 0;

    save_context_to_buffer(bufs_p, (void *)&context);
    save_str_to_buffer(bufs_p, (void *)&string_p->buf[*off]);

    events_perf_submit(ctx);

    return 0;
}

SEC("kprobe/security_file_open")
int kprobe__security_file_open(struct pt_regs *ctx)
{
    if (skip_syscall())
        return 0;

    struct file *f = (struct file *)PT_REGS_PARM1(ctx);

    struct path p = READ_KERN(f->f_path);

    u64 tgid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&file_map, &tgid, &p, BPF_ANY);

    return 0;
}

// == Syscall Hooks (Process) == //

SEC("kprobe/__x64_sys_execve")
int kprobe__execve(struct pt_regs *ctx)
{
    if (skip_syscall()) // keeping track of pidns even if we need to drop the syscall so as to facilitate data for other hooks
    {
        return 0;
    }

    if (get_kubearmor_config(_ENFORCER_BPFLSM) && drop_syscall(_PROCESS_PROBE))
    {   
        return 0;
    }

    sys_context_t context = {};

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 17, 0)
    char *filename = (char *)PT_REGS_PARM1(ctx);
    unsigned long argv = PT_REGS_PARM2(ctx);
#else
    struct pt_regs *ctx2 = (struct pt_regs *)PT_REGS_PARM1(ctx);
    char *filename = (char *)READ_KERN(PT_REGS_PARM1(ctx2));
    unsigned long argv = READ_KERN(PT_REGS_PARM2(ctx2));
#endif

    init_context(&context);

    context.event_id = _SYS_EXECVE;
    context.argnum = 2;
    context.retval = 0;

    set_buffer_offset(DATA_BUF_TYPE, sizeof(sys_context_t));

    bufs_t *bufs_p = get_buffer(DATA_BUF_TYPE);
    if (bufs_p == NULL)
        return 0;

    save_context_to_buffer(bufs_p, (void *)&context);

    save_str_to_buffer(bufs_p, filename);
    save_str_arr_to_buffer(bufs_p, (const char *const *)argv);

    events_perf_submit(ctx);

    return 0;
}

SEC("kretprobe/__x64_sys_execve")
int kretprobe__execve(struct pt_regs *ctx)
{
    if (get_kubearmor_config(_ENFORCER_BPFLSM) && drop_syscall(_PROCESS_PROBE))
    {
        return 0;
    }

    if (skip_syscall())
        return 0;

    sys_context_t context = {};

    init_context(&context);

    context.event_id = _SYS_EXECVE;
    context.argnum = 0;
    context.retval = PT_REGS_RC(ctx);

    // skip if No such file/directory or if there is an EINPROGRESS
    // EINPROGRESS error, happens when the socket is non-blocking and the connection cannot be completed immediately.
    if (context.retval == -2 || context.retval == -115)
    {
        return 0;
    }

    if (context.retval >= 0 && drop_syscall(_PROCESS_PROBE))
    {
        // we need alerts for apparmor enforcer hence only dropping passed logs
        return 0;
    }

    u32 types;
    args_t args = {};
    if (context.retval < 0 && !get_kubearmor_config(_ENFORCER_BPFLSM) && get_kubearmor_config(_ALERT_THROTTLING) && should_drop_alerts_per_container(&context, ctx, types, &args))
    {
        return 0;
    }

    set_buffer_offset(DATA_BUF_TYPE, sizeof(sys_context_t));

    bufs_t *bufs_p = get_buffer(DATA_BUF_TYPE);
    if (bufs_p == NULL)
        return 0;

    save_context_to_buffer(bufs_p, (void *)&context);

    events_perf_submit(ctx);

    return 0;
}

SEC("kprobe/__x64_sys_execveat")
int kprobe__execveat(struct pt_regs *ctx)
{
    if (skip_syscall())
        return 0;

    if (get_kubearmor_config(_ENFORCER_BPFLSM) && drop_syscall(_PROCESS_PROBE))
    {
        return 0;
    }

    sys_context_t context = {};

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 17, 0)

    const int dirfd = PT_REGS_PARM1(ctx);

    const char __user *pathname = (void *)&PT_REGS_PARM2(ctx);

    unsigned long argv = PT_REGS_PARM3(ctx);

    int flags = (int)PT_REGS_PARM5(ctx);

#else
    struct pt_regs *ctx2 = (struct pt_regs *)PT_REGS_PARM1(ctx);

    const int dirfd = READ_KERN(PT_REGS_PARM1(ctx2));

    const char __user *pathname = (void *)READ_KERN(PT_REGS_PARM2(ctx2));

    unsigned long argv = READ_KERN(PT_REGS_PARM3(ctx2));

    int flags = (int)READ_KERN(PT_REGS_PARM5(ctx2));
#endif

    init_context(&context);

    context.event_id = _SYS_EXECVEAT;
    context.argnum = 4;
    context.retval = 0;

    set_buffer_offset(DATA_BUF_TYPE, sizeof(sys_context_t));

    bufs_t *bufs_p = get_buffer(DATA_BUF_TYPE);
    if (bufs_p == NULL)
        return 0;

    save_context_to_buffer(bufs_p, (void *)&context);

    save_to_buffer(bufs_p, (void *)&dirfd, sizeof(int), INT_T);
    save_str_to_buffer(bufs_p, (void *)pathname);
    save_str_arr_to_buffer(bufs_p, (const char *const *)argv);
    save_to_buffer(bufs_p, (void *)&flags, sizeof(int), EXEC_FLAGS_T);

    events_perf_submit(ctx);

    return 0;
}

SEC("kretprobe/__x64_sys_execveat")
int kretprobe__execveat(struct pt_regs *ctx)
{
    if (skip_syscall())
        return 0;
    
    if (get_kubearmor_config(_ENFORCER_BPFLSM) && drop_syscall(_PROCESS_PROBE))
    {
        return 0;
    }

    sys_context_t context = {};

    init_context(&context);

    context.event_id = _SYS_EXECVEAT;
    context.argnum = 0;
    context.retval = PT_REGS_RC(ctx);

    // skip if No such file/directory or if there is an EINPROGRESS
    // EINPROGRESS error, happens when the socket is non-blocking and the connection cannot be completed immediately.
    if (context.retval == -2 || context.retval == -115)
    {
        return 0;
    }

    if (context.retval >= 0 && drop_syscall(_PROCESS_PROBE))
    {
        // we need alerts for apparmor enforcer hence only dropping passed logs
        return 0;
    }

    u32 types;
    args_t args = {};

    if (context.retval < 0 && !get_kubearmor_config(_ENFORCER_BPFLSM) && get_kubearmor_config(_ALERT_THROTTLING) && should_drop_alerts_per_container(&context, ctx, types, &args))
    {
        return 0;
    }

    set_buffer_offset(DATA_BUF_TYPE, sizeof(sys_context_t));

    bufs_t *bufs_p = get_buffer(DATA_BUF_TYPE);
    if (bufs_p == NULL)
        return 0;

    save_context_to_buffer(bufs_p, (void *)&context);

    events_perf_submit(ctx);

    return 0;
}

SEC("kprobe/do_exit")
int kprobe__do_exit(struct pt_regs *ctx)
{
    if (skip_syscall())
        return 0;

    u64 tgid = bpf_get_current_pid_tgid();

    // delete entry for file access which are not successful and are not deleted from file_map since kretprobe/__x64_sys_openat hook is not triggered
    bpf_map_delete_elem(&file_map, &tgid);

    // delete entry for exec (host) pid
    bpf_map_delete_elem(&kubearmor_exec_pids, &tgid);

    sys_context_t context = {};

    const long code = PT_REGS_PARM1(ctx);

    init_context(&context);

    context.event_id = _DO_EXIT;
    context.argnum = 0;
    context.retval = code;

    remove_pid_ns();

    if (get_kubearmor_config(_ENFORCER_BPFLSM) && drop_syscall(_PROCESS_PROBE))
    {
        // dropping after map cleanup
        return 0;
    }

    set_buffer_offset(DATA_BUF_TYPE, sizeof(sys_context_t));

    bufs_t *bufs_p = get_buffer(DATA_BUF_TYPE);
    if (bufs_p == NULL)
        return 0;

    save_context_to_buffer(bufs_p, (void *)&context);

    events_perf_submit(ctx);

    return 0;
}

// == Syscall Hooks (File) == //

static __always_inline int save_args(u32 event_id, struct pt_regs *ctx)
{
    args_t args = {};

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 17, 0)
    args.args[0] = PT_REGS_PARM1(ctx);
    args.args[1] = PT_REGS_PARM2(ctx);
    args.args[2] = PT_REGS_PARM3(ctx);
    args.args[3] = PT_REGS_PARM4(ctx);
    args.args[4] = PT_REGS_PARM5(ctx);
    args.args[5] = PT_REGS_PARM6(ctx);
#else
    struct pt_regs *ctx2 = (struct pt_regs *)PT_REGS_PARM1(ctx);
    bpf_probe_read(&args.args[0], sizeof(args.args[0]), &PT_REGS_PARM1(ctx2));
    bpf_probe_read(&args.args[1], sizeof(args.args[1]), &PT_REGS_PARM2(ctx2));
    bpf_probe_read(&args.args[2], sizeof(args.args[2]), &PT_REGS_PARM3(ctx2));
    bpf_probe_read(&args.args[3], sizeof(args.args[3]), &PT_REGS_PARM4_SYSCALL(ctx2));
    bpf_probe_read(&args.args[4], sizeof(args.args[4]), &PT_REGS_PARM5(ctx2));
    bpf_probe_read(&args.args[5], sizeof(args.args[5]), &PT_REGS_PARM6(ctx2));
#endif

    u32 tgid = bpf_get_current_pid_tgid();
    u64 id = ((u64)event_id << 32) | tgid;

    bpf_map_update_elem(&args_map, &id, &args, BPF_ANY);

    return 0;
}

static __always_inline int load_args(u32 event_id, args_t *args)
{
    u32 tgid = bpf_get_current_pid_tgid();
    u64 id = ((u64)event_id << 32) | tgid;

    args_t *saved_args = bpf_map_lookup_elem(&args_map, &id);
    if (saved_args == 0)
    {
        return -1; // missed entry or not a container
    }

    args->args[0] = saved_args->args[0];
    args->args[1] = saved_args->args[1];
    args->args[2] = saved_args->args[2];
    args->args[3] = saved_args->args[3];
    args->args[4] = saved_args->args[4];
    args->args[5] = saved_args->args[5];

    bpf_map_delete_elem(&args_map, &id);

    return 0;
}

static __always_inline int get_arg_num(u64 types)
{
    unsigned int i, argnum = 0;

#pragma unroll
    for (i = 0; i < MAX_ARGS; i++)
    {
        if (DEC_ARG_TYPE(i, types) != NONE_T)
            argnum++;
    }

    return argnum;
}

static __always_inline int trace_ret_generic(u32 id, struct pt_regs *ctx, u64 types, u32 scope)
{
    if (skip_syscall())
        return 0;

    sys_context_t context = {};
    args_t args = {};

    if (ctx == NULL)
        return 0;

    if (load_args(id, &args) != 0)
        return 0;

    if (get_kubearmor_config(_ENFORCER_BPFLSM) && drop_syscall(scope))
    {
        // dropping after load_args so as the args_map cleanup happens
        return 0;
    }

    init_context(&context);

    context.event_id = id;
    context.argnum = get_arg_num(types);
    context.retval = PT_REGS_RC(ctx);

    // skip if No such file/directory or if there is an EINPROGRESS
    // EINPROGRESS error, happens when the socket is non-blocking and the connection cannot be completed immediately.
    if (context.retval == -2 || context.retval == -115)
    {
        return 0;
    }

    if (context.retval >= 0 && drop_syscall(scope))
    {
        // we need alerts for apparmor enforcer hence only dropping passed logs
        return 0;
    }

    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct path *p = bpf_map_lookup_elem(&file_map, &pid_tgid);
    if (p)
    {
        struct dentry *dent = READ_KERN(p->dentry);
        struct inode *ino = READ_KERN(dent->d_inode);
        kuid_t owner = READ_KERN(ino->i_uid);
        context.oid = owner.val;
    }

    if (context.retval < 0 && !get_kubearmor_config(_ENFORCER_BPFLSM) && get_kubearmor_config(_ALERT_THROTTLING) && should_drop_alerts_per_container(&context, ctx, types, &args))
    {
        return 0;
    }

    set_buffer_offset(DATA_BUF_TYPE, sizeof(sys_context_t));

    bufs_t *bufs_p = get_buffer(DATA_BUF_TYPE);
    if (bufs_p == NULL)
        return 0;

    save_context_to_buffer(bufs_p, (void *)&context);
    save_args_to_buffer(types, &args);
    events_perf_submit(ctx);
    return 0;
}

#define DIR_PROC "/proc/"
static __always_inline int isProcDir(char *path)
{
    char procDir[] = DIR_PROC;
    int i = 0;
    while (i < sizeof(DIR_PROC) - 1 && path[i] != '\0' && path[i] == procDir[i])
    {
        i++;
    }

    if (i == sizeof(DIR_PROC) - 1)
    {
        return 0;
    }

    return 1;
}

#define DIR_SYS "/sys/"
static __always_inline int isSysDir(char *path)
{
    char sysDir[] = DIR_SYS;
    int i = 0;
    while (i < sizeof(DIR_SYS) - 1 && path[i] != '\0' && path[i] == sysDir[i])
    {
        i++;
    }

    if (i == sizeof(DIR_SYS) - 1)
    {
        return 0;
    }

    return 1;
}

SEC("kprobe/__x64_sys_open")
int kprobe__open(struct pt_regs *ctx)
{
    if (skip_syscall())
        return 0;

    struct pt_regs *ctx2 = (struct pt_regs *)PT_REGS_PARM1(ctx);
    const char __user *pathname = (void *)READ_KERN(PT_REGS_PARM1(ctx2));
    char path[8];
    bpf_probe_read(path, 8, pathname);

    if (isProcDir(path) == 0 || isSysDir(path) == 0)
    {
        return 0;
    }

    return save_args(_SYS_OPEN, ctx);
}

SEC("kretprobe/__x64_sys_open")
int kretprobe__open(struct pt_regs *ctx)
{
    return trace_ret_generic(_SYS_OPEN, ctx, ARG_TYPE0(FILE_TYPE_T) | ARG_TYPE1(OPEN_FLAGS_T), _FILE_PROBE);
}

SEC("kprobe/__x64_sys_openat")
int kprobe__openat(struct pt_regs *ctx)
{
    if (skip_syscall())
        return 0;

    struct pt_regs *ctx2 = (struct pt_regs *)PT_REGS_PARM1(ctx);
    const char __user *pathname = (void *)READ_KERN(PT_REGS_PARM2(ctx2));
    char path[8];
    bpf_probe_read(path, 8, pathname);

    if (isProcDir(path) == 0 || isSysDir(path) == 0)
    {
        return 0;
    }

    return save_args(_SYS_OPENAT, ctx);
}

SEC("kretprobe/__x64_sys_openat")
int kretprobe__openat(struct pt_regs *ctx)
{
    return trace_ret_generic(_SYS_OPENAT, ctx, ARG_TYPE0(INT_T) | ARG_TYPE1(FILE_TYPE_T) | ARG_TYPE2(OPEN_FLAGS_T), _FILE_PROBE);
}

SEC("kprobe/__x64_sys_unlink")
int kprobe__unlink(struct pt_regs *ctx)
{
    if (skip_syscall())
        return 0;

    return save_args(_SYS_UNLINK, ctx);
}

SEC("kretprobe/__x64_sys_unlink")
int kretprobe__unlink(struct pt_regs *ctx)
{
    return trace_ret_generic(_SYS_UNLINK, ctx, ARG_TYPE0(INT_T) | ARG_TYPE1(FILE_TYPE_T), _FILE_PROBE);
}

SEC("kprobe/__x64_sys_unlinkat")
int kprobe__unlinkat(struct pt_regs *ctx)
{
    if (skip_syscall())
        return 0;

    return save_args(_SYS_UNLINKAT, ctx);
}

SEC("kretprobe/__x64_sys_unlinkat")
int kretprobe__unlinkat(struct pt_regs *ctx)
{
    return trace_ret_generic(_SYS_UNLINKAT, ctx, ARG_TYPE0(INT_T) | ARG_TYPE1(FILE_TYPE_T) | ARG_TYPE2(UNLINKAT_FLAG_T), _FILE_PROBE);
}

SEC("kprobe/__x64_sys_rmdir")
int kprobe__rmdir(struct pt_regs *ctx)
{
    if (skip_syscall())
        return 0;

    return save_args(_SYS_RMDIR, ctx);
}

SEC("kretprobe/__x64_sys_rmdir")
int kretprobe__rmdir(struct pt_regs *ctx)
{
    return trace_ret_generic(_SYS_RMDIR, ctx, ARG_TYPE1(FILE_TYPE_T), _FILE_PROBE);
}

SEC("kprobe/__x64_sys_close")
int kprobe__close(struct pt_regs *ctx)
{
    if (skip_syscall())
        return 0;

    return save_args(_SYS_CLOSE, ctx);
}

SEC("kretprobe/__x64_sys_close")
int kretprobe__close(struct pt_regs *ctx)
{
    return trace_ret_generic(_SYS_CLOSE, ctx, ARG_TYPE0(INT_T), _FILE_PROBE);
}

SEC("kprobe/__x64_sys_chown")
int kprobe__chown(struct pt_regs *ctx)
{
    if (skip_syscall())
        return 0;
    return save_args(_SYS_CHOWN, ctx);
}

SEC("kretprobe/__x64_sys_chown")
int kretprobe__chown(struct pt_regs *ctx)
{
    return trace_ret_generic(_SYS_CHOWN, ctx, ARG_TYPE0(FILE_TYPE_T) | ARG_TYPE1(INT_T) | ARG_TYPE2(INT_T), _FILE_PROBE);
}

SEC("kprobe/__x64_sys_fchownat")
int kprobe__fchownat(struct pt_regs *ctx)
{
    if (skip_syscall())
        return 0;
    return save_args(_SYS_FCHOWNAT, ctx);
}

SEC("kretprobe/__x64_sys_fchownat")
int kretprobe__fchownat(struct pt_regs *ctx)
{
    return trace_ret_generic(_SYS_FCHOWNAT, ctx, ARG_TYPE0(INT_T) | ARG_TYPE1(FILE_TYPE_T) | ARG_TYPE2(INT_T) | ARG_TYPE3(INT_T) | ARG_TYPE4(INT_T), _FILE_PROBE);
}

SEC("kprobe/__x64_sys_setuid")
int kprobe__setuid(struct pt_regs *ctx)
{
    if (skip_syscall())
        return 0;
    return save_args(_SYS_SETUID, ctx);
}

SEC("kretprobe/__x64_sys_setuid")
int kretprobe__setuid(struct pt_regs *ctx)
{
    return trace_ret_generic(_SYS_SETUID, ctx, ARG_TYPE0(INT_T), _CAPS_PROBE);
}

SEC("kprobe/__x64_sys_setgid")
int kprobe__setgid(struct pt_regs *ctx)
{
    if (skip_syscall())
        return 0;
    return save_args(_SYS_SETGID, ctx);
}

SEC("kretprobe/__x64_sys_setgid")
int kretprobe__setgid(struct pt_regs *ctx)
{
    return trace_ret_generic(_SYS_SETGID, ctx, ARG_TYPE0(INT_T), _CAPS_PROBE);
}

SEC("kprobe/__x64_sys_ptrace")
int kprobe__ptrace(struct pt_regs *ctx)
{
    if (skip_syscall())
        return 0;
    return save_args(_SYS_PTRACE, ctx);
}

SEC("kretprobe/__x64_sys_ptrace")
int kretprobe__ptrace(struct pt_regs *ctx)
{
    return trace_ret_generic(_SYS_PTRACE, ctx, ARG_TYPE0(PTRACE_REQ_T) | ARG_TYPE1(INT_T) | ARG_TYPE2(FILE_TYPE_T), _CAPS_PROBE);
}

SEC("kprobe/__x64_sys_mount")
int kprobe__mount(struct pt_regs *ctx)
{
    if (skip_syscall())
        return 0;
    return save_args(_SYS_MOUNT, ctx);
}

SEC("kretprobe/__x64_sys_mount")
int kretprobe__mount(struct pt_regs *ctx)
{
    return trace_ret_generic(_SYS_MOUNT, ctx, ARG_TYPE0(STR_T) | ARG_TYPE1(STR_T) | ARG_TYPE2(STR_T) | ARG_TYPE3(MOUNT_FLAG_T) | ARG_TYPE4(STR_T), _CAPS_PROBE);
}

SEC("kprobe/__x64_sys_umount")
int kprobe__umount(struct pt_regs *ctx)
{
    if (skip_syscall())
        return 0;
    return save_args(_SYS_UMOUNT, ctx);
}

SEC("kretprobe/__x64_sys_umount")
int kretprobe__umount(struct pt_regs *ctx)
{
    return trace_ret_generic(_SYS_UMOUNT, ctx, ARG_TYPE0(STR_T) | ARG_TYPE1(UMOUNT_FLAG_T), _CAPS_PROBE);
}

struct tracepoint_syscalls_sys_exit_t
{
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;

    int __syscall_ret;
    long ret;
};

SEC("tracepoint/syscalls/sys_exit_openat")
int sys_exit_openat(struct tracepoint_syscalls_sys_exit_t *args)
{
    if (skip_syscall())
        return 0;

    u32 id = _SYS_OPENAT;
    u64 types = ARG_TYPE0(INT_T) | ARG_TYPE1(FILE_TYPE_T) | ARG_TYPE2(OPEN_FLAGS_T);

    sys_context_t context = {};
    args_t orig_args = {};

    if (args == NULL)
        return 0;

    if (load_args(id, &orig_args) != 0)
        return 0;

    if (get_kubearmor_config(_ENFORCER_BPFLSM) && drop_syscall(_FILE_PROBE))
    {
        // dropping after load_args so as the args_map cleanup happens
        return 0;
    }

    init_context(&context);

    context.event_id = id;
    context.argnum = get_arg_num(types);
    context.retval = args->ret;

    // skip if No such file/directory or if there is an EINPROGRESS
    // EINPROGRESS error, happens when the socket is non-blocking and the connection cannot be completed immediately.
    if (context.retval == -2 || context.retval == -115)
    {
        return 0;
    }

    if (context.retval >= 0 && drop_syscall(_FILE_PROBE))
    {
        return 0;
    }

    if (context.retval < 0 && !get_kubearmor_config(_ENFORCER_BPFLSM) && get_kubearmor_config(_ALERT_THROTTLING) && should_drop_alerts_per_container(&context, (struct pt_regs *)args, types, &orig_args))
    {
        return 0;
    }

    set_buffer_offset(DATA_BUF_TYPE, sizeof(sys_context_t));

    bufs_t *bufs_p = get_buffer(DATA_BUF_TYPE);
    if (bufs_p == NULL)
        return 0;

    save_context_to_buffer(bufs_p, (void *)&context);
    save_args_to_buffer(types, &orig_args);

    events_perf_submit((struct pt_regs *)args);

    return 0;
}

// == Syscall Hooks (Network) == //

SEC("kprobe/__x64_sys_socket")
int kprobe__socket(struct pt_regs *ctx)
{
    if (skip_syscall())
        return 0;

    return save_args(_SYS_SOCKET, ctx);
}

SEC("kretprobe/__x64_sys_socket")
int kretprobe__socket(struct pt_regs *ctx)
{
    return trace_ret_generic(_SYS_SOCKET, ctx, ARG_TYPE0(SOCK_DOM_T) | ARG_TYPE1(SOCK_TYPE_T) | ARG_TYPE2(INT_T), _NETWORK_PROBE);
}

SEC("kprobe/__x64_sys_connect")
int kprobe__connect(struct pt_regs *ctx)
{
    if (skip_syscall())
        return 0;

    return save_args(_SYS_CONNECT, ctx);
}

SEC("kretprobe/__x64_sys_connect")
int kretprobe__connect(struct pt_regs *ctx)
{
    return trace_ret_generic(_SYS_CONNECT, ctx, ARG_TYPE0(INT_T) | ARG_TYPE1(SOCKADDR_T), _NETWORK_PROBE);
}

SEC("kprobe/__x64_sys_accept")
int kprobe__accept(struct pt_regs *ctx)
{
    if (skip_syscall())
        return 0;

    return save_args(_SYS_ACCEPT, ctx);
}

SEC("kretprobe/__x64_sys_accept")
int kretprobe__accept(struct pt_regs *ctx)
{
    return trace_ret_generic(_SYS_ACCEPT, ctx, ARG_TYPE0(INT_T) | ARG_TYPE1(SOCKADDR_T), _NETWORK_PROBE);
}

SEC("kprobe/__x64_sys_bind")
int kprobe__bind(struct pt_regs *ctx)
{
    if (skip_syscall())
        return 0;

    return save_args(_SYS_BIND, ctx);
}

SEC("kretprobe/__x64_sys_bind")
int kretprobe__bind(struct pt_regs *ctx)
{
    return trace_ret_generic(_SYS_BIND, ctx, ARG_TYPE0(INT_T) | ARG_TYPE1(SOCKADDR_T), _NETWORK_PROBE);
}

SEC("kprobe/__x64_sys_listen")
int kprobe__listen(struct pt_regs *ctx)
{
    if (skip_syscall())
        return 0;

    return save_args(_SYS_LISTEN, ctx);
}

SEC("kretprobe/__x64_sys_listen")
int kretprobe__listen(struct pt_regs *ctx)
{
    return trace_ret_generic(_SYS_LISTEN, ctx, ARG_TYPE0(INT_T) | ARG_TYPE1(INT_T), _NETWORK_PROBE);
}

static __always_inline int get_connection_info(struct sock_common *conn, struct sockaddr_in *sockv4, struct sockaddr_in6 *sockv6, sys_context_t *context, args_t *args, u32 event)
{
    switch (conn->skc_family)
    {
    case AF_INET:
        sockv4->sin_family = conn->skc_family;
        sockv4->sin_addr.s_addr = conn->skc_daddr;
        sockv4->sin_port = (event == _TCP_CONNECT) ? conn->skc_dport : (conn->skc_num >> 8) | (conn->skc_num << 8);
        args->args[1] = (unsigned long)sockv4;
        context->event_id = (event == _TCP_CONNECT) ? _TCP_CONNECT : _TCP_ACCEPT;
        break;

    case AF_INET6:
        sockv6->sin6_family = conn->skc_family;
        sockv6->sin6_port = (event == _TCP_CONNECT) ? conn->skc_dport : (conn->skc_num >> 8) | (conn->skc_num << 8);
        bpf_probe_read(&sockv6->sin6_addr.in6_u.u6_addr16, sizeof(sockv6->sin6_addr.in6_u.u6_addr16), conn->skc_v6_daddr.in6_u.u6_addr16);
        args->args[1] = (unsigned long)sockv6;
        context->event_id = (event == _TCP_CONNECT) ? _TCP_CONNECT_v6 : _TCP_ACCEPT_v6;
        break;

    default:
        return 1;
    }

    return 0;
}

SEC("kprobe/__x64_sys_tcp_connect")
int kprobe__tcp_connect(struct pt_regs *ctx)
{
    if (skip_syscall())
        return 0;

    u32 tgid = bpf_get_current_pid_tgid();
    u64 id = ((u64)_TCP_CONNECT << 32) | tgid;

    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);

    args_t args = {};
    args.args[0] = (unsigned long)sk;

    bpf_map_update_elem(&args_map, &id, &args, BPF_ANY);

    return 0;
}

SEC("kretprobe/__x64_sys_tcp_connect")
int kretprobe__tcp_connect(struct pt_regs *ctx)
{
    if (skip_syscall())
        return 0;

    struct sock *sk;

    u32 tgid = bpf_get_current_pid_tgid();
    u64 id = ((u64)_TCP_CONNECT << 32) | tgid;

    args_t *argp = bpf_map_lookup_elem(&args_map, &id);
    if (!argp)
        return 0;
    bpf_map_delete_elem(&args_map, &id);
    
    unsigned long sk_ptr = argp->args[0];
    if (!sk_ptr)
        return 0;
    sk = (struct sock *)sk_ptr;

    if (get_kubearmor_config(_ENFORCER_BPFLSM) && drop_syscall(_NETWORK_PROBE))
    {
        return 0;
    }

    struct sock_common conn = READ_KERN(sk->__sk_common);
    struct sockaddr_in sockv4;
    struct sockaddr_in6 sockv6;

    sys_context_t context = {};
    args_t args = {};
    u64 types = ARG_TYPE0(STR_T) | ARG_TYPE1(SOCKADDR_T);

    init_context(&context);
    context.argnum = get_arg_num(types);
    context.retval = PT_REGS_RC(ctx);

    if (context.retval >= 0 && drop_syscall(_NETWORK_PROBE))
    {
        return 0;
    }

    if (get_connection_info(&conn, &sockv4, &sockv6, &context, &args, _TCP_CONNECT) != 0)
    {
        return 0;
    }

    args.args[0] = (unsigned long)conn.skc_prot->name;

    if (context.retval < 0 && !get_kubearmor_config(_ENFORCER_BPFLSM) && get_kubearmor_config(_ALERT_THROTTLING) && should_drop_alerts_per_container(&context, ctx, types, &args))
    {
        return 0;
    }

    set_buffer_offset(DATA_BUF_TYPE, sizeof(sys_context_t));
    bufs_t *bufs_p = get_buffer(DATA_BUF_TYPE);
    if (bufs_p == NULL)
        return 0;
    save_context_to_buffer(bufs_p, (void *)&context);
    save_args_to_buffer(types, &args);
    events_perf_submit(ctx);

    return 0;
}

SEC("kretprobe/__x64_sys_inet_csk_accept")
int kretprobe__inet_csk_accept(struct pt_regs *ctx)
{
    if (skip_syscall())
        return 0;

    if (get_kubearmor_config(_ENFORCER_BPFLSM) && drop_syscall(_NETWORK_PROBE))
    {
        return 0;
    }

    struct sock *newsk = (struct sock *)PT_REGS_RC(ctx);
    if (newsk == NULL)
        return 0;

    // Code from https://github.com/iovisor/bcc/blob/master/tools/tcpaccept.py with adaptations
    u16 protocol = 1;
    int gso_max_segs_offset = offsetof(struct sock, sk_gso_max_segs);
    int sk_lingertime_offset = offsetof(struct sock, sk_lingertime);

    if (sk_lingertime_offset - gso_max_segs_offset == 2)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
        protocol = READ_KERN(newsk->sk_protocol);
#else
        protocol = newsk->sk_protocol;
#endif
    else if (sk_lingertime_offset - gso_max_segs_offset == 4)
    // 4.10+ with little endian
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
        protocol = READ_KERN(*(u8 *)((u64)&newsk->sk_gso_max_segs - 3));
    else
        // pre-4.10 with little endian
        protocol = READ_KERN(*(u8 *)((u64)&newsk->sk_wmem_queued - 3));
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
        // 4.10+ with big endian
        protocol = READ_KERN(*(u8 *)((u64)&newsk->sk_gso_max_segs - 1));
    else
        // pre-4.10 with big endian
        protocol = READ_KERN(*(u8 *)((u64)&newsk->sk_wmem_queued - 1));
#else
#error "Fix your compiler's __BYTE_ORDER__?!"
#endif

    if (protocol != IPPROTO_TCP)
        return 0;

    struct sock_common conn = READ_KERN(newsk->__sk_common);
    struct sockaddr_in sockv4;
    struct sockaddr_in6 sockv6;
    sys_context_t context = {};
    args_t args = {};
    u64 types = ARG_TYPE0(STR_T) | ARG_TYPE1(SOCKADDR_T);
    init_context(&context);
    context.argnum = get_arg_num(types);
    int *err_ptr = (int *)PT_REGS_PARM3(ctx);
    bpf_probe_read(&context.retval, sizeof(context.retval), err_ptr);

    if (context.retval >= 0 && drop_syscall(_NETWORK_PROBE))
    {
        return 0;
    }

    if (get_connection_info(&conn, &sockv4, &sockv6, &context, &args, _TCP_ACCEPT) != 0)
    {
        return 0;
    }

    args.args[0] = (unsigned long)conn.skc_prot->name;

    if (context.retval < 0 && !get_kubearmor_config(_ENFORCER_BPFLSM) && get_kubearmor_config(_ALERT_THROTTLING) && should_drop_alerts_per_container(&context, ctx, types, &args))
    {
        return 0;
    }

    set_buffer_offset(DATA_BUF_TYPE, sizeof(sys_context_t));
    bufs_t *bufs_p = get_buffer(DATA_BUF_TYPE);
    if (bufs_p == NULL)
        return 0;

    save_context_to_buffer(bufs_p, (void *)&context);
    save_args_to_buffer(types, &args);
    events_perf_submit(ctx);

    return 0;
}
char LICENSE[] SEC("license") = "Dual BSD/GPL";