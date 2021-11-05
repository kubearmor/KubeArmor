/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2021 Authors of KubeArmor */

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

#define __TARGET_ARCH_x86
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "shared.h"

#define AF_UNIX             1   /* Unix domain sockets 		*/
#define AF_INET             2   /* Internet IP Protocol 	*/
#define AF_INET6            10 /* IP version 6			*/

#define MAX_PERCPU_BUFSIZE  (1 << 15)     // This value is actually set by the kernel as an upper bound
#define MAX_BUFFER_SIZE     32768
#define MAX_STRING_SIZE     4096
#define MAX_STR_ARR_ELEM    20
#define MAX_BUFFERS         3

#define BUF_IDX             0

#define NONE_T              0UL
#define INT_T               1UL
#define STR_T               10UL
#define STR_ARR_T           11UL
#define SOCKADDR_T          12UL
#define OPEN_FLAGS_T        13UL
#define EXEC_FLAGS_T        14UL
#define SOCK_DOM_T          15UL
#define SOCK_TYPE_T         16UL

#define MAX_ARGS            6
#define ENC_ARG_TYPE(n, type) type << (8 * n)
#define ARG_TYPE0(type) ENC_ARG_TYPE(0, type)
#define ARG_TYPE1(type) ENC_ARG_TYPE(1, type)
#define ARG_TYPE2(type) ENC_ARG_TYPE(2, type)
#define ARG_TYPE3(type) ENC_ARG_TYPE(3, type)
#define ARG_TYPE4(type) ENC_ARG_TYPE(4, type)
#define ARG_TYPE5(type) ENC_ARG_TYPE(5, type)
#define DEC_ARG_TYPE(n, type) ((type >> (8 * n)) & 0xFF)

#define READ_KERN(ptr) ({ typeof(ptr) _val;                             \
                          __builtin_memset(&_val, 0, sizeof(_val));     \
                          bpf_core_read(&_val, sizeof(_val), &ptr);    \
                          _val;                                         \
                        })

#define BPF_MAP(_name, _type, _key_type, _value_type, _max_entries) \
struct bpf_map_def SEC("maps") _name = { \
  .type = _type, \
  .key_size = sizeof(_key_type), \
  .value_size = sizeof(_value_type), \
  .max_entries = _max_entries, \
};

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

enum {
    // file
    _SYS_OPEN = 2,
    _SYS_OPENAT = 257,
    _SYS_CLOSE = 3,

    // network
    _SYS_SOCKET = 41,
    _SYS_CONNECT = 42,
    _SYS_ACCEPT = 43,
    _SYS_BIND = 49,
    _SYS_LISTEN = 50,

    // process
    _SYS_EXECVE = 59,
    _SYS_EXECVEAT = 322,
    _DO_EXIT = 351,
};

/*=============================== INTERNAL STRUCTS ===========================*/

typedef struct __attribute__((__packed__)) sys_context {
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
} sys_context_t;


typedef struct args {
    unsigned long args[6];
} args_t;

typedef struct buffers {
    u8 buf[MAX_BUFFER_SIZE];
} buf_t;

/*=================================== MAPS =====================================*/

BPF_HASH(pid_ns_map, u32, u32);
BPF_HASH(args_map, u64, args_t);
BPF_PERCPU_ARRAY(bufs, buf_t, MAX_BUFFERS);
BPF_PERCPU_ARRAY(bufs_off, u32, MAX_BUFFERS);           // Holds offsets to bufs respectively

/*================================== EVENTS ====================================*/

BPF_PERF_OUTPUT(sys_events)

/*============================== HELPER FUNCTIONS ==============================*/

static __always_inline u32 get_pid_ns_id(struct nsproxy *ns)
{
    struct pid_namespace* pidns = READ_KERN(ns->pid_ns_for_children);
    return READ_KERN(pidns->ns.inum);
}

static __always_inline u32 get_mnt_ns_id(struct nsproxy *ns)
{
    struct mnt_namespace* mntns = READ_KERN(ns->mnt_ns);
    return READ_KERN(mntns->ns.inum);
}

static __always_inline u32 get_task_pid_ns_id(struct task_struct *task)
{
    return get_pid_ns_id(READ_KERN(task->nsproxy));
}

static __always_inline u32 get_task_mnt_ns_id(struct task_struct *task)
{
    return get_mnt_ns_id(READ_KERN(task->nsproxy));
}

static __always_inline u32 get_task_ns_ppid(struct task_struct *task)
{
    struct task_struct *real_parent = READ_KERN(task->real_parent);
    struct nsproxy *namespaceproxy = READ_KERN(real_parent->nsproxy);
    struct pid_namespace *pid_ns_children = READ_KERN(namespaceproxy->pid_ns_for_children);
    unsigned int level = READ_KERN(pid_ns_children->level);

    // kernel 4.19 onwards, and CO:RE:
    struct pid *tpid = READ_KERN(real_parent->thread_pid);
    return READ_KERN(tpid->numbers[level].nr);
}

static __always_inline u32 get_task_ns_tgid(struct task_struct *task)
{
    struct nsproxy *namespaceproxy = READ_KERN(task->nsproxy);
    struct pid_namespace *pid_ns_children = READ_KERN(namespaceproxy->pid_ns_for_children);
    unsigned int level = READ_KERN(pid_ns_children->level);
    struct task_struct *group_leader = READ_KERN(task->group_leader);

    // kernel 4.19 onwards, and CO:RE:
    struct pid *tpid = READ_KERN(group_leader->thread_pid);
    return READ_KERN(tpid->numbers[level].nr);
}

static __always_inline u32 get_task_ns_pid(struct task_struct *task)
{
    struct nsproxy *namespaceproxy = READ_KERN(task->nsproxy);
    struct pid_namespace *pid_ns_children = READ_KERN(namespaceproxy->pid_ns_for_children);
    unsigned int level = READ_KERN(pid_ns_children->level);

    // kernel 4.19 onwards, and CO:RE:
    struct pid *tpid = READ_KERN(task->thread_pid);
    return READ_KERN(tpid->numbers[level].nr);
}

static __always_inline u32 get_task_ppid(struct task_struct *task)
{
    struct task_struct *parent = READ_KERN(task->real_parent);
    return READ_KERN(parent->pid);
}

// == Pid NS Management == //

static __always_inline u32 add_pid_ns()
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    u32 one = 1;

#if defined(MONITOR_HOST)

    u32 pid_ns = get_task_pid_ns_id(task);
    if (pid_ns != PROC_PID_INIT_INO) {
        return 0;
    }

    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (bpf_map_lookup_elem(&pid_ns_map, &pid) != 0) {
        return pid;
    }

    bpf_map_update_elem(&pid_ns_map, &pid, &one, BPF_ANY);
    return pid;

#elif defined(MONITOR_HOST_AND_CONTAINER)

    u32 pid_ns = get_task_pid_ns_id(task);
    if (pid_ns == PROC_PID_INIT_INO)
    { // host
        u32 pid = bpf_get_current_pid_tgid() >> 32;
        if (bpf_map_lookup_elem(&pid_ns_map, &pid) != 0) {
            return pid;
        }

        bpf_map_update_elem(&pid_ns_map, &pid, &one, BPF_ANY);
        return pid;
    }
    else
    { // container
        if (bpf_map_lookup_elem(&pid_ns_map, &pid_ns) != 0) {
            return pid_ns;
        }

        bpf_map_update_elem(&pid_ns_map, &pid_ns, &one, BPF_ANY);
        return pid_ns;
    }

#else /* MONITOR_CONTAINER */

    u32 pid_ns = get_task_pid_ns_id(task);
    if (pid_ns == PROC_PID_INIT_INO) {
        return 0;
    }

    if (bpf_map_lookup_elem(&pid_ns_map, &pid_ns) != 0) {
        return pid_ns;
    }

    bpf_map_update_elem(&pid_ns_map, &pid_ns, &one, BPF_ANY);
    return pid_ns;

    return 0;

#endif /* MONITOR_HOST || MONITOR_CONTAINER */
}

static __always_inline u32 remove_pid_ns()
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

#if defined(MONITOR_HOST)

    u32 pid_ns = get_task_pid_ns_id(task);
    if (pid_ns != PROC_PID_INIT_INO) {
        return 0;
    }

    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (bpf_map_lookup_elem(&pid_ns_map, &pid) != 0) {
        bpf_map_delete_elem(&pid_ns_map, &pid);
        return 0;
    }

#elif defined(MONITOR_HOST_AND_CONTAINER)

    u32 pid_ns = get_task_pid_ns_id(task);
    if (pid_ns == PROC_PID_INIT_INO) { // host
        u32 pid = bpf_get_current_pid_tgid() >> 32;
        if (bpf_map_lookup_elem(&pid_ns_map, &pid) != 0) {
            bpf_map_delete_elem(&pid_ns_map, &pid);
            return 0;
        }
    } else { // container
        if (get_task_ns_pid(task) == 1) {
            bpf_map_delete_elem(&pid_ns_map, &pid_ns);
            return 0;
        }
    }

#else /* !MONITOR_HOST */

    u32 pid_ns = get_task_pid_ns_id(task);
    if (pid_ns == PROC_PID_INIT_INO) {
        return 0;
    }

    if (get_task_ns_pid(task) == 1) {
        bpf_map_delete_elem(&pid_ns_map, &pid_ns);
        return 0;
    }

#endif /* !MONITOR_HOST */

    return 0;
}

static __always_inline u32 skip_syscall()
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

#if defined(MONITOR_HOST)

    u32 pid_ns = get_task_pid_ns_id(task);
    if (pid_ns != PROC_PID_INIT_INO) {
        return 1;
    }

    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (bpf_map_lookup_elem(&pid_ns_map, &pid) != 0) {
        return 0;
    }

#elif defined(MONITOR_HOST_AND_CONTAINER)

    u32 pid_ns = get_task_pid_ns_id(task);
    if (pid_ns == PROC_PID_INIT_INO) { // host
        u32 pid = bpf_get_current_pid_tgid() >> 32;
        if (bpf_map_lookup_elem(&pid_ns_map, &pid) != 0) {
            return 0;
        }
    } else { // container
        u32 pid_ns = get_task_pid_ns_id(task);
        if (bpf_map_lookup_elem(&pid_ns_map, &pid_ns) != 0) {
            return 0;
        }
    }

#else /* !MONITOR_HOST */

    u32 pid_ns = get_task_pid_ns_id(task);
    if (bpf_map_lookup_elem(&pid_ns_map, &pid_ns) != 0) {
        return 0;
    }

#endif /* !MONITOR_HOST */

    return 1;
}

// == Context Management == //

static __always_inline u32 init_context(sys_context_t *context)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    context->ts = bpf_ktime_get_ns();

    context->host_ppid = get_task_ppid(task);
    context->host_pid = bpf_get_current_pid_tgid() >> 32;

#if defined(MONITOR_HOST)

    context->pid_id = 0;
    context->mnt_id = 0;

    context->ppid = get_task_ppid(task);
    context->pid = bpf_get_current_pid_tgid() >> 32;

#elif defined(MONITOR_HOST_AND_CONTAINER)

    u32 pid = get_task_ns_tgid(task);
    if (context->host_pid == pid) { // host
        context->pid_id = 0;
        context->mnt_id = 0;

        context->ppid = get_task_ppid(task);
        context->pid = bpf_get_current_pid_tgid() >> 32;
    } else { // container
        context->pid_id = get_task_pid_ns_id(task);
        context->mnt_id = get_task_mnt_ns_id(task);

        context->ppid = get_task_ns_ppid(task);
        context->pid = pid;
    }

#else /* !MONITOR_HOST */

    context->pid_id = get_task_pid_ns_id(task);
    context->mnt_id = get_task_mnt_ns_id(task);

    context->ppid = get_task_ns_ppid(task);
    context->pid = get_task_ns_tgid(task);

#endif /* !MONITOR_HOST */

    context->uid = bpf_get_current_uid_gid();

    bpf_get_current_comm(&context->comm, sizeof(context->comm));

    return 0;
}

// == Buffer Management == //

static __always_inline buf_t* get_buf(int idx)
{
    return bpf_map_lookup_elem(&bufs, &idx);
}

static __always_inline void set_buf_off(int buf_idx, u32 new_off)
{
    bpf_map_update_elem(&bufs_off, &buf_idx, &new_off, BPF_ANY);
}

static __always_inline u32* get_buf_off(int buf_idx)
{
    return bpf_map_lookup_elem(&bufs_off, &buf_idx);
}

static __always_inline int save_context_to_buffer(buf_t *bufs_p, void *ptr)
{
    if (bpf_probe_read(&(bufs_p->buf[0]), sizeof(sys_context_t), ptr) == 0)
    {
        return sizeof(sys_context_t);
    }

    return 0;
}

static __always_inline int save_str_to_buffer(buf_t *bufs_p, void *ptr)
{
    u32 *off = get_buf_off(BUF_IDX);
    if (off == NULL) {
        return -1;
    }

    if (*off > MAX_BUFFER_SIZE - MAX_STRING_SIZE - sizeof(int)) {
        return 0; // not enough space - return
    }

    u8 type = STR_T;
    bpf_probe_read(&(bufs_p->buf[*off & (MAX_BUFFER_SIZE-1)]), 1, &type);

    *off += 1;

    if (*off > MAX_BUFFER_SIZE - MAX_STRING_SIZE - sizeof(int)) {
        return 0;
    }

    int sz = bpf_probe_read_str(&(bufs_p->buf[*off + sizeof(int)]), MAX_STRING_SIZE, ptr);
    if (sz > 0) {
        if (*off > MAX_BUFFER_SIZE - sizeof(int)) {
            return 0;
        }

        bpf_probe_read(&(bufs_p->buf[*off]), sizeof(int), &sz);

        *off += sz + sizeof(int);
        set_buf_off(BUF_IDX, *off);

        return sz + sizeof(int);
    }

    return 0;
}

static __always_inline int save_to_buffer(buf_t *bufs_p, void *ptr, int size, u8 type)
{
    // the biggest element that can be saved with this function should be defined here
    #define MAX_ELEMENT_SIZE sizeof(struct sockaddr_un)

    if (type == 0) {
        return 0;
    }

    u32 *off = get_buf_off(BUF_IDX);
    if (off == NULL) {
        return -1;
    }

    if (*off > MAX_BUFFER_SIZE - MAX_ELEMENT_SIZE) {
        return 0;
    }

    if (bpf_probe_read(&(bufs_p->buf[*off]), 1, &type) != 0) {
        return 0;
    }

    *off += 1;

    if (*off > MAX_BUFFER_SIZE - MAX_ELEMENT_SIZE) {
        return 0;
    }

    if (bpf_probe_read(&(bufs_p->buf[*off]), size, ptr) == 0) {
        *off += size;
        set_buf_off(BUF_IDX, *off);
        return size;
    }

    return 0;
}

static __always_inline int save_argv(buf_t *bufs_p, void *ptr)
{
    const char *argp = NULL;
    bpf_probe_read(&argp, sizeof(argp), ptr);

    if (argp) {
        return save_str_to_buffer(bufs_p, (void *)(argp));
    }

    return 0;
}

static __always_inline int save_str_arr_to_buffer(buf_t *bufs_p, const char *const *ptr)
{
    save_to_buffer(bufs_p, NULL, 0, STR_ARR_T);

#pragma unroll
    for (int i = 0; i < MAX_STR_ARR_ELEM; i++) {
        if (save_argv(bufs_p, (void *)&ptr[i]) == 0) {
            goto out;
        }
    }

    char ellipsis[] = "...";
    save_str_to_buffer(bufs_p, (void *)ellipsis);

out:
    save_to_buffer(bufs_p, NULL, 0, STR_ARR_T);

    return 0;
}

static __always_inline int save_args_to_buffer(u64 types, args_t *args) {
    if (types == 0) {
        return 0;
    }

    buf_t *bufs_p = get_buf(BUF_IDX);
    if (bufs_p == NULL) {
        return 0;
    }

#pragma unroll
    for (int i = 0; i < MAX_ARGS; i++) {
        switch (DEC_ARG_TYPE(i, types)) {
        case NONE_T:
            break;
        case INT_T:
            save_to_buffer(bufs_p, (void *)&(args->args[i]), sizeof(int), INT_T);
            break;
        case OPEN_FLAGS_T:
            save_to_buffer(bufs_p, (void *)&(args->args[i]), sizeof(int), OPEN_FLAGS_T);
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
            if (args->args[i]) {
                short family = 0;
                bpf_probe_read(&family, sizeof(short), (void *)args->args[i]);
                switch (family) {
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
        }
    }

    return 0;
}

static __always_inline int events_perf_submit(struct pt_regs *ctx) {
    buf_t *bufs_p = get_buf(BUF_IDX);
    if (bufs_p == NULL)
        return -1;

    u32 *off = get_buf_off(BUF_IDX);
    if (off == NULL)
        return -1;

    void *data = bufs_p->buf;
    int size = *off & (MAX_BUFFER_SIZE - 1);

    return bpf_perf_event_output(ctx, &sys_events, BPF_F_CURRENT_CPU, data, size);
}

// == Syscall Hooks (Process) == //

SEC("kprobe/__x64_sys_execve")
int kprobe__execve(struct pt_regs *ctx)
{
    sys_context_t context = {};

    struct pt_regs *real_regs;
    real_regs = (struct pt_regs *)PT_REGS_PARM1(ctx);

    if (!add_pid_ns()) {
        return 0;
    }

    init_context(&context);

    context.event_id = _SYS_EXECVE;
    context.argnum = 2;
    context.retval = 0;

    set_buf_off(BUF_IDX, sizeof(sys_context_t));

    buf_t *bufs_p = get_buf(BUF_IDX);
    if (bufs_p == NULL) {
        return 0;
    }

    save_context_to_buffer(bufs_p, (void *)&context);

    save_str_to_buffer(bufs_p, (void *)PT_REGS_PARM1_CORE(real_regs));
    save_str_arr_to_buffer(bufs_p, (const char *const *)PT_REGS_PARM2_CORE(real_regs));

    events_perf_submit(ctx);

    return 0;
}

SEC("kretprobe/__x64_sys_execve")
int kretprobe__execve(struct pt_regs *ctx)
{
    sys_context_t context = {};

    if (skip_syscall())
        return 0;

    init_context(&context);

    context.event_id = _SYS_EXECVE;
    context.argnum = 0;
    context.retval = PT_REGS_RC_CORE(ctx);

    // TEMP: skip if No such file or directory
    if (context.retval == -2)
    {
        return 0;
    }

    set_buf_off(BUF_IDX, sizeof(sys_context_t));

    buf_t *bufs_p = get_buf(BUF_IDX);
    if (bufs_p == NULL)
        return 0;

    save_context_to_buffer(bufs_p, (void *)&context);

    events_perf_submit(ctx);

    return 0;
}

SEC("kprobe/__x64_sys_execveat")
int kprobe__execveat(struct pt_regs *ctx)
{
    sys_context_t context = {};

    struct pt_regs *real_regs;
    real_regs = (struct pt_regs *)PT_REGS_PARM1(ctx);

    if (!add_pid_ns())
        return 0;

    init_context(&context);

    context.event_id = _SYS_EXECVEAT;
    context.argnum = 4;
    context.retval = 0;

    set_buf_off(BUF_IDX, sizeof(sys_context_t));

    buf_t *bufs_p = get_buf(BUF_IDX);
    if (bufs_p == NULL)
        return 0;

    save_context_to_buffer(bufs_p, (void *)&context);

    save_to_buffer(bufs_p, (void *)PT_REGS_PARM1_CORE(real_regs), sizeof(int), INT_T);
    save_str_to_buffer(bufs_p, (void *)PT_REGS_PARM2_CORE(real_regs));
    save_str_arr_to_buffer(bufs_p, (const char *const *)PT_REGS_PARM3_CORE(real_regs));
    save_to_buffer(bufs_p, (void *)PT_REGS_PARM5_CORE(real_regs), sizeof(int), EXEC_FLAGS_T);

    events_perf_submit(ctx);

    return 0;
}

SEC("kretprobe/__x64_sys_execveat")
int kretprobe__execveat(struct pt_regs *ctx)
{
    sys_context_t context = {};

    if (skip_syscall())
        return 0;

    init_context(&context);

    context.event_id = _SYS_EXECVEAT;
    context.argnum = 0;
    context.retval = PT_REGS_RC_CORE(ctx);

    // TEMP: skip if No such file or directory
    if (context.retval == -2)
    {
        return 0;
    }

    set_buf_off(BUF_IDX, sizeof(sys_context_t));

    buf_t *bufs_p = get_buf(BUF_IDX);
    if (bufs_p == NULL)
        return 0;

    save_context_to_buffer(bufs_p, (void *)&context);

    events_perf_submit(ctx);

    return 0;
}

SEC("kprobe/do_exit")
int BPF_KPROBE(kprobe__do_exit)
{
    sys_context_t context = {};

    if (skip_syscall())
        return 0;

    init_context(&context);

    context.event_id = _DO_EXIT;
    context.argnum = 0;
    // context.retval = code;

    remove_pid_ns();

    set_buf_off(BUF_IDX, sizeof(sys_context_t));

    buf_t *bufs_p = get_buf(BUF_IDX);
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

    struct pt_regs * ctx2 = (struct pt_regs *)PT_REGS_PARM1_CORE(ctx);  
    bpf_probe_read(&args.args[0], sizeof(args.args[0]), &ctx2->di);
    bpf_probe_read(&args.args[1], sizeof(args.args[1]), &ctx2->si);
    bpf_probe_read(&args.args[2], sizeof(args.args[2]), &ctx2->dx);
    bpf_probe_read(&args.args[3], sizeof(args.args[3]), &ctx2->r10);
    bpf_probe_read(&args.args[4], sizeof(args.args[4]), &ctx2->r8);
    bpf_probe_read(&args.args[5], sizeof(args.args[5]), &ctx2->r9);

    u64 id = event_id;
    u32 tid = bpf_get_current_pid_tgid();
    id = id << 32 | tid;

    bpf_map_update_elem(&args_map, &id, &args, BPF_ANY);

    return 0;
}

static __always_inline int load_args(args_t *args, u32 event_id)
{
    args_t *saved_args;
    u32 tid = bpf_get_current_pid_tgid();
    u64 id = event_id;
    id = id << 32 | tid;

    saved_args = bpf_map_lookup_elem(&args_map, &id);
    if (saved_args == 0) {
        // missed entry or not a container
        return -1;
    }

    args->args[0] = saved_args->args[0];
    args->args[1] = saved_args->args[1];
    args->args[2] = saved_args->args[2];
    args->args[3] = saved_args->args[3];
    args->args[4] = saved_args->args[4];
    args->args[5] = saved_args->args[5];

    return 0;
}

static __always_inline int get_arg_num(u64 types)
{
    unsigned int i, argnum = 0;

#pragma unroll
    for (i = 0; i < MAX_ARGS; i++) {
        if (DEC_ARG_TYPE(i, types) != NONE_T)
            argnum++;
    }

    return argnum;
}

static __always_inline int trace_ret_generic(u32 id, struct pt_regs *ctx, u64 types)
{
    sys_context_t context = {};
    args_t args = {};

    if (load_args(&args, id) != 0)
        return 0;

    if (skip_syscall())
        return 0;

    init_context(&context);

    context.event_id = id;
    context.argnum = get_arg_num(types);
    context.retval = PT_REGS_RC_CORE(ctx);

    // TEMP: skip if No such file or directory
    if (context.retval == -2) {
        return 0;
    }

    set_buf_off(BUF_IDX, sizeof(sys_context_t));

    buf_t *bufs_p = get_buf(BUF_IDX);
    if (bufs_p == NULL)
        return 0;

    save_context_to_buffer(bufs_p, (void *)&context);
    save_args_to_buffer(types, &args);

    events_perf_submit(ctx);

    return 0;
}

SEC("kprobe/__x64_sys_open")
int kprobe__open(struct pt_regs *ctx)
{
    if (skip_syscall())
        return 0;

    return save_args(_SYS_OPEN, ctx);
}

SEC("kretprobe/__x64_sys_open")
int kretprobe__open(struct pt_regs *ctx)
{
    return trace_ret_generic(_SYS_OPEN, ctx, ARG_TYPE0(STR_T) | ARG_TYPE1(OPEN_FLAGS_T));
}

SEC("kprobe/__x64_sys_openat")
int kprobe__openat(struct pt_regs *ctx)
{
    if (skip_syscall())
        return 0;

    return save_args(_SYS_OPENAT, ctx);
}

SEC("kretprobe/__x64_sys_openat")
int kretprobe__openat(struct pt_regs *ctx)
{
    return trace_ret_generic(_SYS_OPENAT, ctx, ARG_TYPE0(INT_T) | ARG_TYPE1(STR_T) | ARG_TYPE2(OPEN_FLAGS_T));
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
    return trace_ret_generic(_SYS_CLOSE, ctx, ARG_TYPE0(INT_T));
}

// == Syscall Hooks (Network) == //

SEC("kprobe/__x64_sys_socket")
int kprobe__socket(struct pt_regs *ctx)
{
    if (skip_syscall())
        return 0;

    return save_args(_SYS_SOCKET, ctx);
}

SEC("kprobe/__x64_sys_socket")
int kretprobe__socket(struct pt_regs *ctx)
{
    return trace_ret_generic(_SYS_SOCKET, ctx, ARG_TYPE0(SOCK_DOM_T) | ARG_TYPE1(SOCK_TYPE_T) | ARG_TYPE2(INT_T));
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
    return trace_ret_generic(_SYS_CONNECT, ctx, ARG_TYPE0(INT_T) | ARG_TYPE1(SOCKADDR_T));
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
    return trace_ret_generic(_SYS_ACCEPT, ctx, ARG_TYPE0(INT_T) | ARG_TYPE1(SOCKADDR_T));
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
    return trace_ret_generic(_SYS_BIND, ctx, ARG_TYPE0(INT_T) | ARG_TYPE1(SOCKADDR_T));
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
    return trace_ret_generic(_SYS_LISTEN, ctx, ARG_TYPE0(INT_T) | ARG_TYPE1(INT_T));
}

char LICENSE[] SEC("license") = "GPL";
