#define KBUILD_MODNAME "kubearmor_container_monitor"

#include <linux/version.h>

#include <linux/nsproxy.h>
#include <linux/pid_namespace.h>

#include <linux/un.h>
#include <linux/ip.h>

#include <net/sock.h>
#include <net/inet_sock.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0)
#error Minimal required kernel version is 4.14
#endif

// == Syscall Monitor == //

#define MAX_PERCPU_BUFSIZE (1 << 15)
#define MAX_STRING_SIZE    4096
#define MAX_STR_ARR_ELEM   20

#define MAX_BUFFERS        1
#define SUBMIT_BUF_IDX     0

#define NONE_T        0UL
#define INT_T         1UL
#define STR_T         10UL
#define STR_ARR_T     11UL
#define SOCKADDR_T    12UL
#define OPEN_FLAGS_T  13UL
#define EXEC_FLAGS_T  14UL
#define SOCK_DOM_T    15UL
#define SOCK_TYPE_T   16UL
#define TYPE_MAX      255UL

#define ENC_ARG_TYPE(n, type) type<<(8*n)
#define ARG_TYPE0(type) ENC_ARG_TYPE(0, type)
#define ARG_TYPE1(type) ENC_ARG_TYPE(1, type)
#define ARG_TYPE2(type) ENC_ARG_TYPE(2, type)
#define ARG_TYPE3(type) ENC_ARG_TYPE(3, type)
#define ARG_TYPE4(type) ENC_ARG_TYPE(4, type)
#define ARG_TYPE5(type) ENC_ARG_TYPE(5, type)
#define DEC_ARG_TYPE(n, enc_type) ((enc_type>>(8*n))&0xFF)

enum event_id {
    SYS_READ,
    SYS_WRITE,
    SYS_OPEN,
    SYS_CLOSE,
    SYS_STAT,
    SYS_FSTAT,
    SYS_LSTAT,
    SYS_POLL,
    SYS_LSEEK,
    SYS_MMAP,
    SYS_MPROTECT, // 10
    SYS_MUNMAP,
    SYS_BRK,
    SYS_RT_SIGACTION,
    SYS_RT_SIGPROCMASK,
    SYS_RT_SIGRETURN,
    SYS_IOCTL,
    SYS_PREAD64,
    SYS_PWRITE64,
    SYS_READV,
    SYS_WRITEV, // 20
    SYS_ACCESS,
    SYS_PIPE,
    SYS_SELECT,
    SYS_SCHED_YIELD,
    SYS_MREMAP,
    SYS_MSYNC,
    SYS_MINCORE,
    SYS_MADVISE,
    SYS_SHMGET,
    SYS_SHMAT, // 30
    SYS_SHMCTL,
    SYS_DUP,
    SYS_DUP2,
    SYS_PAUSE,
    SYS_NANOSLEEP,
    SYS_GETITIMER,
    SYS_ALARM,
    SYS_SETITIMER,
    SYS_GETPID,
    SYS_SENDFILE, // 40
    _SYS_SOCKET,
    _SYS_CONNECT,
    _SYS_ACCEPT,
    _SYS_SENDTO,
    _SYS_RECVFROM,
    _SYS_SENDMSG,
    _SYS_RECVMSG,
    _SYS_SHUTDOWN,
    _SYS_BIND,
    _SYS_LISTEN, // 50
    _SYS_GETSOCKNAME,
    _SYS_GETPEERNAME,
    _SYS_SOCKETPAIR,
    _SYS_SETSOCKOPT,
    _SYS_GETSOCKOPT,
    SYS_CLONE,
    SYS_FORK,
    SYS_VFORK,
    SYS_EXECVE,
    SYS_EXIT, // 60
    SYS_WAIT4,
    SYS_KILL,
    SYS_UNAME,
    SYS_SEMGET,
    SYS_SEMOP,
    SYS_SEMCTL,
    SYS_SHMDT,
    SYS_MSGGET,
    SYS_MSGSND,
    SYS_MSGRCV, // 70
    SYS_MSGCTL,
    SYS_FCNTL,
    SYS_FLOCK,
    SYS_FSYNC,
    SYS_FDATASYNC,
    SYS_TRUNCATE,
    SYS_FTRUNCATE,
    SYS_GETDENTS,
    SYS_GETCWD,
    SYS_CHDIR, // 80
    SYS_FCHDIR,
    SYS_RENAME,
    SYS_MKDIR,
    SYS_RMDIR,
    SYS_CREAT,
    SYS_LINK,
    SYS_UNLINK,
    SYS_SYMLINK,
    SYS_READLINK,
    SYS_CHMOD, // 90
    SYS_FCHMOD,
    SYS_CHOWN,
    SYS_FCHOWN,
    SYS_LCHOWN,
    SYS_UMASK,
    SYS_GETTIMEOFDAY,
    SYS_GETRLIMIT,
    SYS_GETRUSAGE,
    SYS_SYSINFO,
    SYS_TIMES, // 100
    SYS_PTRACE,
    SYS_GETUID,
    SYS_SYSLOG,
    SYS_GETGID,
    SYS_SETUID,
    SYS_SETGID,
    SYS_GETEUID,
    SYS_GETEGID,
    SYS_SETPGID,
    SYS_GETPPID, // 110
    SYS_GETPGRP,
    SYS_SETSID,
    SYS_SETREUID,
    SYS_SETREGID,
    SYS_GETGROUPS,
    SYS_SETGROUPS,
    SYS_SETRESUID,
    SYS_GETRESUID,
    SYS_SETRESGID,
    SYS_GETRESGID, // 120
    SYS_GETPGID,
    SYS_SETFSUID,
    SYS_SETFSGID,
    SYS_GETSID,
    SYS_CAPGET,
    SYS_CAPSET,
    SYS_RT_SIGPENDING,
    SYS_RT_SIGTIMEDWAIT,
    SYS_RT_SIGQUEUEINFO,
    SYS_RT_SIGSUSPEND, // 130
    SYS_SIGALTSTACK,
    SYS_UTIME,
    SYS_MKNOD,
    SYS_USELIB,
    SYS_PERSONALITY,
    SYS_USTAT,
    SYS_STATFS,
    SYS_FSTATFS,
    SYS_SYSFS,
    SYS_GETPRIORITY, // 140
    SYS_SETPRIORITY,
    SYS_SCHED_SETPARAM,
    SYS_SCHED_GETPARAM,
    SYS_SCHED_SETSCHEDULER,
    SYS_SCHED_GETSCHEDULER,
    SYS_SCHED_GET_PRIORITY_MAX,
    SYS_SCHED_GET_PRIORITY_MIN,
    SYS_SCHED_RR_GET_INTERVAL,
    SYS_MLOCK,
    SYS_MUNLOCK, // 150
    SYS_MLOCKALL,
    SYS_MUNLOCKALL,
    SYS_VHANGUP,
    SYS_MODIFY_LDT,
    SYS_PIVOT_ROOT,
    SYS_SYSCTL,
    SYS_PRCTL,
    SYS_ARCH_PRCTL,
    SYS_ADJTIMEX,
    SYS_SETRLIMIT, // 160
    SYS_CHROOT,
    SYS_SYNC,
    SYS_ACCT,
    SYS_SETTIMEOFDAY,
    SYS_MOUNT,
    SYS_UMOUNT,
    SYS_SWAPON,
    SYS_SWAPOFF,
    SYS_REBOOT,
    SYS_SETHOSTNAME, // 170
    SYS_SETDOMAINNAME,
    SYS_IOPL,
    SYS_IOPERM,
    SYS_CREATE_MODULE,
    SYS_INIT_MODULE,
    SYS_DELETE_MODULE,
    SYS_GET_KERNEL_SYMS,
    SYS_QUERY_MODULE,
    SYS_QUOTACTL,
    SYS_NFSSERVCTL, // 180
    SYS_GETPMSG,
    SYS_PUTPMSG,
    SYS_AFS,
    SYS_TUXCALL,
    SYS_SECURITY,
    SYS_GETTID,
    SYS_READAHEAD,
    SYS_SETXATTR,
    SYS_LSETXATTR,
    SYS_FSETXATTR, // 190
    SYS_GETXATTR,
    SYS_LGETXATTR,
    SYS_FGETXATTR,
    SYS_LISTXATTR,
    SYS_LLISTXATTR,
    SYS_FLISTXATTR,
    SYS_REMOVEXATTR,
    SYS_LREMOVEXATTR,
    SYS_FREMOVEXATTR,
    SYS_TKILL, // 200
    SYS_TIME,
    SYS_FUTEX,
    SYS_SCHED_SETAFFINITY,
    SYS_SCHED_GETAFFINITY,
    SYS_SET_THREAD_AREA,
    SYS_IO_SETUP,
    SYS_IO_DESTROY,
    SYS_IO_GETEVENTS,
    SYS_IO_SUBMIT,
    SYS_IO_CANCEL, // 210
    SYS_GET_THREAD_AREA,
    SYS_LOOOKUP_DCOOKIE,
    SYS_EPOLL_CREATE,
    SYS_EPOLL_CTL_OLD,
    SYS_EPOLL_WAIT_OLD,
    SYS_REMAP_FILE_PAGES,
    SYS_GETDENTS64,
    SYS_SET_TID_ADDRESS,
    SYS_RESTART_SYSCALL,
    SYS_SEMTIMEDOP, // 220
    SYS_FADVISE64,
    SYS_TIMER_CREATE,
    SYS_TIMER_SETTIME,
    SYS_TIMER_GETTIME,
    SYS_TIMER_GETOVERRUN,
    SYS_TIMER_DELETE,
    SYS_CLOCK_SETTIME,
    SYS_CLOCK_GETTIME,
    SYS_CLOCK_GETRES,
    SYS_CLOCK_NANOSLEEP, // 230
    SYS_EXIT_GROUP,
    SYS_EPOLL_WAIT,
    SYS_EPOLL_CTL,
    SYS_TGKILL,
    SYS_UTIMES,
    SYS_VSERVER,
    SYS_MBIND,
    SYS_SET_MEMPOLICY,
    SYS_GET_MEMPOLICY,
    SYS_MQ_OPEN, // 240
    SYS_MQ_UNLINK,
    SYS_MQ_TIMEDSEND,
    SYS_MQ_TIMEDRECEIVE,
    SYS_MQ_NOTIFY,
    SYS_MQ_GETSETATTR,
    SYS_KEXEC_LOAD,
    SYS_WAITID,
    SYS_ADD_KEY,
    SYS_REQUEST_KEY,
    SYS_KEYCTL, // 250
    SYS_IOPRIO_SET,
    SYS_IOPRIO_GET,
    SYS_INOTIFY_INIT,
    SYS_INOTIFY_ADD_WATCH,
    SYS_INOTIFY_RM_WATCH,
    SYS_MIGRATE_PAGES,
    SYS_OPENAT,
    SYS_MKDIRAT,
    SYS_MKNODAT,
    SYS_FCHOWNAT, // 260
    SYS_FUTIMESAT,
    SYS_NEWFSTATAT,
    SYS_UNLINKAT,
    SYS_RENAMEAT,
    SYS_LINKAT,
    SYS_SYMLINKAT,
    SYS_READLINKAT,
    SYS_FCHMODAT,
    SYS_FACCESSAT,
    SYS_PSELECT6, // 270
    SYS_PPOLL,
    SYS_UNSHARE,
    SYS_SET_ROBUST_LIST,
    SYS_GET_ROBUST_LIST,
    SYS_SPLICE,
    SYS_TEE,
    SYS_SYNC_FILE_RANGE,
    SYS_VMSPLICE,
    SYS_MOVE_PAGES,
    SYS_UTIMENSAT, // 280
    SYS_EPOLL_PWAIT,
    SYS_SIGNALFD,
    SYS_TIMERFD_CREATE,
    SYS_EVENTFD,
    SYS_FALLOCATE,
    SYS_TIMERFD_SETTIME,
    SYS_TIMERFD_GETTIME,
    _SYS_ACCEPT4,
    SYS_SIGNALFD4,
    SYS_EVENTFD2, // 290
    SYS_EPOLL_CREATE1,
    SYS_DUP3,
    SYS_PIPE2,
    SYS_IONOTIFY_INIT1,
    SYS_PREADV,
    SYS_PWRITEV,
    SYS_RT_TGSIGQUEUEINFO,
    SYS_PERF_EVENT_OPEN,
    _SYS_RECVMMSG,
    SYS_FANOTIFY_INIT, // 300
    SYS_FANOTIFY_MARK,
    SYS_PRLIMIT64,
    SYS_NAME_TO_HANDLE_AT,
    SYS_OPEN_BY_HANDLE_AT,
    SYS_CLOCK_ADJTIME,
    SYS_SYNCFS,
    _SYS_SENDMMSG,
    SYS_SETNS,
    SYS_GETCPU,
    SYS_PROCESS_VM_READV, // 310
    SYS_PROCESS_VM_WRITEV,
    SYS_KCMP,
    SYS_FINIT_MODULE,
    SYS_SCHED_SETATTR,
    SYS_SCHED_GETATTR,
    SYS_RENAMEAT2,
    SYS_SECCOMPP,
    SYS_GETRANDOM,
    SYS_MEMFD_CREATE,
    SYS_KEXEC_FILE_LOAD, // 320
    SYS_BPF,
    SYS_EXECVEAT,
    SYS_USERFAULTFD,
    SYS_MEMBARRIER,
    SYS_MLOCK2,
    SYS_COPY_FILE_RANGE,
    SYS_PREADV2,
    SYS_PWRITEV2,
    SYS_PKEY_MPROTECT,
    SYS_PKEY_ALLOC, // 330
    SYS_PKRY_FREE,
    SYS_STATX,
    SYS_IO_PGETEVENTS,
    SYS_RSEQ,
    DO_EXIT = 351,
};

typedef struct __attribute__((__packed__)) context {
    u64 ts;

    u32 pid_id;
    u32 mnt_id;

    u32 host_pid;

    u32 ppid;
    u32 pid;
    u32 tid;
    u32 uid;

    u32 eventid;
    u32 argnum;
    s32 retval;

    char comm[TASK_COMM_LEN];
} context_t;

typedef struct args {
    unsigned long args[6];
} args_t;

typedef struct simple_buf {
    u8 buf[MAX_PERCPU_BUFSIZE];
} buf_t;

BPF_HASH(pids_map, u32, u32);
BPF_HASH(args_map, u64, args_t);
BPF_PERCPU_ARRAY(bufs, buf_t, MAX_BUFFERS);
BPF_PERCPU_ARRAY(bufs_off, u32, MAX_BUFFERS);

BPF_PERF_OUTPUT(events);

// == Skb Monitor == //

typedef struct __attribute__((__packed__)) context_skb {
    u64 ts;

    u32 pid_id;
    u32 mnt_id;

    u32 host_pid;

    u8 l4_proto;
    u8 pad1[3];

    u32 saddr;
    u32 daddr;

    u16 sport;
    u16 dport;

    u32 pad4;

    u64 network_key;
} context_skb_t;

BPF_HASH(host_pid_skb_map, u32, u32);

BPF_PERF_OUTPUT(events_skb);

// == Kernel Helpers == //

static __always_inline u32 get_task_pid_ns_id(struct task_struct *task)
{
    return task->nsproxy->pid_ns_for_children->ns.inum;
}

struct mnt_namespace {
    atomic_t count;
    struct ns_common ns;
};

static __always_inline u32 get_task_mnt_ns_id(struct task_struct *task)
{
    return task->nsproxy->mnt_ns->ns.inum;
}

static __always_inline u32 get_task_ns_ppid(struct task_struct *task)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 19, 0)
    return task->real_parent->pids[PIDTYPE_PID].pid->numbers[task->real_parent->nsproxy->pid_ns_for_children->level].nr;
#else
    return task->real_parent->thread_pid->numbers[task->real_parent->nsproxy->pid_ns_for_children->level].nr;
#endif
}

static __always_inline u32 get_task_ns_tgid(struct task_struct *task)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 19, 0)
    return task->group_leader->pids[PIDTYPE_PID].pid->numbers[task->nsproxy->pid_ns_for_children->level].nr;
#else
    return task->group_leader->thread_pid->numbers[task->nsproxy->pid_ns_for_children->level].nr;
#endif
}

static __always_inline u32 get_task_ns_pid(struct task_struct *task)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 19, 0)
    return task->pids[PIDTYPE_PID].pid->numbers[task->nsproxy->pid_ns_for_children->level].nr;
#else
    return task->thread_pid->numbers[task->nsproxy->pid_ns_for_children->level].nr;
#endif
}

// == Pid Management == //

static __always_inline u32 lookup_pid_ns(struct task_struct *task)
{
    u32 task_pid_ns = get_task_pid_ns_id(task);

    u32 *pid_ns = pids_map.lookup(&task_pid_ns);
    if (pid_ns == 0)
        return 0;

    return *pid_ns;
}

static __always_inline u32 add_pid_ns_if_needed()
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    u32 pid_ns = get_task_pid_ns_id(task);

    if (pids_map.lookup(&pid_ns) != 0)
        return pid_ns;

    if (get_task_ns_pid(task) == 1) {
        pids_map.update(&pid_ns, &pid_ns);
        return pid_ns;
    }

    return 0;
}

static __always_inline void remove_pid_ns_if_needed()
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    u32 pid_ns = get_task_pid_ns_id(task);
    
    if (pids_map.lookup(&pid_ns) != 0) {
        if (get_task_ns_pid(task) == 1) {
            pids_map.delete(&pid_ns);
        }
    }
}

static __always_inline int should_trace()
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    u32 rc = lookup_pid_ns(task);
    return rc;
}

// == Context Management == //

static __always_inline int init_context(context_t *context)
{
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();

    context->ts = bpf_ktime_get_ns();

    context->pid_id = get_task_pid_ns_id(task);
    context->mnt_id = get_task_mnt_ns_id(task);

    context->host_pid = bpf_get_current_pid_tgid() >> 32;    
    
    context->ppid = get_task_ns_ppid(task);
    context->pid = get_task_ns_tgid(task);
    context->tid = get_task_ns_pid(task);
    context->uid = bpf_get_current_uid_gid();

    bpf_get_current_comm(&context->comm, sizeof(context->comm));

    return 0;
}

// == Argument Management == //

static __always_inline void get_syscall_args(struct pt_regs *ctx, args_t *args)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 17, 0)
    args->args[0] = PT_REGS_PARM1(ctx);
    args->args[1] = PT_REGS_PARM2(ctx);
    args->args[2] = PT_REGS_PARM3(ctx);
    args->args[3] = PT_REGS_PARM4(ctx);
    args->args[4] = PT_REGS_PARM5(ctx);
    args->args[5] = PT_REGS_PARM6(ctx);
#else
    struct pt_regs * ctx2 = (struct pt_regs *)ctx->di;
    bpf_probe_read(&args->args[0], sizeof(args->args[0]), &ctx2->di);
    bpf_probe_read(&args->args[1], sizeof(args->args[1]), &ctx2->si);
    bpf_probe_read(&args->args[2], sizeof(args->args[2]), &ctx2->dx);
    bpf_probe_read(&args->args[3], sizeof(args->args[3]), &ctx2->r10);
    bpf_probe_read(&args->args[4], sizeof(args->args[4]), &ctx2->r8);
    bpf_probe_read(&args->args[5], sizeof(args->args[5]), &ctx2->r9);
#endif
}

static __always_inline int load_args(args_t *args, bool delete, u32 event_id)
{
    u32 tgid = bpf_get_current_pid_tgid();
    u64 id = ((u64)event_id << 32) | tgid;

    args_t *saved_args = args_map.lookup(&id);
    if (saved_args == 0) {
        return -1; // missed entry or not a container
    }

    args->args[0] = saved_args->args[0];
    args->args[1] = saved_args->args[1];
    args->args[2] = saved_args->args[2];
    args->args[3] = saved_args->args[3];
    args->args[4] = saved_args->args[4];
    args->args[5] = saved_args->args[5];

    if (delete)
        args_map.delete(&id);

    return 0;
}

static __always_inline int save_args(struct pt_regs *ctx, u32 event_id, bool is_syscall)
{
    args_t args = {};

    if (!is_syscall) {
        args.args[0] = PT_REGS_PARM1(ctx);
        args.args[1] = PT_REGS_PARM2(ctx);
        args.args[2] = PT_REGS_PARM3(ctx);
        args.args[3] = PT_REGS_PARM4(ctx);
        args.args[4] = PT_REGS_PARM5(ctx);
        args.args[5] = PT_REGS_PARM6(ctx);
    } else {
        get_syscall_args(ctx, &args);
    }

    u32 tgid = bpf_get_current_pid_tgid();
    u64 id = ((u64)event_id << 32) | tgid;

    args_map.update(&id, &args);

    return 0;
}

static __always_inline int get_arg_num(u64 types)
{
    unsigned int i, argnum = 0;

    #pragma unroll
    for(i=0; i<6; i++) {
        if (DEC_ARG_TYPE(i, types) != NONE_T)
            argnum++;
    }

    return argnum;
}

// == Buffer Management == //

static __always_inline buf_t* get_buf(int idx)
{
    return bufs.lookup(&idx);
}

static __always_inline void set_buf_off(int buf_idx, u32 new_off)
{
    bufs_off.update(&buf_idx, &new_off);
}

static __always_inline u32* get_buf_off(int buf_idx)
{
    return bufs_off.lookup(&buf_idx);
}

static __always_inline int save_context_to_buf(buf_t *submit_p, void *ptr)
{
    int rc = bpf_probe_read(&(submit_p->buf[0]), sizeof(context_t), ptr);
    if (rc == 0)
        return sizeof(context_t);

    return 0;
}

static __always_inline int save_to_submit_buf(buf_t *submit_p, void *ptr, int size, u8 type)
{
    // the biggest element that can be saved with this function should be defined here
    #define MAX_ELEMENT_SIZE sizeof(struct sockaddr_un)

    if (type == 0)
        return 0;

    u32* off = get_buf_off(SUBMIT_BUF_IDX);
    if (off == NULL)
        return -1;
    if (*off > MAX_PERCPU_BUFSIZE - MAX_ELEMENT_SIZE)
        return 0;

    int rc = bpf_probe_read(&(submit_p->buf[*off]), 1, &type);
    if (rc != 0)
        return 0;

    *off += 1;

    if (*off > MAX_PERCPU_BUFSIZE - MAX_ELEMENT_SIZE)
        return 0;

    rc = bpf_probe_read(&(submit_p->buf[*off]), size, ptr);
    if (rc == 0) {
        *off += size;
        set_buf_off(SUBMIT_BUF_IDX, *off);
        return size;
    }

    return 0;
}

static __always_inline int save_str_to_buf(buf_t *submit_p, void *ptr)
{
    u32* off = get_buf_off(SUBMIT_BUF_IDX);
    if (off == NULL)
        return -1;
    if (*off > MAX_PERCPU_BUFSIZE - MAX_STRING_SIZE - sizeof(int))
        return 0; // not enough space - return

    u8 type = STR_T;
    bpf_probe_read(&(submit_p->buf[*off & (MAX_PERCPU_BUFSIZE-1)]), 1, &type);

    *off += 1;

    if (*off > MAX_PERCPU_BUFSIZE - MAX_STRING_SIZE - sizeof(int))
        return 0;

    // Read into buffer
    int sz = bpf_probe_read_str(&(submit_p->buf[*off + sizeof(int)]), MAX_STRING_SIZE, ptr);
    if (sz > 0) {
        if (*off > MAX_PERCPU_BUFSIZE - sizeof(int))
            return 0;

        bpf_probe_read(&(submit_p->buf[*off]), sizeof(int), &sz);

        *off += sz + sizeof(int);
        set_buf_off(SUBMIT_BUF_IDX, *off);

        return sz + sizeof(int);
    }

    return 0;
}

static __always_inline int events_perf_submit(struct pt_regs *ctx)
{
    u32* off = get_buf_off(SUBMIT_BUF_IDX);
    if (off == NULL)
        return -1;

    buf_t *submit_p = get_buf(SUBMIT_BUF_IDX);
    if (submit_p == NULL)
        return -1;

    int size = *off & (MAX_PERCPU_BUFSIZE-1);
    void * data = submit_p->buf;

    return events.perf_submit(ctx, data, size);
}

static __always_inline int save_argv(buf_t *submit_p, void *ptr)
{
    const char *argp = NULL;
    bpf_probe_read(&argp, sizeof(argp), ptr);
    if (argp) {
        return save_str_to_buf(submit_p, (void *)(argp));
    }

    return 0;
}

static __always_inline int save_str_arr_to_buf(buf_t *submit_p, const char __user *const __user *ptr)
{
    save_to_submit_buf(submit_p, NULL, 0, STR_ARR_T);

    #pragma unroll
    for (int i = 0; i < MAX_STR_ARR_ELEM; i++) {
        if (save_argv(submit_p, (void *)&ptr[i]) == 0)
             goto out;
    }

    char ellipsis[] = "...";
    save_str_to_buf(submit_p, (void *)ellipsis);

out:
    save_to_submit_buf(submit_p, NULL, 0, STR_ARR_T);

    return 0;
}

static __always_inline int save_args_to_submit_buf(u64 types, args_t *args)
{
    unsigned int i;
    short family = 0;

    if (types == 0)
        return 0;

    buf_t *submit_p = get_buf(SUBMIT_BUF_IDX);
    if (submit_p == NULL)
        return 0;

    #pragma unroll
    for(i=0; i<6; i++) {
        switch (DEC_ARG_TYPE(i, types))
        {
            case NONE_T:
                break;
            case INT_T:
                save_to_submit_buf(submit_p, (void*)&(args->args[i]), sizeof(int), INT_T);
                break;
            case OPEN_FLAGS_T:
                save_to_submit_buf(submit_p, (void*)&(args->args[i]), sizeof(int), OPEN_FLAGS_T);
            case STR_T:
                save_str_to_buf(submit_p, (void *)args->args[i]);
                break;
            case SOCK_DOM_T:
                save_to_submit_buf(submit_p, (void*)&(args->args[i]), sizeof(int), SOCK_DOM_T);
                break;
            case SOCK_TYPE_T:
                save_to_submit_buf(submit_p, (void*)&(args->args[i]), sizeof(int), SOCK_TYPE_T);
                break;
            case SOCKADDR_T:
                if (args->args[i]) {
                    bpf_probe_read(&family, sizeof(short), (void*)args->args[i]);
                    switch (family)
                    {
                        case AF_UNIX:
                            save_to_submit_buf(submit_p, (void*)(args->args[i]), sizeof(struct sockaddr_un), SOCKADDR_T);
                            break;
                        case AF_INET:
                            save_to_submit_buf(submit_p, (void*)(args->args[i]), sizeof(struct sockaddr_in), SOCKADDR_T);
                            break;
                        case AF_INET6:
                            save_to_submit_buf(submit_p, (void*)(args->args[i]), sizeof(struct sockaddr_in6), SOCKADDR_T);
                            break;
                        default:
                            save_to_submit_buf(submit_p, (void*)&family, sizeof(short), SOCKADDR_T);
                    }
                }
                break;
        }
    }

    return 0;
}

// == Syscall Hooks (Process) == //

int syscall__execve(struct pt_regs *ctx,
    const char __user *filename,
    const char __user *const __user *__argv,
    const char __user *const __user *__envp)
{
    context_t context = {};

    u32 ret = add_pid_ns_if_needed();
    if (ret == 0)
        return 0;

    init_context(&context);
    set_buf_off(SUBMIT_BUF_IDX, sizeof(context_t));

    buf_t *submit_p = get_buf(SUBMIT_BUF_IDX);
    if (submit_p == NULL)
        return 0;

    context.eventid = SYS_EXECVE;
    context.argnum = 2;
    context.retval = 0;

    save_context_to_buf(submit_p, (void*)&context);
    save_str_to_buf(submit_p, (void *)filename);
    save_str_arr_to_buf(submit_p, __argv);

    events_perf_submit(ctx);

    return 0;
}

int trace_ret_execve(struct pt_regs *ctx)
{
    context_t context = {};

    if (!should_trace())
        return 0;

    init_context(&context);

    context.eventid = SYS_EXECVE;
    context.argnum = 0;
    context.retval = PT_REGS_RC(ctx);

    if (context.retval == 0)
        return 0;

    set_buf_off(SUBMIT_BUF_IDX, sizeof(context_t));

    buf_t *submit_p = get_buf(SUBMIT_BUF_IDX);
    if (submit_p == NULL)
        return 0;

    save_context_to_buf(submit_p, (void*)&context);

    events_perf_submit(ctx);

    return 0;
}

int syscall__execveat(struct pt_regs *ctx,
    const int dirfd,
    const char __user *pathname,
    const char __user *const __user *__argv,
    const char __user *const __user *__envp,
    const int flags)
{
    context_t context = {};

    u32 ret = add_pid_ns_if_needed();
    if (ret == 0)
        return 0;

    init_context(&context);
    set_buf_off(SUBMIT_BUF_IDX, sizeof(context_t));

    buf_t *submit_p = get_buf(SUBMIT_BUF_IDX);
    if (submit_p == NULL)
        return 0;

    context.eventid = SYS_EXECVEAT;
    context.argnum = 4;
    context.retval = 0;

    save_context_to_buf(submit_p, (void*)&context);

    save_to_submit_buf(submit_p, (void*)&dirfd, sizeof(int), INT_T);
    save_str_to_buf(submit_p, (void *)pathname);
    save_str_arr_to_buf(submit_p, __argv);
    save_to_submit_buf(submit_p, (void*)&flags, sizeof(int), EXEC_FLAGS_T);

    events_perf_submit(ctx);

    return 0;
}

int trace_ret_execveat(struct pt_regs *ctx)
{
    context_t context = {};

    if (!should_trace())
        return 0;

    init_context(&context);

    context.eventid = SYS_EXECVEAT;
    context.argnum = 0;
    context.retval = PT_REGS_RC(ctx);

    if (context.retval == 0)
        return 0;

    set_buf_off(SUBMIT_BUF_IDX, sizeof(context_t));

    buf_t *submit_p = get_buf(SUBMIT_BUF_IDX);
    if (submit_p == NULL)
        return 0;

    save_context_to_buf(submit_p, (void*)&context);

    events_perf_submit(ctx);

    return 0;
}

int trace_do_exit(struct pt_regs *ctx, long code)
{
    context_t context = {};

    if (!should_trace())
        return 0;

    init_context(&context);

    context.eventid = DO_EXIT;
    context.argnum = 0;
    context.retval = code;

    remove_pid_ns_if_needed();

    if (context.retval == 0)
        return 0;

    set_buf_off(SUBMIT_BUF_IDX, sizeof(context_t));

    buf_t *submit_p = get_buf(SUBMIT_BUF_IDX);
    if (submit_p == NULL)
        return 0;

    save_context_to_buf(submit_p, (void*)&context);

    events_perf_submit(ctx);

    return 0;
}

// == Syscall Hooks (File) == //

static __always_inline int trace_ret_generic(struct pt_regs *ctx, u32 id, u64 types, bool delete_args)
{
    context_t context = {};
    args_t args = {};

    if (load_args(&args, delete_args, id) != 0)
        return -1;

    if (!should_trace())
        return -1;

    init_context(&context);

    context.eventid = id;
    context.argnum = get_arg_num(types);
    context.retval = PT_REGS_RC(ctx);

    if (context.retval == 0)
        return 0;

    set_buf_off(SUBMIT_BUF_IDX, sizeof(context_t));

    buf_t *submit_p = get_buf(SUBMIT_BUF_IDX);
    if (submit_p == NULL)
        return 0;

    save_context_to_buf(submit_p, (void*)&context);
    save_args_to_submit_buf(types, &args);

    events_perf_submit(ctx);

    return 0;
}

int syscall__open(struct pt_regs *ctx)                                
{                                                                      
    if (!should_trace())                                               
        return 0;                                                      

    return save_args(ctx, SYS_OPEN, true);                                   
}

int trace_ret_open(struct pt_regs *ctx)                               
{                                                                     
    return trace_ret_generic(ctx, SYS_OPEN, ARG_TYPE0(STR_T)|ARG_TYPE1(OPEN_FLAGS_T), true);            
}

int syscall__close(struct pt_regs *ctx)                                
{                                                                      
    if (!should_trace())                                               
        return 0;                                                      

    return save_args(ctx, SYS_CLOSE, true);
}

int trace_ret_close(struct pt_regs *ctx)                               
{                                                                     
    return trace_ret_generic(ctx, SYS_CLOSE, ARG_TYPE0(INT_T), true);
}

// == Syscall Hooks (Network) == //

int syscall__socket(struct pt_regs *ctx)                                
{                                                                      
    if (!should_trace())                                               
        return 0;                                                      

    return save_args(ctx, _SYS_SOCKET, true);                                   
}

int trace_ret_socket(struct pt_regs *ctx)                               
{                                                                     
    return trace_ret_generic(ctx, _SYS_SOCKET, ARG_TYPE0(SOCK_DOM_T)|ARG_TYPE1(SOCK_TYPE_T)|ARG_TYPE2(INT_T), true);            
}

int syscall__connect(struct pt_regs *ctx)                                
{                                                                      
    if (!should_trace())                                               
        return 0;                                                      

    return save_args(ctx, _SYS_CONNECT, true);                                   
}

int trace_ret_connect(struct pt_regs *ctx)                               
{                                                                     
    return trace_ret_generic(ctx, _SYS_CONNECT, ARG_TYPE0(INT_T)|ARG_TYPE1(SOCKADDR_T), true);            
}

int syscall__accept(struct pt_regs *ctx)                                
{                                                                      
    if (!should_trace())                                               
        return 0;                                                      

    return save_args(ctx, _SYS_ACCEPT, true);                                   
}

int trace_ret_accept(struct pt_regs *ctx)                               
{                                                                     
    return trace_ret_generic(ctx, _SYS_ACCEPT, ARG_TYPE0(INT_T)|ARG_TYPE1(SOCKADDR_T), true);            
}

int syscall__bind(struct pt_regs *ctx)                                
{                                                                      
    if (!should_trace())                                               
        return 0;                                                      

    return save_args(ctx, _SYS_BIND, true);                                   
}

int trace_ret_bind(struct pt_regs *ctx)                               
{                                                                     
    return trace_ret_generic(ctx, _SYS_BIND, ARG_TYPE0(INT_T)|ARG_TYPE1(SOCKADDR_T), true);            
}

int syscall__listen(struct pt_regs *ctx)                                
{                                                                      
    if (!should_trace())                                               
        return 0;                                                      

    return save_args(ctx, _SYS_LISTEN, true);                                   
}

int trace_ret_listen(struct pt_regs *ctx)                               
{                                                                     
    return trace_ret_generic(ctx, _SYS_LISTEN, ARG_TYPE0(INT_T)|ARG_TYPE1(INT_T), true);            
}

// == Skb Hooks == //

#define MAC_HEADER_SIZE 14;

#define member_address(source_struct, source_member)                                                \
    ({                                                                                              \
        void* __ret;                                                                                \
        __ret = (void*) (((char*)source_struct) + offsetof(typeof(*source_struct), source_member)); \
        __ret;                                                                                      \
    })

#define member_read(destination, source_struct, source_member)                                                           \
    do{                                                                                                                  \
        bpf_probe_read(destination, sizeof(source_struct->source_member), member_address(source_struct, source_member)); \
    } while(0)

struct tcphdr {
	__be16	source;
	__be16	dest;
	__be32	seq;
	__be32	ack_seq;
    __u8    doff;
    __u8    th_flags;
	__be16	window;
	__sum16	check;
	__be16	urg_ptr;
};

union tcp_word_hdr { 
	struct tcphdr hdr;
	__be32 		  words[5];
}; 

struct udphdr {
	__be16	source;
	__be16	dest;
	__be16	len;
	__sum16	check;
};

BPF_HASH(network_map, u64, u64, 4096);
// BPF_TABLE_PINNED("hash", u64, u64, network_map, 4096, "/sys/fs/bpf/kubearmor/network_map");

static int do_trace_skb(context_skb_t *context_skb, struct sk_buff *skb, u32 policy_id)
{
    char *head;
    char *l3_header_address;
    char *l4_header_address;

    u16 mac_header;
    u16 network_header;

    struct iphdr iphdr;
    union tcp_word_hdr tcphdr;
    struct udphdr udphdr;

    member_read(&head, skb, head);
    member_read(&mac_header, skb, mac_header);
    member_read(&network_header, skb, network_header);

    if(network_header == 0) {
        network_header = mac_header + MAC_HEADER_SIZE;
    }

    l3_header_address = head + network_header;

    u8 ip_version;
    bpf_probe_read(&ip_version, sizeof(u8), l3_header_address);
    ip_version = ip_version >> 4 & 0xf;

    if (ip_version == 4) {
        bpf_probe_read(&iphdr, sizeof(iphdr), l3_header_address);

        context_skb->l4_proto = iphdr.protocol;

        context_skb->saddr = iphdr.saddr;
        context_skb->daddr = iphdr.daddr;
    } else {
        return -1;
    }

    l4_header_address = l3_header_address + (iphdr.ihl * 4);

    switch (context_skb->l4_proto) {
    case IPPROTO_TCP:
        bpf_probe_read(&tcphdr, sizeof(tcphdr), l4_header_address);

        context_skb->sport = tcphdr.hdr.source;
        context_skb->dport = tcphdr.hdr.dest;

        break;
    case IPPROTO_UDP:
        bpf_probe_read(&udphdr, sizeof(udphdr), l4_header_address);

        context_skb->sport = udphdr.source;
        context_skb->dport = udphdr.dest;

        break;
    default:
        return -1;
    }

    if (context_skb->saddr == 16777343) { // "127.0.0.1"
        return 0;
    }

    u64 network_key = (u64)context_skb->saddr << 24 | context_skb->l4_proto << 16 | context_skb->sport;
    u64 network_val = (u64) policy_id << 32 | 0xFFFF;
    network_map.update(&network_key, &network_val);

    context_skb->network_key = network_key;
    
    return 0;
}

static int do_trace(void *ctx, struct sk_buff *skb, void *netdev, u32 policy_id)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    context_skb_t context_skb = {};

    if (do_trace_skb(&context_skb, skb, policy_id) < 0)
        return 0;

    context_skb.ts = bpf_ktime_get_ns();

    context_skb.pid_id = get_task_pid_ns_id(task);
    context_skb.mnt_id = get_task_mnt_ns_id(task);

    u64 id = bpf_get_current_pid_tgid();
    context_skb.host_pid = id >> 32;

    events_skb.perf_submit(ctx, &context_skb, sizeof(context_skb));

    return 0;
}

int kprobe__ip_output(struct pt_regs *ctx, struct net *net, struct sock *sk, struct sk_buff *skb)
{
    if (!should_trace())
        return 0;

    u32 host_pid = bpf_get_current_pid_tgid() >> 32;

    u32 *policy_id = host_pid_skb_map.lookup(&host_pid);
    if (policy_id == 0)
        return 0;

   return do_trace(ctx, skb, NULL, *policy_id);
}
