#ifndef _KERNEL_HELPERS_H
#define _KERNEL_HELPERS_H

#include "common_types.h"

#ifdef KBUILD_MODNAME
#ifdef BTF_SUPPORTED

#define READ_KERN(ptr)                                    \
    ({                                                    \
        typeof(ptr) _val;                                 \
        __builtin_memset((void *)&_val, 0, sizeof(_val)); \
        bpf_core_read((void *)&_val, sizeof(_val), &ptr); \
        _val;                                             \
    })
#else

#include <linux/nsproxy.h> // struct nsproxy
#include <linux/mount.h> // struct vfsmount

#define READ_KERN(ptr)                                     \
    ({                                                     \
        typeof(ptr) _val;                                  \
        __builtin_memset((void *)&_val, 0, sizeof(_val));  \
        bpf_probe_read((void *)&_val, sizeof(_val), &ptr); \
        _val;                                              \
    })
#endif

#undef container_of
#define container_of(ptr, type, member)                    \
    ({                                                     \
        const typeof(((type *)0)->member) *__mptr = (ptr); \
        (type *)((char *)__mptr - offsetof(type, member)); \
    })

#ifndef BTF_SUPPORTED
struct mnt_namespace
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 11, 0)
    atomic_t count;
#endif
    struct ns_common ns;
};

struct mount
{
    struct hlist_node mnt_hash;
    struct mount *mnt_parent;
    struct dentry *mnt_mountpoint;
    struct vfsmount mnt;
};
#endif

#else

#define READ_KERN(ptr)                                    \
    ({                                                    \
        typeof(ptr) _val;                                 \
        __builtin_memset((void *)&_val, 0, sizeof(_val)); \
        bpf_core_read((void *)&_val, sizeof(_val), &ptr); \
        _val;                                             \
    })

#endif    

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

#if (defined(KBUILD_MODNAME) && LINUX_VERSION_CODE < KERNEL_VERSION(4, 19, 0) && !defined(RHEL_RELEASE_GT_8_0) && !defined(BTF_SUPPORTED))
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

#endif // _KERNEL_HELPERS_H