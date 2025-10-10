#ifndef _VISIBILITY_H
#define _VISIBILITY_H

#include "kernel_helpers.h"
#include "common_types.h"

// == Visibility == //
#define DEFAULT_VISIBILITY_KEY 0xc0ffee

enum
{
    _FILE_PROBE = 0,
    _PROCESS_PROBE = 1,
    _NETWORK_PROBE = 2,
    _CAPS_PROBE = 3,
    _DNS_PROBE = 4,
    _IMA_PROBE = 5,

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
}kubearmor_visibility SEC(".maps");

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

#endif // _VISIBILITY_H