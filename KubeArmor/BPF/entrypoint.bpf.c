// +build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 1 << 10);
} ka_ea_event_map SEC(".maps");

enum {
    // process
    _SYS_EXECVE = 59,
    _SYS_EXECVEAT = 322,

    // file
    _SYS_OPEN = 2,
    _SYS_OPENAT = 257,

    // network
    _SYS_SOCKET = 41,
    _SYS_CONNECT = 42,
    _SYS_ACCEPT = 43,
    _SYS_BIND = 49,
    _SYS_LISTEN = 50,
};

int skip_syscall(uint32_t key)
{
    uint32_t *val = bpf_map_lookup_elem(&ka_ea_event_map, &key);
    if (val == 0) return 1;
    else if (val != 0 && *val == 0) return 1;
    return 0;
}

// process

SEC("tp/syscalls/sys_enter_execve")
int syscall__sys_execve(void *ctx)
{
    if (skip_syscall(_SYS_EXECVE)) {
        // bpf_printk("[ka-ea-entrypoint]: fail - sys_execve");
        return 0;
    }
    bpf_printk("[ka-ea-entrypoint]: pass - sys_execve");
    return 0;
}

SEC("tp/syscalls/sys_enter_execveat")
int syscall__sys_execveat(void *ctx)
{
    if (skip_syscall(_SYS_EXECVEAT)) {
        // bpf_printk("[ka-ea-entrypoint]: fail - sys_execveat");
        return 0;
    }
    bpf_printk("[ka-ea-entrypoint]: pass - sys_execveat");
    return 0;
}

// file

SEC("tp/syscalls/sys_enter_open")
int syscall__sys_open(void *ctx)
{
    if (skip_syscall(_SYS_OPEN)) {
        // bpf_printk("[ka-ea-entrypoint]: fail - sys_open");
        return 0;
    }
    bpf_printk("[ka-ea-entrypoint]: pass - sys_open");
    return 0;
}

SEC("tp/syscalls/sys_enter_openat")
int syscall__sys_openat(void *ctx)
{
    if (skip_syscall(_SYS_OPENAT)) {
        // bpf_printk("[ka-ea-entrypoint]: fail - sys_openat");
        return 0;
    }
    bpf_printk("[ka-ea-entrypoint]: pass - sys_openat");
    return 0;
}

// network

SEC("tp/syscalls/sys_enter_socket")
int syscall__sys_socket(void *ctx)
{
    if (skip_syscall(_SYS_SOCKET)) {
        // bpf_printk("[ka-ea-entrypoint]: fail - sys_socket");
        return 0;
    }
    bpf_printk("[ka-ea-entrypoint]: pass - sys_socket");
    return 0;
}

SEC("tp/syscalls/sys_enter_connect")
int syscall__sys_connect(void *ctx)
{
    if (skip_syscall(_SYS_CONNECT)) {
        // bpf_printk("[ka-ea-entrypoint]: fail - sys_connect");
        return 0;
    }
    bpf_printk("[ka-ea-entrypoint]: pass - sys_connect");
    return 0;
}

SEC("tp/syscalls/sys_enter_accept")
int syscall__sys_accept(void *ctx)
{
    if (skip_syscall(_SYS_ACCEPT)) {
        // bpf_printk("[ka-ea-entrypoint]: fail - sys_accept");
        return 0;
    }
    bpf_printk("[ka-ea-entrypoint]: pass - sys_accept");
    return 0;
}

SEC("tp/syscalls/sys_enter_bind")
int syscall__sys_bind(void *ctx)
{
    if (skip_syscall(_SYS_BIND)) {
        // bpf_printk("[ka-ea-entrypoint]: fail - sys_bind");
        return 0;
    }
    bpf_printk("[ka-ea-entrypoint]: pass - sys_bind");
    return 0;
}

SEC("tp/syscalls/sys_enter_listen")
int syscall__sys_listen(void *ctx)
{
    if (skip_syscall(_SYS_LISTEN)) {
        // bpf_printk("[ka-ea-entrypoint]: fail - sys_listen");
        return 0;
    }
    bpf_printk("[ka-ea-entrypoint]: pass - sys_listen");
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
