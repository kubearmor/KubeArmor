// +build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

// process

SEC("kprobe/sys_execve")
int kprobe__sys_execve(void *ctx)
{
    // uint32_t id = 59;
    // uint32_t *val = bpf_lookup_elem(event_map, &id);
    // if (val == 0) return;
    // else if (val != 0 && *val == 0) return;

    bpf_printk("sys_execve");
    return 0;
}

SEC("kprobe/sys_execveat")
int kprobe__sys_execveat(void *ctx)
{
    bpf_printk("sys_execveat");
    return 0;
}

// file

SEC("kprobe/sys_open")
int kprobe__sys_open(void *ctx)
{
    // int id = 2;

	bpf_printk("sys_open");
    return 0;
}

SEC("kprobe/sys_openat")
int kprobe__sys_openat(void *ctx)
{
	bpf_printk("sys_openat");
    return 0;
}

// network

SEC("kprobe/sys_socket")
int kprobe__sys_socket(void *ctx)
{
	bpf_printk("sys_socket");
    return 0;
}

SEC("kprobe/sys_bind")
int kprobe__sys_bind(void *ctx)
{
    bpf_printk("sys_bind");
    return 0;
}

SEC("kprobe/sys_listen")
int kprobe__sys_listen(void *ctx)
{
    bpf_printk("sys_listen");
    return 0;
}

SEC("kprobe/sys_accept")
int kprobe__sys_accept(void *ctx)
{
    bpf_printk("sys_accept");
    return 0;
}

SEC("kprobe/sys_connect")
int kprobe__sys_connect(void *ctx)
{
    bpf_printk("sys_connect");
    return 0;
}
