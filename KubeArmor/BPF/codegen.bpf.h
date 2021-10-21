/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2021 Authors of KubeArmor */

#ifndef __CODEGEN_BPF_H
#define __CODEGEN_BPF_H

#include "runtime.h"
#include "maps.bpf.h"
#include "common.bpf.h"

union v4addr {
	__u32 d1;
	__u8 octet[4];
} __packed;

union v6addr {
	struct {
		__u32 d1;
		__u32 d2;
		__u32 d3;
		__u32 d4;
	};
	__u8 octet[16];
} __packed;

struct syscalls_enter_execve_args {
	unsigned long long unused;
	long syscall_nr;
	long filename;
	long argv;
	long envp;
};

struct syscalls_enter_execveat_args {
	unsigned long long unused;
	long syscall_nr;
	long fd;
	long filename;
	long argv;
	long envp;
	long flags;
};

struct syscalls_enter_open_args {
	unsigned long long unused;
	long syscall_nr;
	long filename;
	long flags;
	long mode;
};

struct syscalls_enter_openat_args {
	unsigned long long unused;
	long syscall_nr;
	long fd;
	long filename;
	long flags;
	long mode;
};

struct syscalls_enter_socket_args {
	unsigned long long unused;
	long syscall_nr;
	long family;
	long type;
	long protocol;
};

struct syscalls_enter_connect_args {
	unsigned long long unused;
	long syscall_nr;
	long fd;
	long uservaddr;
	long addrlen;
};

struct syscalls_enter_accept_args {
	unsigned long long unused;
	long syscall_nr;
	long fd;
	long upeer_sockaddr;
	long upeer_addrlen_ptr;
};

struct syscalls_enter_bind_args {
	unsigned long long unused;
	long syscall_nr;
	long fd;
	long umyaddr;
	long addrlen;
};

static inline const char *
tp_sys_execve_path(struct syscalls_enter_execve_args *ctx)
{
	return 0;
}

static inline const char *
tp_sys_execveat_path(struct syscalls_enter_execveat_args *ctx)
{
	return 0;
}

static inline int
tp_sys_execveat_flags(struct syscalls_enter_execveat_args *ctx)
{
	return 0;
}

static inline const char *
tp_sys_open_path(struct syscalls_enter_open_args *ctx)
{
	return 0;
}

static inline int
tp_sys_open_flags(struct syscalls_enter_open_args *ctx)
{
	return 0;
}

static inline umode_t
tp_sys_open_mode(struct syscalls_enter_open_args *ctx)
{
	return 0;
}

static inline const char *
tp_sys_openat_path(struct syscalls_enter_openat_args *ctx)
{
	return 0;
}

static inline int
tp_sys_openat_flags(struct syscalls_enter_openat_args *ctx)
{
	return 0;
}

static inline umode_t
tp_sys_openat_mode(struct syscalls_enter_openat_args *ctx)
{
	return 0;
}

static inline int
tp_sys_socket_protocol(struct syscalls_enter_socket_args *ctx)
{
	return 0;
}

static inline union v4addr *
tp_sys_connect_ipv4(struct syscalls_enter_connect_args *ctx)
{
	return 0;
}

static inline union v6addr *
tp_sys_connect_ipv6(struct syscalls_enter_connect_args *ctx)
{
	return 0;
}

static inline unsigned short
tp_sys_connect_port(struct syscalls_enter_connect_args *ctx)
{
	return 0;
}

static inline union v4addr *
tp_sys_accept_ipv4(struct syscalls_enter_accept_args *ctx)
{
	return 0;
}

static inline union v6addr *
tp_sys_accept_ipv6(struct syscalls_enter_accept_args *ctx)
{
	return 0;
}

static inline unsigned short
tp_sys_accept_port(struct syscalls_enter_accept_args *ctx)
{
	return 0;
}

static inline union v4addr *
tp_sys_bind_ipv4(struct syscalls_enter_bind_args *ctx)
{
	return 0;
}

static inline union v6addr *
tp_sys_bind_ipv6(struct syscalls_enter_bind_args *ctx)
{
	return 0;
}

static inline unsigned short
tp_sys_bind_port(struct syscalls_enter_bind_args *ctx)
{
	return 0;
}

static inline bool
ka_ea_check_inspect(void)
{
	struct process_filter_key key;
	struct process_filter_value *value;

	key.pid_ns = task_get_pid_ns(NULL);
	key.mnt_ns = task_get_mnt_ns(NULL);
	key.host_pid = task_get_host_pid();

	value = bpf_map_lookup_elem(__ka_ea_map(ka_ea_process_filter_map), &key);
	return (value && value->inspect);
}

// sys_execve
#define __ka_ea_evt59_path(ctx) \
	tp_sys_execve_path(ctx)

// sys_execveat
#define __ka_ea_evt322_path(ctx)  \
	tp_sys_execveat_path(ctx)
#define __ka_ea_evt322_flags(ctx) \
	tp_sys_execveat_flags(ctx)

// sys_open
#define __ka_ea_evt2_path(ctx)  \
	tp_sys_open_path(ctx)
#define __ka_ea_evt2_flags(ctx) \
	tp_sys_open_flags(ctx)
#define __ka_ea_evt2_mode(ctx)  \
	tp_sys_open_mode(ctx)

// sys_openat
#define __ka_ea_evt257_path(ctx)  \
	tp_sys_openat_path(ctx)
#define __ka_ea_evt257_flags(ctx) \
	tp_sys_openat_flags(ctx)
#define __ka_ea_evt257_mode(ctx)  \
	tp_sys_openat_mode(ctx)

// sys_socket
#define __ka_ea_evt41_protocol(ctx) \
	tp_sys_socket_protocol(ctx)

// sys_connect
#define __ka_ea_evt42_ipv4(ctx) \
	tp_sys_connect_ipv4(ctx)
#define __ka_ea_evt42_ipv6(ctx) \
	tp_sys_connect_ipv6(ctx)
#define __ka_ea_evt42_port(ctx) \
	tp_sys_connect_port(ctx)

// sys_accept
#define __ka_ea_evt43_ipv4(ctx) \
	tp_sys_accept_ipv4(ctx)
#define __ka_ea_evt43_ipv6(ctx) \
	tp_sys_accept_ipv6(ctx)
#define __ka_ea_evt43_port(ctx) \
	tp_sys_accept_port(ctx)

// sys_bind
#define __ka_ea_evt49_ipv4(ctx) \
	tp_sys_bind_ipv4(ctx)
#define __ka_ea_evt49_ipv6(ctx) \
	tp_sys_bind_ipv6(ctx)
#define __ka_ea_evt49_port(ctx) \
	tp_sys_bind_port(ctx)

#define __ka_ea_evt_log(m) \
	bpf_printk(m)

char LICENSE[] SEC("license") = "GPL";

#endif /* __CODEGEN_BPF_H */
