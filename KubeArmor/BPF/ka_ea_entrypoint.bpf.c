// SPDX-License-Identifier: GPL-2.0
// Copyright 2021 Authors of KubeArmor

#include "common.bpf.h"
#include "maps.bpf.h"

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 1 << 10);
} ka_ea_event_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct event_filter_key);
	__type(value, struct event_filter_value);
	__uint(max_entries, 1 << 10);
} ka_ea_event_filter_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 1 << 16);
} ka_ea_event_jmp_table SEC(".maps");

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

static inline int
call_event_handler(void *ctx, uint32_t event_id)
{
	struct event_filter_key key;
	struct event_filter_value *value;
	struct task_struct *task;

	task = (struct task_struct *) bpf_get_current_task();
	key.pid_ns = task_get_pid_ns(task);
	key.mnt_ns = task_get_mnt_ns(task);
	key.event_id = event_id;

	value = bpf_map_lookup_elem(&ka_ea_event_filter_map, &key);
	if (value) {
		bpf_tail_call(ctx, &ka_ea_event_jmp_table, value->jmp_idx);
	}

	return 0;
}

int skip_syscall(uint32_t key)
{
	uint32_t *val;

	val = bpf_map_lookup_elem(&ka_ea_event_map, &key);
	if (!val || *val == 0)
		return 1;

	return 0;
}

// process

SEC("tp/syscalls/sys_enter_execve")
int syscall__sys_execve(void *ctx)
{
	if (skip_syscall(_SYS_EXECVE)) {
		return 0;
	}

	call_event_handler(ctx, _SYS_EXECVE);

	return 0;
}

SEC("tp/syscalls/sys_enter_execveat")
int syscall__sys_execveat(void *ctx)
{
	if (skip_syscall(_SYS_EXECVEAT)) {
		return 0;
	}

	call_event_handler(ctx, _SYS_EXECVEAT);

	return 0;
}

// file

SEC("tp/syscalls/sys_enter_open")
int syscall__sys_open(void *ctx)
{
	if (skip_syscall(_SYS_OPEN)) {
		return 0;
	}

	call_event_handler(ctx, _SYS_OPEN);

	return 0;
}

SEC("tp/syscalls/sys_enter_openat")
int syscall__sys_openat(void *ctx)
{
	if (skip_syscall(_SYS_OPENAT)) {
		return 0;
	}

	call_event_handler(ctx, _SYS_OPENAT);

	return 0;
}

// network

SEC("tp/syscalls/sys_enter_socket")
int syscall__sys_socket(void *ctx)
{
	if (skip_syscall(_SYS_SOCKET)) {
		return 0;
	}

	call_event_handler(ctx, _SYS_SOCKET);

	return 0;
}

SEC("tp/syscalls/sys_enter_connect")
int syscall__sys_connect(void *ctx)
{
	if (skip_syscall(_SYS_CONNECT)) {
		return 0;
	}

	call_event_handler(ctx, _SYS_CONNECT);

	return 0;
}

SEC("tp/syscalls/sys_enter_accept")
int syscall__sys_accept(void *ctx)
{
	if (skip_syscall(_SYS_ACCEPT)) {
		return 0;
	}

	call_event_handler(ctx, _SYS_ACCEPT);

	return 0;
}

SEC("tp/syscalls/sys_enter_bind")
int syscall__sys_bind(void *ctx)
{
	if (skip_syscall(_SYS_BIND)) {
		return 0;
	}

	call_event_handler(ctx, _SYS_BIND);

	return 0;
}

SEC("tp/syscalls/sys_enter_listen")
int syscall__sys_listen(void *ctx)
{
	if (skip_syscall(_SYS_LISTEN)) {
		return 0;
	}

	call_event_handler(ctx, _SYS_LISTEN);

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
