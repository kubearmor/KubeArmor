// SPDX-License-Identifier: GPL-2.0
// Copyright 2021 Authors of KubeArmor

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#include "maps.bpf.h"

SEC("tracepoint/sys_enter_execve")
int ka_ea_sys_execve(void *ctx)
{
	bpf_printk("hello from sys_enter_execve");

	return 0;
}

SEC("tracepoint/sys_enter_exit")
int ka_ea_sys_exit(void *ctx)
{
	bpf_printk("bye from sys_enter_exit");

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
