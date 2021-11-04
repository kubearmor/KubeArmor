/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2021 Authors of KubeArmor */

#ifndef __CODEGEN_BPF_H
#define __CODEGEN_BPF_H

#include "hash.h"
#include "runtime.h"
#include "maps.bpf.h"
#include "common.bpf.h"

#define ntohs(n) \
	(((((u16)(n) & 0xFF)) << 8) | (((u16)(n) & 0xFF00) >> 8))

struct log_t {
    // u64 ts;

    // u32 pid_id;
    // u32 mnt_id;

    // u32 host_ppid;
    // u32 host_pid;

    // u32 ppid;
    u32 pid;
    u32 uid;

    // u32 event_id;

    char comm[TASK_COMM_LEN];
};

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

struct syscalls_enter_connect_args {
	unsigned long long unused;
	long syscall_nr;
	long fd;
	long usockaddr;
	long addrlen;
};

struct syscalls_enter_bind_args {
	unsigned long long unused;
	long syscall_nr;
	long fd;
	long usockaddr;
	long addrlen;
};

static inline int
ka_ea_log_submit(struct pt_regs *ctx) {
    u64 cur_pid = bpf_get_current_pid_tgid();
	u64 cur_uid = bpf_get_current_uid_gid();

    struct log_t *log;

    log = bpf_ringbuf_reserve((void *)__ka_ea_map(ka_ea_ringbuff_map), sizeof(*log), 0);
    if(!log) {
        return 0;
    }
	
    log->pid = cur_pid >> 32;
	log->uid = cur_uid >> 32;
    bpf_get_current_comm(log->comm, sizeof(log->comm));

    bpf_ringbuf_submit(log, 0);
    return 0;
}

static inline void
ka_ea_reset_rate(u32 uniq_id)
{
	struct rate_limit_key key = {};
	struct rate_limit_value value = {};

	key.pid_ns = task_get_pid_ns(NULL);
	key.mnt_ns = task_get_mnt_ns(NULL);
	key.uniq_id = uniq_id;

	bpf_map_update_elem((void *)__ka_ea_map(ka_ea_rate_limit_map), &key,
		&value, BPF_ANY);
}

static inline u64
ka_ea_update_rate(u32 uniq_id, struct rate_limit_value *vp_out)
{
	struct rate_limit_key key;
	struct rate_limit_value *vp, value;
	u64 curns = bpf_ktime_get_ns();

	key.pid_ns = task_get_pid_ns(NULL);
	key.mnt_ns = task_get_mnt_ns(NULL);
	key.uniq_id = uniq_id;

	vp = bpf_map_lookup_elem((void *)__ka_ea_map(ka_ea_rate_limit_map), &key);
	if (!vp || (vp->initns == 0)) {
		value.initns = curns;
		value.events = 1;
	} else {
		value.initns = vp->initns;
		value.events = vp->events + 1;
	}

	bpf_map_update_elem((void *)__ka_ea_map(ka_ea_rate_limit_map), &key,
		&value, BPF_ANY);

	vp_out->initns = value.initns;
	vp_out->events = value.events;
	return curns;
}

static inline bool
ka_ea_audit_task(void)
{
	struct process_filter_key key;
	struct process_filter_value *value;

	key.pid_ns = task_get_pid_ns(NULL);
	key.mnt_ns = task_get_mnt_ns(NULL);
	key.host_pid = task_get_host_pid();

	value = bpf_map_lookup_elem((void *)__ka_ea_map(ka_ea_process_filter_map), &key);
	return (value && value->inspect);
}

static inline u32
tp_sys_execve_read_path(struct syscalls_enter_execve_args *ctx)
{
	char buffer[MAX_FILENAME_LEN] = {};
	void *uptr = (void *)ctx->filename;

	if (bpf_probe_read_user(&buffer, sizeof(buffer) - 1, uptr) == 0) {
		return jenkins_hash(buffer, strnlen(buffer, MAX_FILENAME_LEN), 0);
	}

	return 0;
}

static inline u32
tp_sys_execveat_read_path(struct syscalls_enter_execveat_args *ctx)
{
	char buffer[MAX_FILENAME_LEN] = {};
	void *uptr = (void *)ctx->filename;

	if (bpf_probe_read_user(&buffer, sizeof(buffer) - 1, uptr) == 0) {
		return jenkins_hash(buffer, strnlen(buffer, MAX_FILENAME_LEN), 0);
	}

	return 0;
}

static inline u32
tp_sys_open_read_path(struct syscalls_enter_open_args *ctx)
{
	char buffer[MAX_FILENAME_LEN] = {};
	void *uptr = (void *)ctx->filename;

	if (bpf_probe_read_user(&buffer, sizeof(buffer) - 1, uptr) == 0) {
		return jenkins_hash(buffer, strnlen(buffer, MAX_FILENAME_LEN), 0);
	}

	return 0;
}

static inline u32
tp_sys_openat_read_path(struct syscalls_enter_openat_args *ctx)
{
	char buffer[MAX_FILENAME_LEN] = {};
	void *uptr = (void *)ctx->filename;

	if (bpf_probe_read_user(&buffer, sizeof(buffer) - 1, uptr) == 0) {
		return jenkins_hash(buffer, strnlen(buffer, MAX_FILENAME_LEN), 0);
	}

	return 0;
}

static inline void
tp_sys_connect_read_ipv4(struct syscalls_enter_connect_args *ctx, union v4addr *v4ip)
{
	struct sockaddr_in sockaddr;
	void *uptr = (void *)ctx->usockaddr;

	/* sanity check */
	if (!v4ip)
		return;
	if (ctx->addrlen != sizeof(struct sockaddr_in))
		return;

	if (bpf_probe_read_user(&sockaddr, ctx->addrlen, uptr) == 0) {
		v4ip->d1 = sockaddr.sin_addr.s_addr;
	}
}

static inline unsigned short
tp_sys_connect_read_port(struct syscalls_enter_connect_args *ctx)
{
	struct sockaddr_in sockaddr;
	void *uptr = (void *)ctx->usockaddr;

	/* sanity check */
	if (ctx->addrlen != sizeof(struct sockaddr_in))
		return 0;

	if (bpf_probe_read_user(&sockaddr, ctx->addrlen, uptr) == 0) {
		return ntohs(sockaddr.sin_port);
	}

	return 0;
}

static inline void
tp_sys_bind_read_ipv4(struct syscalls_enter_connect_args *ctx, union v4addr *v4ip)
{
	struct sockaddr_in sockaddr;
	void *uptr = (void *)ctx->usockaddr;

	/* sanity check */
	if (!v4ip)
		return;
	if (ctx->addrlen != sizeof(struct sockaddr_in))
		return;

	if (bpf_probe_read_user(&sockaddr, ctx->addrlen, uptr) == 0) {
		v4ip->d1 = sockaddr.sin_addr.s_addr;
	}
}

static inline unsigned short
tp_sys_bind_read_port(struct syscalls_enter_connect_args *ctx)
{
	struct sockaddr_in sockaddr;
	void *uptr = (void *)ctx->usockaddr;

	/* sanity check */
	if (ctx->addrlen != sizeof(struct sockaddr_in))
		return 0;

	if (bpf_probe_read_user(&sockaddr, ctx->addrlen, uptr) == 0) {
		return ntohs(sockaddr.sin_port);
	}

	return 0;
}

// sys_execve
#define __ka_ea_evt59_read_path(ctx) \
	tp_sys_execve_read_path(ctx)

// sys_execveat
#define __ka_ea_evt322_read_path(ctx)  \
	tp_sys_execveat_read_path(ctx)
#define __ka_ea_evt322_read_flags(ctx) \
	(int)(((struct syscalls_enter_execveat_args *)ctx)->flags)

// sys_open
#define __ka_ea_evt2_read_path(ctx)  \
	tp_sys_open_read_path(ctx)
#define __ka_ea_evt2_read_flags(ctx) \
	(int)(((struct syscalls_enter_open_args *)ctx)->flags)
#define __ka_ea_evt2_read_mode(ctx)  \
	(mode_t)(((struct syscalls_enter_open_args *)ctx)->mode)

// sys_openat
#define __ka_ea_evt257_read_path(ctx)  \
	tp_sys_openat_read_path(ctx)
#define __ka_ea_evt257_read_flags(ctx) \
	(int)(((struct syscalls_enter_openat_args *)ctx)->flags)
#define __ka_ea_evt257_read_mode(ctx)  \
	(mode_t)(((struct syscalls_enter_openat_args *)ctx)->mode)

// sys_connect
#define __ka_ea_evt42_read_ipv4(ctx, v) \
	tp_sys_connect_read_ipv4(ctx, v)
#define __ka_ea_evt42_read_port(ctx) \
	tp_sys_connect_read_port(ctx)

// sys_bind
#define __ka_ea_evt49_read_ipv4(ctx, v) \
	tp_sys_bind_read_ipv4(ctx, v)
#define __ka_ea_evt49_read_port(ctx) \
	tp_sys_bind_read_port(ctx)

#define __ka_ea_evt_log(c) \
	ka_ea_log_submit(c)

#define __ka_ea_rl_log(id, ev, ns, m) \
	do { \
		if (rlv.events >= ev) { \
			if ((curns - rlv.initns) <= ns) { \
				__ka_ea_evt_log(m); \
				ka_ea_reset_rate(id); \
			} else { \
				ka_ea_reset_rate(id); \
			} \
		} \
	} while(0)

#define __INIT_LOCAL_PATH(e) \
	u32 path;                \
	path = __ka_ea_evt## e## _read_path(ctx);

#define __INIT_LOCAL_MODE(e) \
	umode_t mode;            \
	mode = __ka_ea_evt## e## _read_mode(ctx);

#define __INIT_LOCAL_FLAGS(e) \
	int flags;                \
	flags = __ka_ea_evt## e## _read_flags(ctx);

#define __INIT_LOCAL_PORT(e) \
	unsigned short port;     \
	port = __ka_ea_evt## e## _read_port(ctx);

#define __INIT_LOCAL_IPV4(e) \
	union v4addr v4ip = {};  \
	__ka_ea_evt## e## _read_ipv4(ctx, &v4ip);

#define __INIT_LOCAL_RATE(id) \
	struct rate_limit_value rlv; \
	u64 curns = ka_ea_update_rate(id, &rlv);

char LICENSE[] SEC("license") = "GPL";

#endif /* __CODEGEN_BPF_H */
