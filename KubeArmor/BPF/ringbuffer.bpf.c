#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#ifdef asm_inline
#undef asm_inline
#define asm_inline asm
#endif

struct log{
    int PID;
    //int UID;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 10);
} ringbuff_map SEC(".maps");

long flag = 0;

SEC("tp/syscalls/sys_enter_execve")
int syscall__sys_execve(struct trace_event_raw_sched_process_exec *ctx) {
    struct log *log;
    __u64 id = bpf_get_current_pid_tgid();
    __u32 tgid = id >> 32;

    log = bpf_map_lookup_elem(&ringbuff_map, 0);
    if (!log) {
        bpf_printk("Map not updated\n");
        return 0;
    }
    log = bpf_ringbuf_reserve(&ringbuff_map, sizeof(int), flag);
    if (!log) {
        return 0;
    }

    log->PID = tgid;

    bpf_ringbuf_submit(log, flag);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
