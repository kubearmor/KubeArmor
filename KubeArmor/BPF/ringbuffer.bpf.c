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

struct bpf_map_def SEC("maps") events = {
    .type = BPF_MAP_TYPE_RINGBUF,
    .max_entries = 1 << 10,
};

long flag = 0;

SEC("tracepoint/syscalls/sys_enter_execve")
int sys_enter_execve(struct pt_regs *ctx) {
    struct log *log;
    __u64 id = bpf_get_current_pid_tgid();
    __u32 tgid = id >> 32;

    log = bpf_ringbuf_reserve(&events, sizeof(int), flag);
    if (!log) {
        return 0;
    }

    log->PID = tgid;

    bpf_ringbuf_submit(log, flag);
    return 0;
}