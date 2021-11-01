#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#ifdef asm_inline
#undef asm_inline
#define asm_inline asm
#endif

#define TASK_COMM_LEN 16

struct log_t{
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

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24 );
} ka_ea_ringbuff_map SEC(".maps");

long flag = 0;

SEC("tp/sched/sched_process_exec")
int syscall__sys_execve(struct pt_regs *ctx) {
    u64 cur_pid = bpf_get_current_pid_tgid();
    u64 cur_uid = bpf_get_current_uid_gid();
    struct log_t *log;
   
    log = bpf_ringbuf_reserve(&ka_ea_ringbuff_map, sizeof(*log), 0);
    if(!log) {
        return 0;
    }
    log->pid = cur_pid >> 32;
    log->uid = cur_uid >> 32;
    bpf_get_current_comm(log->comm, sizeof(log->comm));

    bpf_ringbuf_submit(log, flag);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
