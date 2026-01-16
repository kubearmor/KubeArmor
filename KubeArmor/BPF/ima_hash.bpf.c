// +build ignore
/* SPDX-License-Identifier: GPL-2.0    */
/* Copyright 2026 Authors of KubeArmor */

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "ima_hash.h"
#include "visibility.h"
#include "kubearmor_config.h"


SEC("lsm.s/bprm_check_security")
int BPF_PROG(ima_bprm_check_security, struct linux_binprm *bprm) {

    if (drop_syscall(_IMA_PROBE))
        return 0;

    u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    void *hash_exists = bpf_map_lookup_elem(&kubearmor_ima_hash_map, &pid);
    if (hash_exists)
        return 0;
    
    ima_hash_t hash = {0};
    u32 algo = bpf_ima_file_hash(bprm->file, hash.digest, sizeof(hash.digest));

    if (algo > 0){
        bpf_map_update_elem(&kubearmor_ima_hash_map, &pid, &hash, BPF_ANY);
    }

    return 0;
}

/*
SEC("lsm.s/file_open")
int BPF_PROG(ima_file_open, struct file *file) {
    
    // bpf_ima_file_hash() leading to performance bottleneck for the system,
    // it appears as a high latency operation and due to frequency of the file events
    // every file operation becomes a potential bottleneck
    

    // ima_hash_t hash = {0};
    // u32 algo = bpf_ima_file_hash(file, hash.digest, sizeof(hash.digest));

    // u32 pid = bpf_get_current_pid_tgid() >> 32;
    // pid |= FILE_HASH_MASK;
    // if (algo > 0){
    //     bpf_map_update_elem(&kubearmor_ima_hash_map, &pid, &hash, BPF_ANY);
    // }
    return 0;
}
*/

char LICENSE[] SEC("license") = "Dual BSD/GPL";