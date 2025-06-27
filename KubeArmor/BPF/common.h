/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2024 Authors of KubeArmor */
/* This module contains the common structures shared by lsm and system monitor*/
# include "throttling.h"
#ifndef __COMMON_H
#define __COMMON_H
#define MAX_ENTRIES 10240
#define MAX_ARGUMENT_SIZE 256

//struct for argument string
struct argVal{
  char argsArray[MAX_ARGUMENT_SIZE];
};

// key for kubearmor_args_store map (tgid + argument index)
struct cmd_args_key {
  u64 tgid ;
  u64 ind;
};

// map to store arguments for a process 
struct {
 __uint(type, BPF_MAP_TYPE_LRU_HASH);
 __uint(max_entries, MAX_ENTRIES);
 __type(key, struct cmd_args_key);
 __type(value, struct argVal);
 __uint(pinning, LIBBPF_PIN_BY_NAME);
} kubearmor_args_store SEC(".maps");


// map to store argument string -- created to avoid memory overflow in verifier
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);  
    __type(key, u32);
    __type(value, struct argVal);  // Store the args in this struct
} cmd_args_buf SEC(".maps");

#endif /* __COMMON_H */