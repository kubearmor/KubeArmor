/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2024 Authors of KubeArmor */
/* This module contains the common structures shared by lsm and system monitor*/
# include "throttling.h"
#ifndef __COMMON_H
#define __COMMON_H
#define MAX_ENTRIES 10240
#define MAX_ARGUMENT_SIZE 256
#define MAX_STR_ARR_ELEM 20

// arguments matching 

// values stored for argument map
struct argVal{
  char argsArray[80];
};
struct cmd_args_key {
  u64 tgid ;
  u64 ind;
};

struct {
 __uint(type, BPF_MAP_TYPE_LRU_HASH);
 __uint(max_entries, MAX_ENTRIES);
 __type(key, struct cmd_args_key);
 __type(value, struct argVal);
 __uint(pinning, LIBBPF_PIN_BY_NAME);
} args_store SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);  // Adjust max_entries based on expected usage
    __type(key, u32);
    __type(value, struct argVal);  // Store the args in this struct
} cmd_args_buf SEC(".maps");

#endif /* __COMMON_H */