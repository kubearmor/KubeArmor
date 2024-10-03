/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2024 Authors of KubeArmor */
/* This module contains the common structures shared by lsm and system monitor*/
# include "throttling.h"
#ifndef __COMMON_H
#define __COMMON_H
#define MAX_ENTRIES 10240
 #define MAX_ARGUMENT_SIZE 256

// arguments matching 

// values stored for argument map
struct argVal{
  char argsArray[5][25];
};


struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);  // Only one entry to store the count
    __type(key, int);
    __type(value, int);
} index_map SEC(".maps");

struct {
 __uint(type, BPF_MAP_TYPE_LRU_HASH);
 __uint(max_entries, MAX_ENTRIES);
 __type(key, unsigned int);
 __type(value, struct argVal);
 __uint(pinning, LIBBPF_PIN_BY_NAME);
} args_store SEC(".maps");

#endif /* __COMMON_H */