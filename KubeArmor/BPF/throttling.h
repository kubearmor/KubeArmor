/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2024 Authors of KubeArmor */

#ifndef __THROTTLING_H
#define __THROTTLING_H

struct outer_key {
  u32 pid_ns;
  u32 mnt_ns;
};
// Throttling 
struct alert_throttle_state {
  u64 first_event_timestamp;
  u64 event_count;
  u64 throttle;
};

struct alert {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 256);
  __uint(key_size, sizeof(struct outer_key));
  __uint(value_size, sizeof(struct alert_throttle_state));
  __uint(pinning, LIBBPF_PIN_BY_NAME);
};

struct alert kubearmor_alert_throttle SEC(".maps");

#endif /* __THROTTLING_H */