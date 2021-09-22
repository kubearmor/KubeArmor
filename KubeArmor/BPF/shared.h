/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2021 Authors of KubeArmor */

#ifndef __SHARED_H
#define __SHARED_H

#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 256
#define PATTERN_MAX_LEN TASK_COMM_LEN

#define get_dynamic_array(entry, field) \
	((void *)entry + (entry->__data_loc_##field & 0xffff))

struct task_context {
	unsigned int pid;
	unsigned int tid;
	unsigned int pid_ns;
	unsigned int mnt_ns;
	char comm[TASK_COMM_LEN];
	char filename[MAX_FILENAME_LEN];
};

#endif /* __SHARED_H */
