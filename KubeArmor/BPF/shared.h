/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2021 Authors of KubeArmor */

#ifndef __SHARED_H
#define __SHARED_H

#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 42 // verifier limit for match() unrolling
#define MAX_PATTERN_LEN 7   // verifier limit for match() unrolling

#define get_dynamic_array(entry, field) \
	((void *)entry + (entry->__data_loc_##field & 0xffff))

#endif /* __SHARED_H */
