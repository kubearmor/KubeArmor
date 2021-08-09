#ifndef __MAPS_H
#define __MAPS_H

#include "vmlinux.h"

#define PATTERN_MAX_LEN 127

struct pattern_key {
	char pattern[PATTERN_MAX_LEN];
};

struct pattern_value {
	__u32 pattern_id;
};

struct process_spec_key {
	__u32 pid_ns;
	__u32 mnt_ns;
	__u32 pattern_id;
};

struct process_spec_value {
	__u32 pattern_id;
};

#endif /* __MAPS_H */
