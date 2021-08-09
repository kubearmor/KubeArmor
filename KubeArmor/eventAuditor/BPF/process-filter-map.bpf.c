#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#include "maps.bpf.h"

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct process_filter_key);
	__type(value, struct process_filter_value);
	__uint(max_entries, -1U);
} ka_ea_process_filter_map SEC(".maps");

char LICENSE[] SEC("license") = "Dual BSD/GPL";
