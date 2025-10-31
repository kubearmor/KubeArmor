
enum pkt_direction
{
    DIR_INGRESS = 0,
    DIR_EGRESS = 1
};

struct rule_map_key
{
    __u8 direction;
};
struct rule_map_val
{
    __u64 duration;
    __u64 pkt_len_bytes;
    __u64 pkt_count;
};
struct traffic_info
{
    __u8 log_flag;
    __u64 first_packet_ts;
    __u64 total_bytes;
    __u64 no_of_pkt;
};

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, struct traffic_info);
} traffic_info_map SEC(".maps");
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, struct rule_map_val);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} kubearmor_network_quota_rules SEC(".maps");
