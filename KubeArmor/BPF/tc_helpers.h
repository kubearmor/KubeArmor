u64 _first_packet_ts_ingress = -1;
u64 _first_packet_ts_egress = -1;
u64 _total_bytes_egress = 0;
u64 _total_bytes_ingress = 0;
u8 _egress_log_flag = 0;
u8 _ingress_log_flag = 0;
u64 _no_of_pkt_ingress = 0;
u64 _no_of_pkt_egress = 0;

enum pkt_direction
{
    DIR_INGRESS = 111,
    DIR_EGRESS = 112,
};

struct rule_map_key
{
    __u8 direction;
} rule_key;
struct rule_map_val
{
    __u64 duration;
    __u64 pkt_len_bytes;
    __u64 pkt_count;

} rule_val;

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 2);
    __type(key, rule_key);
    __type(value, rule_val);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} kubearmor_network_quota_rules SEC(".maps");
