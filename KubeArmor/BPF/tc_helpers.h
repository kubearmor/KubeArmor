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
struct traffic_info
{
    __u64 first_packet_ts;
    __u64 total_bytes;
    __u64 no_of_pkt;
    __u8 log_flag;
} traffic_info;

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
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, rule_key);
    __type(value, traffic_info);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} traffic_info_map SEC(".maps");
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 2);
    __type(key, rule_key);
    __type(value, rule_val);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} kubearmor_network_quota_rules SEC(".maps");

static __always_inline int handle_pkt(struct __sk_buff *skb, __u8 direction)
{
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;

    // Boundary check for the Ethernet header.
    struct ethhdr *eth = data;
    if ((void *)eth + sizeof(*eth) > data_end)
    {
        return TC_ACT_OK;
    }

    if (eth->h_proto != __builtin_bswap16(ETH_P_IP) && eth->h_proto != __builtin_bswap16(ETH_P_IPV6))
    {
        return TC_ACT_OK;
    }
    struct iphdr *ip_header = data + sizeof(*eth);
    if ((void *)ip_header + sizeof(*ip_header) > data_end)
    {
        return TC_ACT_OK;
    }

    struct rule_map_key rkey = {};
    rkey.direction = direction;
    struct traffic_info *info = bpf_map_lookup_elem(&traffic_info_map, &rkey);
    struct rule_map_val *rval = bpf_map_lookup_elem(&kubearmor_network_quota_rules, &rkey);
    if (rval)
    {
        __sync_fetch_and_add(&info->no_of_pkt, 1);

        if (info->first_packet_ts == -1)
        {
            info->first_packet_ts = bpf_ktime_get_ns();
        }
        else
        {
            u64 current_ts = bpf_ktime_get_ns();
            if ((current_ts - info->first_packet_ts) > rval->duration)
            {
                info->first_packet_ts = current_ts;
                info->total_bytes = 0;
                info->log_flag = 0;
                info->no_of_pkt = 0;
            }
            else
            {
                __sync_fetch_and_add(&info->total_bytes, skb->len);
            }
            if ((rval->pkt_len_bytes > 0 && info->total_bytes > rval->pkt_len_bytes) || (rval->pkt_count > 0 && info->no_of_pkt > rval->pkt_count))
            {
                if (info->log_flag == 0)
                {
                    info->log_flag = 1;
                    sys_context_t context = {};
                    context.ts = bpf_ktime_get_ns();
                    context.event_id = _NET_LIMIT;

                    // piggy back direction info in exec_id field
                    context.exec_id = direction;
                    set_buffer_offset(DATA_BUF_TYPE, sizeof(sys_context_t));
                    bufs_t *bufs_p = get_buffer(DATA_BUF_TYPE);
                    if (bufs_p == NULL)
                        return 0;
                    save_context_to_buffer(bufs_p, (void *)&context);
                    events_perf_submit_skb(skb, DATA_BUF_TYPE);
                }
            }
        }
    }
    else
    {
        // if there are no rules or the rules have been deleted
        info->first_packet_ts = -1;
        info->total_bytes = 0;
        info->log_flag = 0;
        info->no_of_pkt = 0;
    }

    return TC_ACT_OK
}
