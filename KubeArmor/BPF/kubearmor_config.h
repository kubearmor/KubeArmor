#ifndef _KUBEARMOR_CONFIG_H
#define _KUBEARMOR_CONFIG_H
// == Config ==

enum
{
    _MONITOR_HOST = 0,
    _MONITOR_CONTAINER = 1,
    _ENFORCER_BPFLSM = 2,
    _ALERT_THROTTLING = 3,
    _MAX_ALERT_PER_SEC = 4,
    _THROTTLE_SEC = 5,
};

struct kaconfig
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, u32);
    __uint(max_entries, 16);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
}kubearmor_config SEC(".maps");

static __always_inline u32 get_kubearmor_config(u32 config)
{
    u32 *value = bpf_map_lookup_elem(&kubearmor_config, &config);
    if (!value)
    {
        return 0;
    }

    return *value;
}

#endif // _KUBEARMOR_CONFIG_H