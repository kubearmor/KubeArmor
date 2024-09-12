//go:build ignore
#include "shared.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define AF_INET 2
#define ETH_P_IP 0x0800

static __always_inline u32 get_pid_ns_id(struct nsproxy *ns)
{
    // Use BPF_CORE_READ to safely access kernel space memory
    struct pid_namespace *pidns = BPF_CORE_READ(ns, pid_ns_for_children);
    return BPF_CORE_READ(pidns, ns.inum);
}

static __always_inline u32 get_task_pid_ns_id(struct task_struct *task)
{
    return get_pid_ns_id(BPF_CORE_READ(task,nsproxy));
}

static __always_inline u32 get_mnt_ns_id(struct nsproxy *ns)
{
    // Use BPF_CORE_READ to safely access kernel space memory
    struct mnt_namespace *mntns = BPF_CORE_READ(ns, mnt_ns);
    return BPF_CORE_READ(mntns, ns.inum);
}

static __always_inline u32 get_task_mnt_ns_id(struct task_struct *task)
{
    return get_mnt_ns_id(BPF_CORE_READ(task,nsproxy));
}

struct outer_key {
  u32 pid_ns;
  u32 mnt_ns;
};

struct pid_maps{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __uint(key_size, sizeof(struct outer_key));
    __uint(value_size, sizeof(u32));  
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} ;

struct pid_maps dns_container_maps SEC(".maps");

struct socket_print_key {
	__u32 remote_port;	
	__u32 local_port;	
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(struct socket_print_key));
	__uint(value_size, sizeof(struct __sk_buff));
    __uint(max_entries, 128);
} socket_print SEC(".maps");

#define ETH_P_IP	0x0800

SEC("kprobe/udp_sendmsg")
int BPF_KPROBE(ig_udp_sendmsg, struct sock *sk , struct msghdr *msg ,size_t len)
{
    struct outer_key key;
    u32 *value;

    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    
    key.pid_ns = get_task_pid_ns_id(t);
    key.mnt_ns = get_task_mnt_ns_id(t);
    
    value = bpf_map_lookup_elem(&dns_container_maps, &key);
    if (!value) {
        return 0;
    }
    bpf_printk("Kprobe container found pid %u and mnt %u", key.pid_ns, key.mnt_ns);

    struct sock_common skcom; 

    bpf_probe_read(&skcom, sizeof(skcom), &sk->__sk_common);

    u16 sport = skcom.skc_num;
    u16 dport = skcom.skc_dport;

    // Processing only packets on port 53.
    // 13568 = ntohs(53);
    if (sport == 13568 || dport == 13568) {
        u32 saddr = skcom.skc_rcv_saddr;
        u32 daddr = skcom.skc_daddr;
        struct sockets_key socket_key = {0};
        BPF_CORE_READ_INTO(&socket_key.netns, sk, __sk_common.skc_net.net,ns.inum);
        socket_key.sport = sport;
        socket_key.dport = bpf_ntohs(dport);
        socket_key.saddr = bpf_ntohs(saddr);
        socket_key.daddr = bpf_ntohs(daddr);
        
        struct socket_value socket_value;
        
        socket_value.pid_tgid = bpf_get_current_pid_tgid();
    	socket_value.uid_gid = bpf_get_current_uid_gid();
        bpf_get_current_comm(&socket_value.task, sizeof(socket_value.task));        

        bpf_map_update_elem(&dns_shared_map, &socket_key, &socket_value, BPF_ANY);

    }    

    return 0;
}
