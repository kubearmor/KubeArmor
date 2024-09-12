//go:build ignore
#include "shared.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define ETH_P_IP 0x0800 /* Internet Protocol packet     */
#define ETH_HLEN 14
#define PACKET_HOST 0
#define MAX_BUF_SIZE 300
#define DNS_TYPE_A 1 // https://datatracker.ietf.org/doc/html/rfc1035#section-3.2.2
#define MAX_DNS_NAME 255

struct event_t {
	__u32 netns;
	__u32 saddr_v4;
	__u32 daddr_v4;
	__u32 af; 
	__u16 sport;
	__u16 dport;
    __u32 dns_length;
    __u64 pid;
    __u64 ppid;
    __u8 task[TASK_COMM_LEN]; 
    __u16 payload[MAX_BUF_SIZE];
};


struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} socket_events SEC(".maps");

# define DNS_OFF (ETH_HLEN + sizeof(struct iphdr) + sizeof(struct udphdr))

static volatile const __u32 current_netns ;

SEC("socket")
int simple_socket_handler(struct __sk_buff *skb){   

    __u32 h_proto;
 	__u8 protoc;
    __u8 name[MAX_DNS_NAME];
    __u16 sport, dport, l4_off, dns_off, id;
    //Check if the protocol is Ipv4
    bpf_skb_load_bytes(skb, offsetof(struct ethhdr, h_proto), &h_proto, sizeof(h_proto));
    
    if (bpf_ntohs(h_proto) == ETH_P_IP){    
    bpf_skb_load_bytes(skb, ETH_HLEN + offsetof(struct iphdr, protocol),&protoc, sizeof(protoc));
    
        if (protoc == IPPROTO_UDP){
            __u8 ihl_byte;
            bpf_skb_load_bytes(skb, ETH_HLEN, &ihl_byte,sizeof(ihl_byte));
            struct iphdr *iph = (struct iphdr *)&ihl_byte;
            __u8 ip_header_len = iph->ihl * 4;
            l4_off = ETH_HLEN + ip_header_len;
            
            int off = l4_off;
            
            if (skb->pkt_type == PACKET_HOST)
                off += offsetof(struct udphdr, dest);
            else
                off += offsetof(struct udphdr, source);
            
            bpf_skb_load_bytes(skb, l4_off + offsetof(struct udphdr, dest),&dport, sizeof(dport));
            bpf_skb_load_bytes(skb, l4_off + offsetof(struct udphdr, source),&sport, sizeof(sport));
            
            if (bpf_ntohs(sport) == 53 || bpf_ntohs(dport) == 53 || bpf_ntohs(sport) == 5353 || bpf_ntohs(dport) == 5353 ) {
                bpf_printk("currentns is  %u",current_netns);
                struct sockets_key socket_key = {0,0,0,0};
                long err;
                __u8 packet_present = 0;
                                
                __u32 port; 
                err = bpf_skb_load_bytes(skb, off, &port , sizeof(port));
                if (err < 0)
                    return 0;

                struct event_t *event;
                event = bpf_ringbuf_reserve(&socket_events, sizeof(struct event_t), 0);    
                if (!event) {
                    return 0; 
                }

                __u16 udp_total_length;
                bpf_skb_load_bytes(skb, l4_off + offsetof(struct udphdr, len), &udp_total_length, sizeof(udp_total_length));

                __u32 dns_length = bpf_ntohs(udp_total_length) - sizeof(struct udphdr);
                event->dns_length = bpf_ntohs(dns_length);

                u32 len_payload = 0;
                for (len_payload = 0; len_payload < 328; len_payload++) {
                    if (len_payload == dns_length-1){
                        break;
                    }
                }
                len_payload = len_payload+1;
                
                err = bpf_skb_load_bytes(skb, DNS_OFF, event->payload, len_payload);
                if (err != 0) {
                    bpf_ringbuf_discard(event, 0);
                    return 0; 
                }

                bpf_skb_load_bytes(skb, ETH_HLEN + offsetof(struct iphdr, saddr),&event->saddr_v4, sizeof(event->saddr_v4));
                bpf_skb_load_bytes(skb, ETH_HLEN + offsetof(struct iphdr, daddr),&event->daddr_v4, sizeof(event->daddr_v4));
                
                socket_key.netns = current_netns;
                socket_key.saddr = bpf_ntohs(event->saddr_v4);
                socket_key.daddr = bpf_ntohs(event->daddr_v4);
                socket_key.sport = bpf_ntohs(sport);
                socket_key.dport = bpf_ntohs(dport); 
                
                struct socket_value *skb_val;
                skb_val  = bpf_map_lookup_elem(&dns_shared_map, &socket_key);
                if (skb_val != NULL){
                    event->pid = skb_val->uid_gid;
                    event->ppid = skb_val->pid_tgid;
                    packet_present = (uint32_t)1;
                }
                
                event->sport = bpf_ntohs(sport);
                event->dport = bpf_ntohs(dport); 
                event->netns = current_netns;
                                
                bpf_ringbuf_submit(event, 0);
            }
        }
    }
    return 0;
}
