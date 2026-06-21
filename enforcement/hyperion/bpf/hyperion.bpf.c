// +build ignore

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct flow_key {
    __u32 dst_ip;
    __u16 dst_port;
};

struct block_entry {
    __u64 expires_ns;
    __u32 risk_score;
    __u32 reserved;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct flow_key);
    __type(value, struct block_entry);
    __uint(max_entries, 16384);
} blocked_flows SEC(".maps");

SEC("xdp")
int xdp_enforce(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)ip + sizeof(struct iphdr) > data_end)
        return XDP_PASS;

    if (ip->ihl < 5 || ip->ihl > 15)
        return XDP_PASS;

    struct flow_key key_dst = {};
    key_dst.dst_ip = ip->daddr; 
    
    struct flow_key key_src = {};
    key_src.dst_ip = ip->saddr;

    unsigned int ip_hdr_len = ip->ihl * 4;
    ip_hdr_len &= 0x3f;

    void *l4_hdr = (void *)ip + ip_hdr_len;

    if (ip->protocol == IPPROTO_TCP) {
        if (l4_hdr + sizeof(struct tcphdr) > data_end)
            return XDP_PASS;
        struct tcphdr *tcp = (struct tcphdr *)l4_hdr;
        key_dst.dst_port = tcp->dest; 
        key_src.dst_port = tcp->source;
    } else if (ip->protocol == IPPROTO_UDP) {
        if (l4_hdr + sizeof(struct udphdr) > data_end)
            return XDP_PASS;
        struct udphdr *udp = (struct udphdr *)l4_hdr;
        key_dst.dst_port = udp->dest; 
        key_src.dst_port = udp->source;
    } else {
        return XDP_PASS; 
    }

    // Check if destination is blocked (e.g. packet from VM entering veth ingress)
    struct block_entry *entry = bpf_map_lookup_elem(&blocked_flows, &key_dst);
    if (!entry) {
        // Check if source is blocked (e.g. return packet from internet entering physical NIC ingress)
        entry = bpf_map_lookup_elem(&blocked_flows, &key_src);
    }
    if (entry) {
        // If an entry is found, we drop the packet.
        // In Release builds, we strictly rely on the userspace daemon to reconcile expired flows.
        // In Instrumented builds, we can perform passive validation.
#ifdef INSTRUMENTATION_ENABLED
        __u64 now = bpf_ktime_get_ns();
        if (now > entry->expires_ns) {
            // Expired, let it pass
            return XDP_PASS;
        }
#endif
        
        return XDP_DROP;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
