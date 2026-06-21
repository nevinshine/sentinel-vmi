//go:build ignore

#define __TARGET_ARCH_x86
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#define AF_INET 2
#define AF_INET6 10

char __license[] SEC("license") = "Dual MIT/GPL";

// 1. Process Context (Task Storage or Hash Map)
// For simplicity in Phase 8A, we use a hash map keyed by pid_tgid since bpf_task_storage 
// requires specific kernel configurations and BPF_MAP_TYPE_TASK_STORAGE.
struct process_context {
    __u64 subject_hash;
    __u64 lineage_hash;
};

// 2. Behavior Context (Map)
// 1:1 mapping against pid_tgid for Phase 8A
struct behavior_context {
    __u64 behavior_id;
    __u64 pid_tgid;
};

// 3. Socket Context (Socket Local Storage)
struct behavior_tag {
    __u64 behavior_id;
    __u64 subject_hash;
    __u64 timestamp_ns;
};

// 4. Flow Attribution (Hash Map)
struct flow_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  protocol;
};

struct flow_attribution {
    __u64 behavior_id;
    __u64 first_seen_ns;
    __u64 packet_count;
};

// MAPS

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u64); // pid_tgid
    __type(value, struct process_context);
} process_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u64); // pid_tgid
    __type(value, struct behavior_context);
} behavior_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_SK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int); // Socket FD
    __type(value, struct behavior_tag);
} socket_tags SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65535);
    __type(key, struct flow_key);
    __type(value, struct flow_attribution);
} flow_map SEC(".maps");

// HOOK 1: sys_enter_connect (ferry context into socket)
SEC("tracepoint/syscalls/sys_enter_connect")
int tracepoint__syscalls__sys_enter_connect(struct trace_event_raw_sys_enter *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    
    // In Phase 8A, we assume userspace pre-populates behavior_map for the pid_tgid.
    // Let's retrieve the behavior context.
    struct behavior_context *bctx = bpf_map_lookup_elem(&behavior_map, &pid_tgid);
    if (!bctx) {
        return 0; // No behavior tracked for this process
    }

    struct process_context *pctx = bpf_map_lookup_elem(&process_map, &pid_tgid);

    // Get the socket file descriptor from connect() arguments
    // int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
    int sockfd = ctx->args[0];

    // Note: tracepoint sys_enter gives us the FD, but bpf_sk_storage_get requires a `struct sock *` or `struct bpf_sock *`!
    // sys_enter tracepoints DO NOT have access to the `struct sock *`.
    // We MUST use kprobe/tcp_connect or fentry/tcp_connect to get the `struct sock *`!
    return 0;
}

// HOOK 1b: cgroup/connect4
// This gives us direct access to `struct bpf_sock_addr *ctx`
SEC("cgroup/connect4")
int cgroup_connect4(struct bpf_sock_addr *ctx) {
    struct bpf_sock *sk = ctx->sk;
    if (!sk) return 1; // return 1 to allow connect

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    
    struct behavior_context *bctx = bpf_map_lookup_elem(&behavior_map, &pid_tgid);
    if (!bctx) {
        return 1;
    }

    struct process_context *pctx = bpf_map_lookup_elem(&process_map, &pid_tgid);

    // Get or create socket local storage
    struct behavior_tag *tag = bpf_sk_storage_get(&socket_tags, sk, 0, BPF_SK_STORAGE_GET_F_CREATE);
    if (tag) {
        tag->behavior_id = bctx->behavior_id;
        tag->timestamp_ns = bpf_ktime_get_ns();
        if (pctx) {
            tag->subject_hash = pctx->subject_hash;
        } else {
            tag->subject_hash = 0;
        }
    }

    return 1;
}

// HOOK 2: cgroup_skb/egress (recover context from socket and output to flow_attribution)
SEC("cgroup_skb/egress")
int egress__packet_capture(struct __sk_buff *skb) {
    struct bpf_sock *sk = skb->sk;
    if (!sk) return 1;

    struct bpf_sock *full_sk = bpf_sk_fullsock(sk);
    if (!full_sk) return 1;

    // Only process TCP
    if (full_sk->protocol != IPPROTO_TCP) {
        return 1;
    }

    // Try to recover the behavior tag from the socket
    struct behavior_tag *tag = bpf_sk_storage_get(&socket_tags, sk, 0, 0);
    if (!tag) {
        return 1; // No behavior tag
    }

    // Extract 5-tuple from full socket
    struct flow_key key = {};
    key.src_ip = full_sk->src_ip4;
    key.dst_ip = full_sk->dst_ip4;
    key.src_port = full_sk->src_port;
    key.dst_port = bpf_ntohs(full_sk->dst_port);
    key.protocol = IPPROTO_TCP;

    // Update flow_attribution
    struct flow_attribution *flow = bpf_map_lookup_elem(&flow_map, &key);
    if (flow) {
        __sync_fetch_and_add(&flow->packet_count, 1);
    } else {
        struct flow_attribution new_flow = {};
        new_flow.behavior_id = tag->behavior_id;
        new_flow.first_seen_ns = bpf_ktime_get_ns();
        new_flow.packet_count = 1;
        bpf_map_update_elem(&flow_map, &key, &new_flow, BPF_ANY);
    }

    return 1; // Allow packet
}
