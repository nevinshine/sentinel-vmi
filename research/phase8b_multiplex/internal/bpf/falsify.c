//go:build ignore

#define __TARGET_ARCH_x86
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#define AF_INET 2

char __license[] SEC("license") = "Dual MIT/GPL";

struct process_context {
    __u64 subject_hash;
    __u64 lineage_hash;
};

struct behavior_context {
    __u64 behavior_id;
    __u64 pid_tgid;
};

struct behavior_tag {
    __u64 computed_behavior_id;
    __u64 subject_hash;
    __u64 timestamp_ns;
    
    // Tracking state for validation
    __u64 last_true_behavior_id;
    __u32 socket_reuse_count;
    __u32 request_index;
};

struct validation_event {
    __u64 computed_behavior_id;
    __u64 true_behavior_id;
    __u64 socket_cookie;
    __u32 request_index;
    __u32 socket_reuse_count;
};

// Force clang to keep this type in BTF info
struct validation_event __force_btf_validation_event;

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
    __type(key, int);
    __type(value, struct behavior_tag);
} socket_tags SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} validation_events SEC(".maps");


// HOOK 1: cgroup/connect4 (Phase 8A tagger)
SEC("cgroup/connect4")
int cgroup_connect4(struct bpf_sock_addr *ctx) {
    struct bpf_sock *sk = ctx->sk;
    if (!sk) return 1;

    __u64 tgid = bpf_get_current_pid_tgid() >> 32;
    
    struct behavior_context *bctx = bpf_map_lookup_elem(&behavior_map, &tgid);
    if (!bctx) {
        return 1;
    }

    struct process_context *pctx = bpf_map_lookup_elem(&process_map, &tgid);

    // Tag the socket AT CONNECT TIME ONLY. This is what we are falsifying!
    struct behavior_tag *tag = bpf_sk_storage_get(&socket_tags, sk, 0, BPF_SK_STORAGE_GET_F_CREATE);
    if (tag) {
        tag->computed_behavior_id = bctx->behavior_id;
        tag->timestamp_ns = bpf_ktime_get_ns();
        if (pctx) {
            tag->subject_hash = pctx->subject_hash;
        } else {
            tag->subject_hash = 0;
        }
        tag->socket_reuse_count = 0;
        tag->request_index = 0;
        tag->last_true_behavior_id = 0;
    }

    return 1;
}

// HOOK 2: tc/egress (Validation Engine)
SEC("tc")
int tc_egress(struct __sk_buff *skb) {
    struct bpf_sock *sk = skb->sk;
    if (!sk) return 0; // TC_ACT_OK

    struct bpf_sock *full_sk = bpf_sk_fullsock(sk);
    if (!full_sk) return 0;

    if (full_sk->protocol != IPPROTO_TCP) {
        return 0;
    }

    // Try to recover the socket storage
    struct behavior_tag *tag = bpf_sk_storage_get(&socket_tags, sk, 0, 0);
    if (!tag) {
        bpf_printk("TC: Untagged socket");
        return 0; // Untagged socket
    }

    // Load first 200 bytes of the packet to search for Ground Truth "X-Bid: "
    char payload[200];
    int ret = bpf_skb_load_bytes(skb, 0, payload, sizeof(payload));
    if (ret < 0) {
        bpf_printk("TC: bpf_skb_load_bytes failed");
        return 0;
    }

    int found = 0;
    #pragma unroll
    for (int i = 0; i < 150; i++) {
        if (payload[i] == 'X' && payload[i+1] == '-' && payload[i+2] == 'B' && 
            payload[i+3] == 'i' && payload[i+4] == 'd' && payload[i+5] == ':' && payload[i+6] == ' ') {
            
            __u64 true_id = 0;
            #pragma unroll
            for (int j = 0; j < 8; j++) {
                char c = payload[i+7+j];
                if (c >= '0' && c <= '9') true_id = (true_id << 4) | (c - '0');
                else if (c >= 'A' && c <= 'F') true_id = (true_id << 4) | (c - 'A' + 10);
                else if (c >= 'a' && c <= 'f') true_id = (true_id << 4) | (c - 'a' + 10);
            }

            // We found a new request on this socket!
            // Let's emit the validation event if it's the start of a request.
            if (true_id != 0 && tag->last_true_behavior_id != true_id) {
                found = 1;
                if (tag->last_true_behavior_id != 0) {
                    tag->socket_reuse_count++;
                }
                tag->request_index++;
                tag->last_true_behavior_id = true_id;

                struct validation_event event = {};
                event.computed_behavior_id = tag->computed_behavior_id;
                event.true_behavior_id = true_id;
                event.socket_cookie = bpf_get_socket_cookie(skb);
                event.request_index = tag->request_index;
                event.socket_reuse_count = tag->socket_reuse_count;

                bpf_perf_event_output(skb, &validation_events, BPF_F_CURRENT_CPU, &event, sizeof(event));
                bpf_printk("TC: Emitted event! Computed: %X, True: %X", tag->computed_behavior_id, true_id);
            }
            break;
        }
    }
    
    if (found == 0) {
        bpf_printk("TC: X-Bid not found in 200 bytes");
    }

    return 0; // TC_ACT_OK
}
