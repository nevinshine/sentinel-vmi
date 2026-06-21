//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char __license[] SEC("license") = "Dual MIT/GPL";

struct request_event {
    __u64 request_ptr;
    __u64 context_ptr;
    __u64 timestamp_ns;
    __u32 pid;
    __u32 tid;
    char method[16];
    char host[64];
    unsigned char trace_id[16];
};

// Force BTF generation for the Go struct generator
struct request_event __force_btf_request_event;

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} events SEC(".maps");

// Go 1.24 *http.Request offsets
#define REQ_METHOD_OFFSET 0
#define REQ_HOST_OFFSET 128
#define REQ_CTX_OFFSET 248

SEC("uprobe/RoundTrip")
int uprobe_roundtrip(struct pt_regs *ctx) {
    struct request_event event = {};
    
    // In Go 1.17+ ABI, receiver (*http.Transport) is in AX, and first arg (*http.Request) is in BX.
    __u64 req_ptr = ctx->bx;
    if (!req_ptr) return 0;

    event.request_ptr = req_ptr;
    event.timestamp_ns = bpf_ktime_get_ns();
    
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    event.pid = pid_tgid >> 32;
    event.tid = pid_tgid & 0xFFFFFFFF;

    // Read Method string
    __u64 method_data_ptr = 0;
    __u64 method_len = 0;
    bpf_probe_read_user(&method_data_ptr, sizeof(method_data_ptr), (void *)(req_ptr + REQ_METHOD_OFFSET));
    bpf_probe_read_user(&method_len, sizeof(method_len), (void *)(req_ptr + REQ_METHOD_OFFSET + 8));
    
    if (method_len > 0 && method_data_ptr != 0) {
        if (method_len > sizeof(event.method) - 1) method_len = sizeof(event.method) - 1;
        bpf_probe_read_user(event.method, method_len, (void *)method_data_ptr);
    }

    // Read Host string
    __u64 host_data_ptr = 0;
    __u64 host_len = 0;
    bpf_probe_read_user(&host_data_ptr, sizeof(host_data_ptr), (void *)(req_ptr + REQ_HOST_OFFSET));
    bpf_probe_read_user(&host_len, sizeof(host_len), (void *)(req_ptr + REQ_HOST_OFFSET + 8));

    if (host_len > 0 && host_data_ptr != 0) {
        if (host_len > sizeof(event.host) - 1) host_len = sizeof(event.host) - 1;
        bpf_probe_read_user(event.host, host_len, (void *)host_data_ptr);
    }

    // Read context.Context (interface)
    __u64 ctx_data_ptr = 0;
    bpf_probe_read_user(&ctx_data_ptr, sizeof(ctx_data_ptr), (void *)(req_ptr + REQ_CTX_OFFSET + 8));
    event.context_ptr = ctx_data_ptr;

    // Traverse context to find OTel TraceID
    // 1. ctx is *context.valueCtx. The 'val' interface is at offset 32. 
    //    'val.data' (the pointer to the span) is at offset 32 + 8 = 40.
    __u64 span_ptr = 0;
    bpf_probe_read_user(&span_ptr, sizeof(span_ptr), (void *)(ctx_data_ptr + 40));
    
    // 2. span is *trace.recordingSpan. The 'spanContext.traceID' is at offset 192.
    if (span_ptr != 0) {
        bpf_probe_read_user(event.trace_id, sizeof(event.trace_id), (void *)(span_ptr + 192));
    }

    // Emit event
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));

    return 0;
}

SEC("uprobe/Request_write")
int uprobe_request_write(struct pt_regs *ctx) {
    struct request_event event = {};
    
    // In Go ABI, receiver (*http.Request) is in AX
    __u64 req_ptr = ctx->ax;
    if (!req_ptr) return 0;

    event.request_ptr = req_ptr;
    event.timestamp_ns = bpf_ktime_get_ns();
    
    // Read ctx to verify it matches
    __u64 ctx_data_ptr = 0;
    bpf_probe_read_user(&ctx_data_ptr, sizeof(ctx_data_ptr), (void *)(req_ptr + REQ_CTX_OFFSET + 8));
    event.context_ptr = ctx_data_ptr;
    
    // Use a special method string to indicate this is the write phase
    char phase[] = "WRITE";
    bpf_probe_read_kernel(event.method, sizeof(phase), phase);

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    return 0;
}
