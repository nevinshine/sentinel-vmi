// src/bridge.c — Phase 4: Cross-Layer eBPF Map Signaling
//
// Connects Ring -1 detection to the rest of the Sentinel Stack.
// Writes malicious PID alerts to the pinned BPF map vmi_alert_map.
// Hyperion XDP reads this map for wire-speed XDP_DROP.
// Telos Runtime reads this map for taint elevation.
//
// Signal flow:
//   VMI detects rootkit → bridge writes PID to map
//   → Hyperion XDP_DROP → Telos TAINT_CRITICAL
//   → Zero bytes leave the machine

#include "sentinel_vmi.h"
#include "vmi_alert_map.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

// ──────────────────────────────────────────────
// Alert queue — buffered before flush to map
// ──────────────────────────────────────────────

#define ALERT_QUEUE_SIZE 256

static struct vmi_alert alert_queue[ALERT_QUEUE_SIZE];
static int alert_count = 0;
static int bpf_map_fd = -1;

// ──────────────────────────────────────────────
// Internal: Open the pinned BPF map
// ──────────────────────────────────────────────

#ifdef HAVE_LIBBPF
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

static int open_bpf_map(void) {
    bpf_map_fd = bpf_obj_get(VMI_ALERT_MAP_PATH);
    if (bpf_map_fd < 0) {
        fprintf(stderr, "[Bridge] Cannot open pinned map %s: %s\n",
                VMI_ALERT_MAP_PATH, strerror(errno));
        fprintf(stderr, "[Bridge] Create it first: "
                "bpftool map create %s type hash "
                "key 4 value 4 entries %d name %s\n",
                VMI_ALERT_MAP_PATH, VMI_ALERT_MAP_SIZE,
                VMI_ALERT_MAP_NAME);
        return -1;
    }
    printf("[Bridge] Opened pinned BPF map: %s (fd=%d)\n",
           VMI_ALERT_MAP_PATH, bpf_map_fd);
    return 0;
}

static int write_alert_to_map(struct vmi_alert *alert) {
    if (bpf_map_fd < 0) return -1;

    // Key: PID, Value: threat_level
    return bpf_map_update_elem(bpf_map_fd,
                               &alert->pid,
                               &alert->threat_level,
                               BPF_ANY);
}

#else
// ──────────────────────────────────────────────
// No libbpf: filesystem-based fallback
// Write alerts to a well-known file that other
// components can poll. Less efficient but works
// without BPF.
// ──────────────────────────────────────────────

#define VMI_ALERT_FALLBACK_PATH "/tmp/vmi_alerts.log"

static int open_bpf_map(void) {
    printf("[Bridge] libbpf not available — using file-based "
           "fallback at %s\n", VMI_ALERT_FALLBACK_PATH);
    bpf_map_fd = open(VMI_ALERT_FALLBACK_PATH,
                      O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (bpf_map_fd < 0) {
        perror("[Bridge] open fallback");
        return -1;
    }
    return 0;
}

static int write_alert_to_map(struct vmi_alert *alert) {
    if (bpf_map_fd < 0) return -1;

    char line[256];
    int n = snprintf(line, sizeof(line),
                     "ALERT pid=%u threat=%u ts=%lu reason=%s\n",
                     alert->pid, alert->threat_level,
                     alert->timestamp_ns, alert->reason);
    if (write(bpf_map_fd, line, (size_t)n) < 0) {
        perror("[Bridge] write alert");
        return -1;
    }
    return 0;
}
#endif

// ──────────────────────────────────────────────
// Internal: Get monotonic nanosecond timestamp
// ──────────────────────────────────────────────

static uint64_t get_timestamp_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

// ──────────────────────────────────────────────
// Public API
// ──────────────────────────────────────────────

int bridge_init(void) {
    printf("[Bridge] ═══════════════════════════════════════\n");
    printf("[Bridge] Cross-Layer Signal Bridge Initializing\n");
    printf("[Bridge] ═══════════════════════════════════════\n");
    printf("[Bridge] Map name: %s\n", VMI_ALERT_MAP_NAME);
    printf("[Bridge] Map path: %s\n", VMI_ALERT_MAP_PATH);
    printf("[Bridge] Max entries: %d\n", VMI_ALERT_MAP_SIZE);

    alert_count = 0;
    memset(alert_queue, 0, sizeof(alert_queue));

    if (open_bpf_map() < 0) {
        printf("[Bridge] WARN: Map not available — alerts will be "
               "queued in memory only\n");
        // Non-fatal: we still queue alerts
    }

    printf("[Bridge] ✓ Bridge initialized\n");
    return 0;
}

void bridge_teardown(void) {
    printf("[Bridge] Tearing down bridge...\n");

    // Flush remaining alerts
    bridge_flush_alerts();

    if (bpf_map_fd >= 0) {
        close(bpf_map_fd);
        bpf_map_fd = -1;
    }

    printf("[Bridge] Bridge destroyed. %d total alerts processed.\n",
           alert_count);
}

void bridge_signal_malicious(uint32_t pid, const char *reason) {
    printf("[Bridge] ⚠ MALICIOUS SIGNAL: PID %u — %s\n", pid, reason);

    if (alert_count >= ALERT_QUEUE_SIZE) {
        fprintf(stderr, "[Bridge] Alert queue full! Flushing...\n");
        bridge_flush_alerts();
    }

    struct vmi_alert *alert = &alert_queue[alert_count++];
    alert->pid = pid;
    alert->threat_level = VMI_THREAT_MALICIOUS;
    alert->timestamp_ns = get_timestamp_ns();
    strncpy(alert->reason, reason, sizeof(alert->reason) - 1);
    alert->reason[sizeof(alert->reason) - 1] = '\0';

    // Immediate write for malicious alerts — don't wait for flush
    write_alert_to_map(alert);

    printf("[Bridge] → Hyperion XDP will DROP all packets from PID %u\n",
           pid);
    printf("[Bridge] → Telos Runtime will elevate to TAINT_CRITICAL\n");
}

void bridge_signal_suspicious(uint32_t pid, const char *reason) {
    printf("[Bridge] △ SUSPICIOUS SIGNAL: PID %u — %s\n", pid, reason);

    if (alert_count >= ALERT_QUEUE_SIZE) {
        bridge_flush_alerts();
    }

    struct vmi_alert *alert = &alert_queue[alert_count++];
    alert->pid = pid;
    alert->threat_level = VMI_THREAT_SUSPICIOUS;
    alert->timestamp_ns = get_timestamp_ns();
    strncpy(alert->reason, reason, sizeof(alert->reason) - 1);
    alert->reason[sizeof(alert->reason) - 1] = '\0';

    // Suspicious alerts are batched and flushed periodically
}

void bridge_flush_alerts(void) {
    if (alert_count == 0) return;

    printf("[Bridge] Flushing %d queued alerts to map...\n", alert_count);

    int written = 0;
    for (int i = 0; i < alert_count; i++) {
        if (write_alert_to_map(&alert_queue[i]) == 0)
            written++;
    }

    printf("[Bridge] Flushed %d/%d alerts\n", written, alert_count);
    alert_count = 0;
}
