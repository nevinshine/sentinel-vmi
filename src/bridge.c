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
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>

// ──────────────────────────────────────────────
// Alert queue — buffered before flush to map
// ──────────────────────────────────────────────

#define ALERT_QUEUE_SIZE 256
#define PID_POLICY_TABLE_SIZE 1024

#define POLICY_ESCALATION_COUNT 3U
#define POLICY_ESCALATION_WINDOW_NS (10ULL * 1000000000ULL)
#define POLICY_DEDUP_WINDOW_NS      (1ULL * 1000000000ULL)

#define STREAM_DEFAULT_HOST "127.0.0.1"
#define STREAM_DEFAULT_PORT 8421U
#define STREAM_MODE_TCP "tcp"
#define STREAM_MODE_HELPER "helper"
#define STREAM_RECONNECT_BASE_NS (1ULL * 1000000000ULL)
#define STREAM_RECONNECT_MAX_NS  (30ULL * 1000000000ULL)

struct queued_alert {
    struct vmi_alert alert;
    int sent_immediately;
};

struct pid_policy_state {
    uint32_t pid;
    uint32_t last_effective_threat;
    uint32_t suspicious_burst;
    uint64_t burst_window_start_ns;
    uint64_t last_emit_ns;
    int used;
};

static struct queued_alert alert_queue[ALERT_QUEUE_SIZE];
static int alert_count = 0;
static int bpf_map_fd = -1;
static uint64_t total_alerts_processed = 0;

static struct pid_policy_state policy_table[PID_POLICY_TABLE_SIZE];

static int stream_enabled = 0;
static int stream_fd = -1;
static char stream_host[64];
static uint16_t stream_port = STREAM_DEFAULT_PORT;
static char stream_mode[16];
static char stream_helper_cmd[256];
static FILE *stream_helper_fp = NULL;
static uint64_t stream_next_reconnect_ns = 0;
static uint64_t stream_reconnect_backoff_ns = STREAM_RECONNECT_BASE_NS;

static const char *threat_type_from_level(uint32_t level) {
    switch (level) {
    case VMI_THREAT_MALICIOUS:
        return "malicious";
    case VMI_THREAT_SUSPICIOUS:
        return "suspicious";
    default:
        return "clean";
    }
}

static double threat_confidence_from_level(uint32_t level) {
    switch (level) {
    case VMI_THREAT_MALICIOUS:
        return 0.98;
    case VMI_THREAT_SUSPICIOUS:
        return 0.65;
    default:
        return 0.10;
    }
}

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

static int env_enabled(const char *key, int default_value) {
    const char *value = getenv(key);
    if (!value || !*value)
        return default_value;

    if (strcmp(value, "1") == 0 ||
        strcmp(value, "true") == 0 ||
        strcmp(value, "yes") == 0)
        return 1;

    if (strcmp(value, "0") == 0 ||
        strcmp(value, "false") == 0 ||
        strcmp(value, "no") == 0)
        return 0;

    return default_value;
}

static void parse_stream_config(void) {
    stream_enabled = env_enabled("VMI_ALERT_STREAM_ENABLE", 0);
    stream_fd = -1;
    stream_helper_fp = NULL;
    stream_next_reconnect_ns = 0;
    stream_reconnect_backoff_ns = STREAM_RECONNECT_BASE_NS;

    const char *mode = getenv("VMI_ALERT_STREAM_MODE");
    if (!mode || !*mode)
        mode = STREAM_MODE_TCP;
    strncpy(stream_mode, mode, sizeof(stream_mode) - 1);
    stream_mode[sizeof(stream_mode) - 1] = '\0';

    if (strcmp(stream_mode, STREAM_MODE_TCP) != 0 &&
        strcmp(stream_mode, STREAM_MODE_HELPER) != 0) {
        fprintf(stderr,
                "[Bridge] WARN: unknown stream mode '%s', defaulting to tcp\n",
                stream_mode);
        strncpy(stream_mode, STREAM_MODE_TCP, sizeof(stream_mode) - 1);
        stream_mode[sizeof(stream_mode) - 1] = '\0';
    }

    const char *host = getenv("VMI_ALERT_STREAM_HOST");
    if (!host || !*host)
        host = STREAM_DEFAULT_HOST;
    strncpy(stream_host, host, sizeof(stream_host) - 1);
    stream_host[sizeof(stream_host) - 1] = '\0';

    const char *port_env = getenv("VMI_ALERT_STREAM_PORT");
    if (!port_env || !*port_env) {
        stream_port = STREAM_DEFAULT_PORT;
    } else {
        char *end = NULL;
        unsigned long port = strtoul(port_env, &end, 10);
        if (end != port_env && port > 0 && port <= 65535UL)
            stream_port = (uint16_t)port;
        else
            stream_port = STREAM_DEFAULT_PORT;
    }

    const char *helper_cmd = getenv("VMI_ALERT_GRPC_HELPER_CMD");
    if (!helper_cmd || !*helper_cmd)
        helper_cmd = "";
    strncpy(stream_helper_cmd, helper_cmd, sizeof(stream_helper_cmd) - 1);
    stream_helper_cmd[sizeof(stream_helper_cmd) - 1] = '\0';

    if (!stream_enabled && stream_helper_cmd[0] != '\0') {
        stream_enabled = 1;
        printf("[Bridge] Alert stream auto-enabled from helper command\n");
    }

    if (stream_enabled && strcmp(stream_mode, STREAM_MODE_HELPER) == 0 &&
        stream_helper_cmd[0] == '\0') {
        fprintf(stderr,
                "[Bridge] WARN: helper mode selected but "
                "VMI_ALERT_GRPC_HELPER_CMD is empty; disabling stream\n");
        stream_enabled = 0;
    }

    if (stream_enabled) {
        if (strcmp(stream_mode, STREAM_MODE_HELPER) == 0) {
            printf("[Bridge] Alert stream enabled: mode=%s cmd='%s'\n",
                   stream_mode,
                   stream_helper_cmd);
        } else {
            printf("[Bridge] Alert stream enabled: mode=%s target=%s:%u\n",
                   stream_mode,
                   stream_host,
                   (unsigned int)stream_port);
        }
    }
}

static void stream_disconnect(void) {
    if (stream_fd >= 0) {
        close(stream_fd);
        stream_fd = -1;
    }

    if (stream_helper_fp) {
        (void)pclose(stream_helper_fp);
        stream_helper_fp = NULL;
    }
}

static void schedule_stream_reconnect(uint64_t now_ns) {
    stream_next_reconnect_ns = now_ns + stream_reconnect_backoff_ns;
    if (stream_reconnect_backoff_ns < STREAM_RECONNECT_MAX_NS / 2ULL) {
        stream_reconnect_backoff_ns *= 2ULL;
    } else {
        stream_reconnect_backoff_ns = STREAM_RECONNECT_MAX_NS;
    }
}

static int stream_connect_if_needed(uint64_t now_ns) {
    if (!stream_enabled)
        return -1;

    if (strcmp(stream_mode, STREAM_MODE_HELPER) == 0) {
        if (stream_helper_fp)
            return 0;
    } else if (stream_fd >= 0) {
        return 0;
    }

    if (stream_next_reconnect_ns != 0 && now_ns < stream_next_reconnect_ns)
        return -1;

    if (strcmp(stream_mode, STREAM_MODE_HELPER) == 0) {
        FILE *fp = popen(stream_helper_cmd, "w");
        if (!fp) {
            schedule_stream_reconnect(now_ns);
            return -1;
        }

        setvbuf(fp, NULL, _IOLBF, 0);
        stream_helper_fp = fp;
        stream_reconnect_backoff_ns = STREAM_RECONNECT_BASE_NS;
        stream_next_reconnect_ns = 0;
        printf("[Bridge] Connected alert helper stream\n");
        return 0;
    }

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        schedule_stream_reconnect(now_ns);
        return -1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(stream_port);

    const char *connect_host = stream_host;
    if (strcmp(connect_host, "localhost") == 0)
        connect_host = "127.0.0.1";

    if (inet_pton(AF_INET, connect_host, &addr.sin_addr) != 1) {
        close(fd);
        schedule_stream_reconnect(now_ns);
        fprintf(stderr,
                "[Bridge] WARN: invalid stream host '%s' (IPv4 required)\n",
                stream_host);
        return -1;
    }

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        schedule_stream_reconnect(now_ns);
        return -1;
    }

    stream_fd = fd;
    stream_reconnect_backoff_ns = STREAM_RECONNECT_BASE_NS;
    stream_next_reconnect_ns = 0;
    printf("[Bridge] Connected alert stream to %s:%u\n",
           stream_host,
           (unsigned int)stream_port);
    return 0;
}

static void json_escape_string(const char *src, char *dst, size_t dst_size) {
    if (!src || !dst || dst_size == 0)
        return;

    size_t w = 0;
    for (size_t r = 0; src[r] != '\0' && w + 1 < dst_size; r++) {
        unsigned char c = (unsigned char)src[r];
        if (c == '"' || c == '\\') {
            if (w + 2 >= dst_size)
                break;
            dst[w++] = '\\';
            dst[w++] = (char)c;
        } else if (c == '\n') {
            if (w + 2 >= dst_size)
                break;
            dst[w++] = '\\';
            dst[w++] = 'n';
        } else if (c < 0x20) {
            if (w + 1 >= dst_size)
                break;
            dst[w++] = '?';
        } else {
            dst[w++] = (char)c;
        }
    }

    dst[w] = '\0';
}

static int stream_send_alert(const struct vmi_alert *alert) {
    if (!alert)
        return -1;

    if (stream_connect_if_needed(alert->timestamp_ns) < 0)
        return -1;

    char reason_json[2 * VMI_ALERT_REASON_MAX + 8];
    const char *threat_type = threat_type_from_level(alert->threat_level);
    double confidence = threat_confidence_from_level(alert->threat_level);
    char payload[512];
    json_escape_string(alert->reason, reason_json, sizeof(reason_json));

    int len = snprintf(payload,
                       sizeof(payload),
                       "{\"pid\":%u,\"threat_level\":%u,"
                       "\"threat_type\":\"%s\",\"confidence\":%.2f,"
                       "\"timestamp_ns\":%lu,\"reason\":\"%s\"}\n",
                       alert->pid,
                       alert->threat_level,
                       threat_type,
                       confidence,
                       alert->timestamp_ns,
                       reason_json);
    if (len <= 0 || (size_t)len >= sizeof(payload))
        return -1;

    if (strcmp(stream_mode, STREAM_MODE_HELPER) == 0) {
        if (!stream_helper_fp)
            return -1;

        if (fputs(payload, stream_helper_fp) == EOF || fflush(stream_helper_fp) != 0) {
            uint64_t now_ns = alert->timestamp_ns;
            stream_disconnect();
            schedule_stream_reconnect(now_ns);
            return -1;
        }

        return 0;
    }

    ssize_t written = write(stream_fd, payload, (size_t)len);
    if (written != len) {
        uint64_t now_ns = alert->timestamp_ns;
        stream_disconnect();
        schedule_stream_reconnect(now_ns);
        return -1;
    }

    return 0;
}

// ──────────────────────────────────────────────
// Internal: Get monotonic nanosecond timestamp
// ──────────────────────────────────────────────

static uint64_t get_timestamp_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static struct pid_policy_state *get_policy_state(uint32_t pid) {
    struct pid_policy_state *free_slot = NULL;

    for (int i = 0; i < PID_POLICY_TABLE_SIZE; i++) {
        if (policy_table[i].used && policy_table[i].pid == pid)
            return &policy_table[i];
        if (!policy_table[i].used && !free_slot)
            free_slot = &policy_table[i];
    }

    if (!free_slot)
        free_slot = &policy_table[pid % PID_POLICY_TABLE_SIZE];

    memset(free_slot, 0, sizeof(*free_slot));
    free_slot->pid = pid;
    free_slot->used = 1;
    return free_slot;
}

static uint32_t apply_threat_policy(uint32_t pid,
                                    uint32_t requested_threat,
                                    uint64_t now_ns,
                                    int *suppress_emit,
                                    int *escalated) {
    if (suppress_emit)
        *suppress_emit = 0;
    if (escalated)
        *escalated = 0;

    struct pid_policy_state *state = get_policy_state(pid);
    if (!state)
        return requested_threat;

    uint32_t effective = requested_threat;

    if (requested_threat == VMI_THREAT_SUSPICIOUS) {
        if (state->burst_window_start_ns == 0 ||
            now_ns - state->burst_window_start_ns > POLICY_ESCALATION_WINDOW_NS) {
            state->burst_window_start_ns = now_ns;
            state->suspicious_burst = 0;
        }

        state->suspicious_burst++;
        if (state->suspicious_burst >= POLICY_ESCALATION_COUNT) {
            effective = VMI_THREAT_MALICIOUS;
            if (escalated)
                *escalated = 1;
        }
    } else {
        state->suspicious_burst = 0;
        state->burst_window_start_ns = now_ns;
    }

    if (effective == state->last_effective_threat &&
        now_ns - state->last_emit_ns < POLICY_DEDUP_WINDOW_NS) {
        if (!(escalated && *escalated)) {
            if (suppress_emit)
                *suppress_emit = 1;
        }
    }

    if (!(suppress_emit && *suppress_emit)) {
        state->last_effective_threat = effective;
        state->last_emit_ns = now_ns;
    }

    return effective;
}

static int emit_alert(struct queued_alert *queued) {
    if (!queued)
        return -1;

    int map_rc = write_alert_to_map(&queued->alert);
    (void)stream_send_alert(&queued->alert);
    total_alerts_processed++;
    return map_rc;
}

static void enqueue_alert(uint32_t pid,
                          uint32_t threat_level,
                          const char *reason,
                          int immediate) {
    if (alert_count >= ALERT_QUEUE_SIZE)
        bridge_flush_alerts();

    if (alert_count >= ALERT_QUEUE_SIZE)
        return;

    struct queued_alert *queued = &alert_queue[alert_count++];
    memset(queued, 0, sizeof(*queued));
    queued->alert.pid = pid;
    queued->alert.threat_level = threat_level;
    queued->alert.timestamp_ns = get_timestamp_ns();
    strncpy(queued->alert.reason,
            reason ? reason : "unknown",
            sizeof(queued->alert.reason) - 1);
    queued->alert.reason[sizeof(queued->alert.reason) - 1] = '\0';

    if (immediate) {
        emit_alert(queued);
        queued->sent_immediately = 1;
    }
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

    parse_stream_config();
    alert_count = 0;
    memset(alert_queue, 0, sizeof(alert_queue));
    memset(policy_table, 0, sizeof(policy_table));
    total_alerts_processed = 0;

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

    stream_disconnect();

    printf("[Bridge] Bridge destroyed. %lu total alerts processed.\n",
           total_alerts_processed);
}

void bridge_signal_malicious(uint32_t pid, const char *reason) {
    printf("[Bridge] ⚠ MALICIOUS SIGNAL: PID %u — %s\n", pid, reason);
    int suppress = 0;
    int escalated = 0;
    uint64_t now_ns = get_timestamp_ns();
    uint32_t effective = apply_threat_policy(pid,
                                             VMI_THREAT_MALICIOUS,
                                             now_ns,
                                             &suppress,
                                             &escalated);
    if (!suppress) {
        enqueue_alert(pid,
                      effective,
                      reason,
                      1);
    }

    printf("[Bridge] → Hyperion XDP will DROP all packets from PID %u\n",
           pid);
    printf("[Bridge] → Telos Runtime will elevate to TAINT_CRITICAL\n");
}

void bridge_signal_suspicious(uint32_t pid, const char *reason) {
    printf("[Bridge] △ SUSPICIOUS SIGNAL: PID %u — %s\n", pid, reason);

    int suppress = 0;
    int escalated = 0;
    uint64_t now_ns = get_timestamp_ns();
    uint32_t effective = apply_threat_policy(pid,
                                             VMI_THREAT_SUSPICIOUS,
                                             now_ns,
                                             &suppress,
                                             &escalated);

    if (escalated) {
        printf("[Bridge] Escalation policy triggered: PID %u now MALICIOUS\n",
               pid);
    }

    if (suppress) {
        printf("[Bridge] Duplicate alert suppressed for PID %u\n", pid);
        return;
    }

    enqueue_alert(pid,
                  effective,
                  reason,
                  effective == VMI_THREAT_MALICIOUS);

    if (effective == VMI_THREAT_MALICIOUS) {
        printf("[Bridge] → Hyperion XDP will DROP all packets from PID %u\n",
               pid);
        printf("[Bridge] → Telos Runtime will elevate to TAINT_CRITICAL\n");
    }
}

void bridge_flush_alerts(void) {
    if (alert_count == 0) return;

    printf("[Bridge] Flushing %d queued alerts to map...\n", alert_count);

    int written = 0;
    int already_dispatched = 0;
    for (int i = 0; i < alert_count; i++) {
        if (alert_queue[i].sent_immediately) {
            already_dispatched++;
            continue;
        }

        if (emit_alert(&alert_queue[i]) == 0)
            written++;
    }

    printf("[Bridge] Flushed %d batched alerts (%d already dispatched)\n",
           written,
           already_dispatched);
    alert_count = 0;
}
