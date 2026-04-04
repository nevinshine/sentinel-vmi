// include/vmi_alert_map.h
#pragma once
#include <stdint.h>

#define VMI_ALERT_MAP_NAME    "vmi_alert_map"
#define VMI_ALERT_MAP_PATH    "/sys/fs/bpf/vmi_alert_map"
#define VMI_ALERT_MAP_SIZE    1024
#define VMI_ALERT_REASON_MAX  64
#define VMI_ALERT_FALLBACK_PATH "/tmp/vmi_alerts.log"

// Threat levels
#define VMI_THREAT_CLEAN      0
#define VMI_THREAT_SUSPICIOUS 1
#define VMI_THREAT_MALICIOUS  2

// Alert entry written to the map
struct vmi_alert {
    uint32_t pid;
    uint32_t threat_level;
    uint64_t timestamp_ns;
    char     reason[VMI_ALERT_REASON_MAX];
};
