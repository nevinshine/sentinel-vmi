// src/bridge.c
#include "sentinel_vmi.h"
#include "vmi_alert_map.h"
#include <stdio.h>

int bridge_init(void) {
    printf("[Bridge] Initializing cross-layer signal bridge to eBPF/Telos.\n");
    return 0;
}

void bridge_teardown(void) {
    printf("[Bridge] Tearing down cross-layer bridge.\n");
}

void bridge_signal_malicious(uint32_t pid, const char *reason) {
    printf("[Bridge] Signaling malicious activity for PID %u (%s)\n", pid, reason);
}

void bridge_flush_alerts(void) {
    // Fake flushing alerts in the loop
}
