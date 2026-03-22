// src/main.c
#include "sentinel_vmi.h"
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>

static volatile int running = 1;

static void handle_signal(int sig) {
    (void)sig;
    running = 0;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <vm-name>\n", argv[0]);
        return 1;
    }

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    printf("[VMI] Sentinel VMI starting\n");
    printf("[VMI] Target VM: %s\n", argv[1]);

    // Phase 1: Setup KVM introspection session
    struct vmi_session *session = kvmi_setup(argv[1]);
    if (!session) {
        fprintf(stderr, "[VMI] Failed to setup KVM introspection\n");
        return 1;
    }
    printf("[VMI] KVM introspection session established\n");

    // Phase 2: Initial process list dump
    printf("[VMI] Walking guest process list...\n");
    task_walker_dump(session);

    // Phase 3: Arm NPT Guard
    printf("[VMI] Arming NPT Guard on sys_call_table...\n");
    if (npt_guard_arm(session) != 0) {
        fprintf(stderr, "[VMI] Failed to arm NPT Guard\n");
        kvmi_teardown(session);
        return 1;
    }
    printf("[VMI] NPT Guard armed. sys_call_table is now protected.\n");

    // Phase 4: Initialize cross-layer bridge
    printf("[VMI] Initializing cross-layer bridge...\n");
    if (bridge_init() != 0) {
        fprintf(stderr, "[VMI] Failed to initialize bridge\n");
        npt_guard_disarm(session);
        kvmi_teardown(session);
        return 1;
    }

    // Main event loop
    printf("[VMI] Entering event loop. Press Ctrl+C to stop.\n");
    while (running) {
        // Handle NPF events from NPT Guard
        npt_guard_handle_events(session);

        // Process any new alerts
        bridge_flush_alerts();
    }

    printf("[VMI] Shutting down...\n");
    bridge_teardown();
    npt_guard_disarm(session);
    kvmi_teardown(session);

    return 0;
}
