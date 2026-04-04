// src/main.c — Sentinel VMI Entry Point
//
// Ring -1 hypervisor introspection daemon.
// Assumes the guest OS is compromised.
// Enforces security from outside the trust boundary.

#include "sentinel_vmi.h"
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

static volatile int running = 1;

static void handle_signal(int sig) {
    (void)sig;
    running = 0;
}

static void print_banner(void) {
    printf("\n");
    printf("  ╔═══════════════════════════════════════════╗\n");
    printf("  ║         SENTINEL VMI — Ring -1            ║\n");
    printf("  ║    Hypervisor Introspection Engine        ║\n");
    printf("  ╠═══════════════════════════════════════════╣\n");
    printf("  ║  Phase 1: Raw Memory Introspection        ║\n");
    printf("  ║  Phase 2: Semantic Gap Bridging           ║\n");
    printf("  ║  Phase 3: NPT Guard (sys_call_table)     ║\n");
    printf("  ║  Phase 4: Cross-Layer Bridge              ║\n");
    printf("  ╚═══════════════════════════════════════════╝\n");
    printf("\n");
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <vm-name>\n", argv[0]);
        fprintf(stderr, "\n");
        fprintf(stderr, "  vm-name: Name of the QEMU/KVM VM to introspect\n");
        fprintf(stderr, "\n");
        fprintf(stderr, "  CRITICAL: Run this INSIDE a nested KVM VM.\n");
        fprintf(stderr, "            NEVER on the host machine.\n");
        return 1;
    }

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    print_banner();
    printf("[VMI] Target VM: %s\n", argv[1]);
    printf("[VMI] PID: %d\n", getpid());

    // ────────────────────────────────────────
    // Phase 1: Setup KVM introspection session
    // ────────────────────────────────────────
    printf("\n[VMI] ── Phase 1: KVM Introspection Setup ──\n");
    struct vmi_session *session = kvmi_setup(argv[1]);
    if (!session) {
        fprintf(stderr, "[VMI] FATAL: Failed to setup KVM introspection\n");
        return 1;
    }

    // ────────────────────────────────────────
    // Phase 2: Initial process list dump
    // ────────────────────────────────────────
    printf("\n[VMI] ── Phase 2: Process List Walk ──\n");
    task_walker_dump(session);
    task_walker_detect_privilege_escalation(session);

    // ────────────────────────────────────────
    // Phase 3: Arm NPT Guard
    // ────────────────────────────────────────
    printf("\n[VMI] ── Phase 3: NPT Guard ──\n");
    if (npt_guard_arm(session) != 0) {
        fprintf(stderr, "[VMI] FATAL: Failed to arm NPT Guard\n");
        kvmi_teardown(session);
        return 1;
    }

    // Initialize NPF handler
    npf_handler_init(session);

    // ────────────────────────────────────────
    // Phase 4: Initialize cross-layer bridge
    // ────────────────────────────────────────
    printf("\n[VMI] ── Phase 4: Cross-Layer Bridge ──\n");
    if (bridge_init() != 0) {
        fprintf(stderr, "[VMI] FATAL: Failed to initialize bridge\n");
        npt_guard_disarm(session);
        kvmi_teardown(session);
        return 1;
    }

    // ────────────────────────────────────────
    // Main event loop
    // ────────────────────────────────────────
    printf("\n[VMI] ═══════════════════════════════════════\n");
    printf("[VMI] All phases armed. Entering event loop.\n");
    printf("[VMI] Press Ctrl+C to stop.\n");
    printf("[VMI] ═══════════════════════════════════════\n\n");

    while (running) {
        // Handle NPF events from NPT Guard
        npt_guard_handle_events(session);

        // Periodic privilege escalation scan
        task_walker_detect_privilege_escalation(session);

        // Flush queued alerts
        bridge_flush_alerts();
    }

    // ────────────────────────────────────────
    // Graceful shutdown
    // ────────────────────────────────────────
    printf("\n[VMI] Shutting down...\n");
    bridge_teardown();
    npt_guard_disarm(session);
    kvmi_teardown(session);

    printf("[VMI] Sentinel VMI terminated cleanly.\n");
    return 0;
}
