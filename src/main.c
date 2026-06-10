// src/main.c — Sentinel VMI Entry Point
//
// Ring -1 hypervisor introspection daemon.
// Assumes the guest OS is compromised.
// Enforces security from outside the trust boundary.

#include "sentinel_vmi.h"
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
  printf("  ║  Phase 2: Memory Layout Parsing           ║\n");
  printf("  ║  Phase 3: NPT Guard (sys_call_table)     ║\n");
  printf("  ║  Phase 4: Cross-Layer Bridge              ║\n");
  printf("  ╚═══════════════════════════════════════════╝\n");
  printf("\n");
}

int main(int argc, char *argv[]) {
  if (argc < 2) {
    fprintf(stderr, "Usage: %s <vm-name> [--capture-passive]\n", argv[0]);
    fprintf(stderr, "\n");
    fprintf(stderr, "  vm-name: Name of the QEMU/KVM VM to introspect\n");
    fprintf(stderr, "\n");
    return 1;
  }
  
  int is_passive = 0;
  if (argc >= 3 && strcmp(argv[2], "--capture-passive") == 0) {
      is_passive = 1;
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
  task_walker_detect_orphans(session);
  task_walker_detect_fork_bomb(session, 256);
  task_walker_detect_suspicious_ancestry(session);

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

  // Initialize Heki Bridge server
  const char *heki_socket = getenv("TELOS_HEKI_VMI_SOCKET");
  if (heki_socket) {
    if (heki_server_init(session, heki_socket) < 0) {
      fprintf(stderr, "[VMI] WARN: Failed to initialize HEKI server on %s\n",
              heki_socket);
    }
  }

  // ────────────────────────────────────────
  // Main event loop
  // ────────────────────────────────────────
  printf("\n[VMI] ═══════════════════════════════════════\n");
  printf("[VMI] All phases armed. Entering event loop.\n");
  if (is_passive) {
      printf("[VMI] Mode: CAPTURE_PASSIVE (Dumping telemetry to capture/semantic_replay)\n");
      session->active_capture_mode = CAPTURE_PASSIVE;
  }
  printf("[VMI] Press Ctrl+C to stop.\n");
  printf("[VMI] ═══════════════════════════════════════\n\n");

  const char *interval_env = getenv("VMI_SCAN_INTERVAL_MS");
  int scan_interval_ms = interval_env ? atoi(interval_env) : 250;
  if (scan_interval_ms <= 0)
    scan_interval_ms = 250;

  while (running) {
    if (kvmi_session_heartbeat(session) < 0) {
      fprintf(stderr, "[VMI] WARN: KVMI heartbeat failed\n");
    }

    // Handle NPF events from NPT Guard
    npt_guard_handle_events(session);

    // Handle Heki dynamic registrations
    heki_server_poll();

    // Periodic privilege escalation scan
    task_walker_detect_privilege_escalation(session);
    task_walker_detect_orphans(session);
    task_walker_detect_fork_bomb(session, 256);
    task_walker_detect_suspicious_ancestry(session);

    // Flush queued alerts
    bridge_flush_alerts();
    
    if (session->active_capture_mode == CAPTURE_PASSIVE) {
        for (int i = 0; i < session->nr_vcpus; i++) {
            vmi_capture_ring_to_disk(&session->vcpu_rings[i], "capture/semantic_replay");
        }
    } else {
        regulatory_daemon_loop(session);
    }

    usleep(scan_interval_ms * 1000);
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
