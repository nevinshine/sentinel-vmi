// src/npf_handler.c — Phase 3: Nested Page Fault Trap & Analysis
//
// When the NPT Guard fires (a write to the protected sys_call_table
// page), this handler determines:
//   1. WHAT was modified (which syscall entry)
//   2. WHO did it (which vCPU → which guest PID)
//   3. Whether it's legitimate (kernel self-modification) or malicious
//
// If malicious → signal to bridge for cross-layer response.

#include "sentinel_vmi.h"
#include "vmi_alert_map.h"
#include <stdio.h>
#include <string.h>
#include <time.h>

// ──────────────────────────────────────────────
// Known legitimate sys_call_table writers
// Some kernel operations legitimately modify the area
// near sys_call_table (e.g., ftrace, livepatching).
// We maintain a whitelist.
// ──────────────────────────────────────────────

static const char *legitimate_writers[] = {
    "ftrace",
    "livepatch",
    "kprobes",
    NULL
};

// ──────────────────────────────────────────────
// Internal: Check if fault is from a legitimate source
// ──────────────────────────────────────────────

static int is_legitimate_fault(struct vmi_session *s,
                               uint64_t fault_gpa) {
    (void)s;
    (void)fault_gpa;

    // In a full implementation:
    // 1. Read the guest RIP from the trapped vCPU
    // 2. Resolve it to a kernel symbol
    // 3. Check against the whitelist
    //
    // For now, we assume all writes to sys_call_table are hostile.
    // This is the conservative approach — better false positives
    // than missed rootkits.

    return 0;  // Not legitimate → treat as hostile
}

// ──────────────────────────────────────────────
// Internal: Identify the malicious PID
// When a #NPF fires, the vCPU is paused. We read
// the guest's current task pointer to identify who
// was executing when the write occurred.
// ──────────────────────────────────────────────

static uint32_t identify_malicious_pid(struct vmi_session *s) {
    // In a full kvmi implementation:
    // 1. kvmi_get_registers() to read guest RSP/CR3
    // 2. Read current_task from the per-CPU GS segment
    // 3. Extract PID from the current task_struct
    //
    // This requires the vCPU to be paused (which it is
    // during a #NPF trap).

    (void)s;

    // Placeholder: in production, this returns the real PID
    printf("[NPF-Handler] Identifying malicious PID from "
           "trapped vCPU state...\n");
    return 0;  // Unknown for now
}

// ──────────────────────────────────────────────
// Public: Initialize NPF handler
// ──────────────────────────────────────────────

int npf_handler_init(struct vmi_session *s) {
    (void)s;
    printf("[NPF-Handler] Fault handler initialized\n");
    printf("[NPF-Handler] Legitimate writers: ");
    for (int i = 0; legitimate_writers[i]; i++) {
        printf("%s ", legitimate_writers[i]);
    }
    printf("\n");
    return 0;
}

// ──────────────────────────────────────────────
// Public: Process a Nested Page Fault
//
// Called when:
//   - A real #NPF fires (via kvmi event)
//   - The integrity checker detects a modification
//
// Parameters:
//   gpa          — guest physical address of the fault
//   write_access — 1 if this was a write, 0 if read
// ──────────────────────────────────────────────

void npf_handler_process(struct vmi_session *s,
                         uint64_t gpa,
                         int write_access) {
    if (!write_access) return;  // We only care about writes

    printf("[NPF-Handler] ══════════════════════════════════════\n");
    printf("[NPF-Handler] #NPF TRAPPED — WRITE TO PROTECTED PAGE\n");
    printf("[NPF-Handler] ══════════════════════════════════════\n");
    printf("[NPF-Handler] Fault GPA: 0x%lx\n", gpa);

    // Calculate which syscall entry was targeted
    if (s->syscall_table_gpa != 0) {
        int entry_index = (int)((gpa - s->syscall_table_gpa) / 8);
        if (entry_index >= 0 && entry_index < 512) {
            printf("[NPF-Handler] Targeted syscall entry: %d\n",
                   entry_index);
        }
    }

    // Check if this is a legitimate kernel operation
    if (is_legitimate_fault(s, gpa)) {
        printf("[NPF-Handler] Fault classified as LEGITIMATE "
               "(ftrace/livepatch)\n");
        return;
    }

    // This is hostile. Identify the attacker.
    uint32_t malicious_pid = identify_malicious_pid(s);

    printf("[NPF-Handler] ⚠ CLASSIFICATION: MALICIOUS\n");
    printf("[NPF-Handler] ⚠ Attacker PID: %u\n", malicious_pid);
    printf("[NPF-Handler] ⚠ Action: Signaling cross-layer bridge\n");

    // Signal to the cross-layer bridge
    char reason[128];
    snprintf(reason, sizeof(reason),
             "syscall_table_write: GPA=0x%lx", gpa);
    bridge_signal_malicious(malicious_pid, reason);

    printf("[NPF-Handler] ⚠ Response chain activated:\n");
    printf("[NPF-Handler]   → vmi_alert_map updated\n");
    printf("[NPF-Handler]   → Hyperion XDP: XDP_DROP for PID %u\n",
           malicious_pid);
    printf("[NPF-Handler]   → Telos Runtime: TAINT_CRITICAL\n");
    printf("[NPF-Handler]   → Zero bytes leave this machine\n");
}
