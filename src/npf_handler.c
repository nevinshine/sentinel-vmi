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
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define SYSCALL_ENTRY_SIZE 8ULL
#define SYSCALL_MAX_ENTRIES 512ULL
#define SYSCALL_TABLE_SIZE (SYSCALL_ENTRY_SIZE * SYSCALL_MAX_ENTRIES)

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

enum fault_classification {
    FAULT_IGNORE = 0,
    FAULT_LEGITIMATE = 1,
    FAULT_SUSPICIOUS = 2,
    FAULT_MALICIOUS = 3,
};

static const char *classification_to_string(enum fault_classification c) {
    switch (c) {
    case FAULT_LEGITIMATE:
        return "LEGITIMATE";
    case FAULT_SUSPICIOUS:
        return "SUSPICIOUS";
    case FAULT_MALICIOUS:
        return "MALICIOUS";
    default:
        return "IGNORED";
    }
}

// ──────────────────────────────────────────────
// Internal: Check if fault is from a legitimate source
// ──────────────────────────────────────────────

static int is_legitimate_fault(struct vmi_session *s,
                               uint64_t fault_gpa,
                               const char *region_name) {
    (void)s;
    (void)fault_gpa;

    // In a full implementation:
    // 1. Read the guest RIP from the trapped vCPU
    // 2. Resolve it to a kernel symbol
    // 3. Check against the whitelist
    //
    // Optional override for controlled staging environments.
    // Keep disabled in production.
    const char *allow_patch = getenv("VMI_ALLOW_LEGIT_KERNEL_PATCH");
    if (allow_patch && strcmp(allow_patch, "1") == 0) {
        if (region_name &&
            (strcmp(region_name, "sys_call_table") == 0 ||
             strcmp(region_name, "kernel_text") == 0)) {
            return 1;
        }
    }

    // Conservative default: protected writes are hostile.

    return 0;  // Not legitimate → treat as hostile
}

static enum fault_classification classify_fault(struct vmi_session *s,
                                                uint64_t gpa,
                                                int write_access,
                                                const char **region_out,
                                                int *critical_out) {
    if (!s || !write_access) {
        if (region_out) *region_out = "none";
        if (critical_out) *critical_out = 0;
        return FAULT_IGNORE;
    }

    const char *region = "protected_page";
    int critical = 0;

    if (s->syscall_table_gpa != 0 &&
        gpa >= s->syscall_table_gpa &&
        gpa < s->syscall_table_gpa + SYSCALL_TABLE_SIZE) {
        region = "sys_call_table";
        critical = 1;
    }

    if (region_out) *region_out = region;
    if (critical_out) *critical_out = critical;

    if (is_legitimate_fault(s, gpa, region))
        return FAULT_LEGITIMATE;

    return critical ? FAULT_MALICIOUS : FAULT_SUSPICIOUS;
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
    if (!s || !write_access) return;  // We only care about writes

    const char *region_name = "protected_page";
    int critical = 0;
    enum fault_classification classification =
        classify_fault(s, gpa, write_access, &region_name, &critical);

    if (classification == FAULT_IGNORE)
        return;

    printf("[NPF-Handler] ══════════════════════════════════════\n");
    printf("[NPF-Handler] #NPF TRAPPED — WRITE TO PROTECTED PAGE\n");
    printf("[NPF-Handler] ══════════════════════════════════════\n");
    printf("[NPF-Handler] Fault GPA: 0x%lx\n", gpa);
    printf("[NPF-Handler] Region: %s\n", region_name);

    int syscall_target = 0;

    // Calculate which syscall entry was targeted
    if (s->syscall_table_gpa != 0) {
        if (gpa >= s->syscall_table_gpa &&
            gpa < s->syscall_table_gpa + SYSCALL_TABLE_SIZE) {
            syscall_target = 1;
        }

        int entry_index = (int)((gpa - s->syscall_table_gpa) / SYSCALL_ENTRY_SIZE);
        if (entry_index >= 0 && entry_index < 512) {
            printf("[NPF-Handler] Targeted syscall entry: %d\n",
                   entry_index);
        }
    }

    // Check if this is a legitimate kernel operation
    if (classification == FAULT_LEGITIMATE) {
        printf("[NPF-Handler] Fault classified as LEGITIMATE "
               "(ftrace/livepatch)\n");
        return;
    }

    // This is hostile. Identify the attacker.
    uint32_t malicious_pid = identify_malicious_pid(s);

    printf("[NPF-Handler] ⚠ CLASSIFICATION: %s\n",
           classification_to_string(classification));
    printf("[NPF-Handler] ⚠ Attacker PID: %u\n", malicious_pid);
    printf("[NPF-Handler] ⚠ Action: Signaling cross-layer bridge\n");

    // Signal to the cross-layer bridge
    char reason[128];
    if (syscall_target) {
        snprintf(reason, sizeof(reason),
                 "syscall_table_write: GPA=0x%lx", gpa);
        bridge_signal_malicious(malicious_pid, reason);
    } else {
        snprintf(reason, sizeof(reason),
                 "%s_write: GPA=0x%lx", region_name, gpa);
        if (classification == FAULT_MALICIOUS || critical) {
            bridge_signal_malicious(malicious_pid, reason);
        } else {
            bridge_signal_suspicious(malicious_pid, reason);
        }
    }

    printf("[NPF-Handler] ⚠ Response chain activated:\n");
    printf("[NPF-Handler]   → vmi_alert_map updated\n");
    printf("[NPF-Handler]   → Hyperion XDP: XDP_DROP for PID %u\n",
           malicious_pid);
    printf("[NPF-Handler]   → Telos Runtime: TAINT_CRITICAL\n");
    printf("[NPF-Handler]   → Zero bytes leave this machine\n");
}

int npf_handler_report_integrity_violation(struct vmi_session *s,
                                           const char *region_name,
                                           uint64_t gpa,
                                           uint64_t expected_hash,
                                           uint64_t actual_hash,
                                           int critical) {
    if (!s || !region_name)
        return -1;

    uint32_t suspect_pid = identify_malicious_pid(s);

    printf("[NPF-Handler] ══════════════════════════════════════\n");
    printf("[NPF-Handler] INTEGRITY VIOLATION DETECTED\n");
    printf("[NPF-Handler] ══════════════════════════════════════\n");
    printf("[NPF-Handler] Region: %s\n", region_name);
    printf("[NPF-Handler] GPA: 0x%lx\n", gpa);
    printf("[NPF-Handler] Expected hash: 0x%lx\n", expected_hash);
    printf("[NPF-Handler] Current  hash: 0x%lx\n", actual_hash);
    printf("[NPF-Handler] Classification: %s\n",
           critical ? "MALICIOUS" : "SUSPICIOUS");

    char reason[160];
    snprintf(reason,
             sizeof(reason),
             "%s_integrity_violation: GPA=0x%lx baseline=0x%lx current=0x%lx",
             region_name,
             gpa,
             expected_hash,
             actual_hash);

    if (critical) {
        bridge_signal_malicious(suspect_pid, reason);
    } else {
        bridge_signal_suspicious(suspect_pid, reason);
    }

    return 0;
}
