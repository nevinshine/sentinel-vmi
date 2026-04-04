// src/task_walker.c — Phase 2: Semantic Gap Bridging
//
// Parses raw memory into meaningful kernel data structures.
// Walks the task_struct linked list starting from init_task,
// extracts PID, TGID, comm, credentials, and detects
// privilege escalation (uid 0 transitions).
//
// This is where raw bytes become intelligence.

#include "sentinel_vmi.h"
#include "task_offsets.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const struct task_offsets *active_offsets = &OFFSETS_6_6;
static int offsets_initialized = 0;

static const struct task_offsets *select_offsets_profile(const char *kernel_version) {
    if (!kernel_version || !*kernel_version)
        return NULL;

    if (strstr(kernel_version, "6.6"))
        return &OFFSETS_6_6;

    if (strstr(kernel_version, "6.1"))
        return &OFFSETS_6_1;

    return NULL;
}

int task_walker_set_offsets_profile(const char *kernel_version) {
    const struct task_offsets *profile = select_offsets_profile(kernel_version);
    if (!profile)
        return -1;

    active_offsets = profile;
    offsets_initialized = 1;
    printf("[TaskWalker] Using offset profile for kernel %s\n",
           active_offsets->kernel_version);
    return 0;
}

const char *task_walker_get_offsets_profile(void) {
    return active_offsets ? active_offsets->kernel_version : "unknown";
}

static void ensure_offsets_profile_selected(void) {
    if (offsets_initialized)
        return;

    const char *env_profile = getenv("VMI_GUEST_KERNEL_VERSION");
    if (env_profile && task_walker_set_offsets_profile(env_profile) == 0)
        return;

    offsets_initialized = 1;
}

// ──────────────────────────────────────────────
// Internal: Read a single task_struct field
// ──────────────────────────────────────────────

static int read_task_field(struct vmi_session *s,
                           uint64_t task_gva,
                           uint64_t offset,
                           void *buf,
                           size_t size) {
    return vmi_read_virtual(s, s->kernel_pgd,
                            task_gva + offset, buf, size);
}

// ──────────────────────────────────────────────
// Internal: Extract list_head.next pointer
// The task_struct.tasks field is a struct list_head:
//   struct list_head { struct list_head *next, *prev; };
// We read the 'next' pointer to traverse.
// ──────────────────────────────────────────────

static int read_tasks_next(struct vmi_session *s,
                           uint64_t task_gva,
                           uint64_t *next_task_gva) {
    uint64_t list_next;
    if (read_task_field(s, task_gva, active_offsets->tasks_offset,
                        &list_next, sizeof(list_next)) < 0)
        return -1;

    // list_head.next points to the 'tasks' field of the NEXT task_struct.
    // Subtract tasks_offset to get the base of that task_struct.
    *next_task_gva = list_next - active_offsets->tasks_offset;
    return 0;
}

// ──────────────────────────────────────────────
// Public: Read a complete process record from task_struct
// ──────────────────────────────────────────────

int task_walker_read_process(struct vmi_session *s,
                             uint64_t task_gva,
                             struct vmi_process *out) {
    if (!s || !out) return -1;

    ensure_offsets_profile_selected();

    memset(out, 0, sizeof(*out));
    out->task_addr = task_gva;

    // PID
    if (read_task_field(s, task_gva, active_offsets->pid_offset,
                        &out->pid, sizeof(out->pid)) < 0)
        return -1;

    // TGID
    if (read_task_field(s, task_gva, active_offsets->tgid_offset,
                        &out->tgid, sizeof(out->tgid)) < 0)
        return -1;

    // PPID from real_parent->pid
    if (active_offsets->real_parent_offset != 0) {
        uint64_t parent_task = 0;
        if (read_task_field(s, task_gva, active_offsets->real_parent_offset,
                            &parent_task, sizeof(parent_task)) == 0 &&
            parent_task != 0) {
            vmi_read_virtual(s, s->kernel_pgd,
                             parent_task + active_offsets->pid_offset,
                             &out->ppid, sizeof(out->ppid));
        }
    }

    // comm (process name)
    if (read_task_field(s, task_gva, active_offsets->comm_offset,
                        out->comm, TASK_COMM_LEN) < 0)
        return -1;
    out->comm[TASK_COMM_LEN - 1] = '\0';

    // mm_struct pointer
    if (read_task_field(s, task_gva, active_offsets->mm_offset,
                        &out->mm_addr, sizeof(out->mm_addr)) < 0)
        return -1;

    // cred pointer
    if (read_task_field(s, task_gva, active_offsets->cred_offset,
                        &out->cred_addr, sizeof(out->cred_addr)) < 0)
        return -1;

    // Read uid/gid from the cred struct
    if (out->cred_addr) {
        vmi_read_virtual(s, s->kernel_pgd,
                         out->cred_addr + active_offsets->cred_uid_offset,
                         &out->uid, sizeof(out->uid));
        vmi_read_virtual(s, s->kernel_pgd,
                         out->cred_addr + active_offsets->cred_gid_offset,
                         &out->gid, sizeof(out->gid));
    }

    return 0;
}

// ──────────────────────────────────────────────
// Public: Walk the full process list and dump to stdout
// Traverses: init_task → tasks.next → ... → init_task
// ──────────────────────────────────────────────

void task_walker_dump(struct vmi_session *s) {
    ensure_offsets_profile_selected();

    if (!s || s->init_task_addr == 0) {
        printf("[TaskWalker] init_task address not set — "
               "cannot walk process list\n");
        printf("[TaskWalker] Set session->init_task_addr and "
               "session->kernel_pgd first\n");
        return;
    }

    printf("[TaskWalker] ═══════════════════════════════════════\n");
    printf("[TaskWalker] Guest Process List (from Ring -1)\n");
    printf("[TaskWalker] ═══════════════════════════════════════\n");
        printf("[TaskWalker] %-6s %-6s %-6s %-16s %-5s %-5s %-18s\n",
            "PID", "TGID", "PPID", "COMM", "UID", "GID", "TASK_ADDR");
    printf("[TaskWalker] ─────────────────────────────────"
           "──────────────────────\n");

    uint64_t current = s->init_task_addr;
    int count = 0;
    int max_tasks = 4096;  // safety limit

    do {
        struct vmi_process proc;
        if (task_walker_read_process(s, current, &proc) < 0) {
            fprintf(stderr, "[TaskWalker] Failed to read task at 0x%lx\n",
                    current);
            break;
        }

         printf("[TaskWalker] %-6u %-6u %-6u %-16s %-5u %-5u 0x%lx\n",
             proc.pid, proc.tgid, proc.ppid, proc.comm,
               proc.uid, proc.gid, proc.task_addr);

        // Walk to next
        uint64_t next;
        if (read_tasks_next(s, current, &next) < 0) break;

        current = next;
        count++;

        if (count >= max_tasks) {
            fprintf(stderr, "[TaskWalker] Hit task limit (%d), stopping\n",
                    max_tasks);
            break;
        }

    } while (current != s->init_task_addr);

    printf("[TaskWalker] ─────────────────────────────────"
           "──────────────────────\n");
    printf("[TaskWalker] Total processes: %d\n", count);
}

// ──────────────────────────────────────────────
// Public: Find a specific PID in the task list
// ──────────────────────────────────────────────

int task_walker_find_pid(struct vmi_session *s,
                         uint32_t pid,
                         uint64_t *task_addr) {
    if (!s || !task_addr || s->init_task_addr == 0) return -1;

    ensure_offsets_profile_selected();

    uint64_t current = s->init_task_addr;
    int count = 0;

    do {
        uint32_t this_pid;
        if (read_task_field(s, current, active_offsets->pid_offset,
                            &this_pid, sizeof(this_pid)) < 0)
            return -1;

        if (this_pid == pid) {
            *task_addr = current;
            return 0;
        }

        uint64_t next;
        if (read_tasks_next(s, current, &next) < 0) return -1;
        current = next;
        count++;

    } while (current != s->init_task_addr && count < 4096);

    return -1;  // not found
}

// ──────────────────────────────────────────────
// Public: Detect privilege escalation
// Walks the process list and flags any non-init process
// with uid=0 that shouldn't have it. This catches
// setuid(0) attacks from Ring -1.
// ──────────────────────────────────────────────

int task_walker_detect_privilege_escalation(struct vmi_session *s) {
    if (!s || s->init_task_addr == 0) return -1;

    ensure_offsets_profile_selected();

    uint64_t current = s->init_task_addr;
    int detections = 0;
    int count = 0;

    do {
        struct vmi_process proc;
        if (task_walker_read_process(s, current, &proc) < 0)
            break;

        // Skip kernel threads (mm_addr == 0) and init (pid 1)
        if (proc.mm_addr != 0 && proc.pid > 1) {
            // Check for unexpected root credentials
            if (proc.uid == 0) {
                // Read euid to check for setuid escalation
                uint32_t euid = 0;
                if (proc.cred_addr) {
                    vmi_read_virtual(s, s->kernel_pgd,
                                     proc.cred_addr +
                                     active_offsets->cred_euid_offset,
                                     &euid, sizeof(euid));
                }

                if (euid == 0) {
                    printf("[TaskWalker] ⚠ PRIVILEGE ESCALATION DETECTED: "
                           "PID %u (%s) has uid=0, euid=0\n",
                           proc.pid, proc.comm);
                    detections++;

                    // Signal to bridge for cross-layer action
                    bridge_signal_suspicious(proc.pid,
                        "privilege_escalation: unexpected uid=0");
                }
            }
        }

        uint64_t next;
        if (read_tasks_next(s, current, &next) < 0) break;
        current = next;
        count++;

    } while (current != s->init_task_addr && count < 4096);

    return detections;
}
