// src/task_walker.c — Phase 2: Semantic Gap Bridging
//
// Parses raw memory into meaningful kernel data structures.
// Walks the task_struct linked list starting from init_task,
// extracts process semantics, tracks ancestry, and detects
// privilege and behavioral anomalies.
//
// This is where raw bytes become intelligence.

#include "sentinel_vmi.h"
#include "task_offsets.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

const struct task_offsets *active_offsets = &OFFSETS_6_6;
static int offsets_initialized = 0;
static struct task_offsets btf_offsets;
static int btf_offsets_valid = 0;

#define MAX_TASK_SNAPSHOT 4096
#define MAX_PRIV_BASELINE 8192
#define DEFAULT_FORK_BOMB_THRESHOLD 256

struct privilege_baseline_entry {
    uint32_t pid;
    uint32_t uid;
    uint32_t euid;
    uint64_t cap_effective;
    char comm[TASK_COMM_LEN];
    unsigned int generation;
    int used;
};

static struct privilege_baseline_entry privilege_baseline[MAX_PRIV_BASELINE];
static unsigned int privilege_generation = 0;

static const char *const legitimate_transition_names[] = {
    "sudo",
    "su",
    "sshd",
    "login",
    "systemd",
    NULL,
};

static const char *const web_tier_names[] = {
    "nginx",
    "apache2",
    "httpd",
    "php-fpm",
    NULL,
};

static const char *const shell_names[] = {
    "sh",
    "bash",
    "dash",
    "zsh",
    NULL,
};

static int string_in_list(const char *value, const char *const *list) {
    if (!value || !list)
        return 0;

    for (int i = 0; list[i] != NULL; i++) {
        if (strncmp(value, list[i], TASK_COMM_LEN) == 0)
            return 1;
    }

    return 0;
}

static int parse_btf_member_line(const char *line,
                                 char *member,
                                 size_t member_sz,
                                 uint64_t *byte_offset) {
    if (!line || !member || member_sz == 0 || !byte_offset)
        return -1;

    const char *q1 = strchr(line, '\'');
    if (!q1)
        return -1;

    const char *q2 = strchr(q1 + 1, '\'');
    if (!q2)
        return -1;

    size_t len = (size_t)(q2 - (q1 + 1));
    if (len == 0 || len >= member_sz)
        return -1;

    memcpy(member, q1 + 1, len);
    member[len] = '\0';

    const char *bits = strstr(q2, "bits_offset=");
    if (!bits)
        return -1;

    bits += strlen("bits_offset=");
    char *endptr = NULL;
    unsigned long long bit_val = strtoull(bits, &endptr, 10);
    if (endptr == bits)
        return -1;

    *byte_offset = (uint64_t)(bit_val / 8ULL);
    return 0;
}

static int try_load_offsets_from_btf(struct task_offsets *out) {
    if (!out)
        return -1;

    if (access("/sys/kernel/btf/vmlinux", R_OK) != 0)
        return -1;

    FILE *fp = popen("bpftool btf dump file /sys/kernel/btf/vmlinux format raw 2>/dev/null",
                     "r");
    if (!fp)
        return -1;

    struct task_offsets tmp = OFFSETS_6_6;
    tmp.kernel_version = "btf-auto";

    enum {
        TASK_SEEN_TASKS = (1 << 0),
        TASK_SEEN_PID = (1 << 1),
        TASK_SEEN_TGID = (1 << 2),
        TASK_SEEN_COMM = (1 << 3),
        TASK_SEEN_MM = (1 << 4),
        TASK_SEEN_CRED = (1 << 5),
    };

    enum {
        CRED_SEEN_UID = (1 << 0),
        CRED_SEEN_GID = (1 << 1),
        CRED_SEEN_EUID = (1 << 2),
    };

    unsigned int task_mask = 0;
    unsigned int cred_mask = 0;
    int in_task = 0;
    int in_cred = 0;

    char line[2048];
    while (fgets(line, sizeof(line), fp) != NULL) {
        if (strstr(line, "STRUCT 'task_struct'")) {
            in_task = 1;
            in_cred = 0;
            continue;
        }
        if (strstr(line, "STRUCT 'cred'")) {
            in_cred = 1;
            in_task = 0;
            continue;
        }

        if (line[0] != '\t' && line[0] != ' ') {
            in_task = 0;
            in_cred = 0;
            continue;
        }

        char member[128];
        uint64_t byte_offset = 0;
        if (parse_btf_member_line(line, member, sizeof(member), &byte_offset) < 0)
            continue;

        if (in_task) {
            if (strcmp(member, "tasks") == 0) {
                tmp.tasks_offset = byte_offset;
                task_mask |= TASK_SEEN_TASKS;
            } else if (strcmp(member, "pid") == 0) {
                tmp.pid_offset = byte_offset;
                task_mask |= TASK_SEEN_PID;
            } else if (strcmp(member, "tgid") == 0) {
                tmp.tgid_offset = byte_offset;
                task_mask |= TASK_SEEN_TGID;
            } else if (strcmp(member, "real_parent") == 0) {
                tmp.real_parent_offset = byte_offset;
            } else if (strcmp(member, "comm") == 0) {
                tmp.comm_offset = byte_offset;
                task_mask |= TASK_SEEN_COMM;
            } else if (strcmp(member, "mm") == 0) {
                tmp.mm_offset = byte_offset;
                task_mask |= TASK_SEEN_MM;
            } else if (strcmp(member, "files") == 0) {
                tmp.files_offset = byte_offset;
            } else if (strcmp(member, "nsproxy") == 0) {
                tmp.nsproxy_offset = byte_offset;
            } else if (strcmp(member, "start_time") == 0) {
                tmp.start_time_offset = byte_offset;
            } else if (strcmp(member, "flags") == 0) {
                tmp.flags_offset = byte_offset;
            } else if (strcmp(member, "cred") == 0) {
                tmp.cred_offset = byte_offset;
                task_mask |= TASK_SEEN_CRED;
            }
        } else if (in_cred) {
            if (strcmp(member, "uid") == 0) {
                tmp.cred_uid_offset = byte_offset;
                cred_mask |= CRED_SEEN_UID;
            } else if (strcmp(member, "gid") == 0) {
                tmp.cred_gid_offset = byte_offset;
                cred_mask |= CRED_SEEN_GID;
            } else if (strcmp(member, "euid") == 0) {
                tmp.cred_euid_offset = byte_offset;
                cred_mask |= CRED_SEEN_EUID;
            } else if (strcmp(member, "egid") == 0) {
                tmp.cred_egid_offset = byte_offset;
            } else if (strcmp(member, "cap_effective") == 0) {
                tmp.cred_cap_effective_offset = byte_offset;
            }
        }
    }

    int rc = pclose(fp);
    if (rc == -1)
        return -1;

    const unsigned int required_task =
        TASK_SEEN_TASKS | TASK_SEEN_PID | TASK_SEEN_TGID |
        TASK_SEEN_COMM | TASK_SEEN_MM | TASK_SEEN_CRED;
    const unsigned int required_cred =
        CRED_SEEN_UID | CRED_SEEN_GID | CRED_SEEN_EUID;

    if ((task_mask & required_task) != required_task ||
        (cred_mask & required_cred) != required_cred) {
        return -1;
    }

    *out = tmp;
    return 0;
}

static const struct task_offsets *select_offsets_profile(const char *kernel_version) {
    if (!kernel_version || !*kernel_version)
        return NULL;

    if (strstr(kernel_version, "btf")) {
        if (!btf_offsets_valid && try_load_offsets_from_btf(&btf_offsets) == 0)
            btf_offsets_valid = 1;
        return btf_offsets_valid ? &btf_offsets : NULL;
    }

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

    const char *disable_btf = getenv("VMI_DISABLE_BTF_OFFSETS");
    if (!disable_btf || strcmp(disable_btf, "1") != 0) {
        if (task_walker_set_offsets_profile("btf-auto") == 0)
            return;
    }

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

static int snapshot_processes(struct vmi_session *s,
                              struct vmi_process *out,
                              int max_tasks) {
    if (!s || !out || max_tasks <= 0 || s->init_task_addr == 0)
        return -1;

    uint64_t current = s->init_task_addr;
    int count = 0;

    do {
        if (count >= max_tasks)
            break;

        if (task_walker_read_process(s, current, &out[count]) < 0)
            break;

        uint64_t next;
        if (read_tasks_next(s, current, &next) < 0)
            break;

        current = next;
        count++;
    } while (current != s->init_task_addr);

    return count;
}

static int pid_exists(const struct vmi_process *procs, int nr, uint32_t pid) {
    for (int i = 0; i < nr; i++) {
        if (procs[i].pid == pid)
            return 1;
    }
    return 0;
}

static struct vmi_process *find_process_by_pid(struct vmi_process *procs,
                                               int nr,
                                               uint32_t pid) {
    for (int i = 0; i < nr; i++) {
        if (procs[i].pid == pid)
            return &procs[i];
    }
    return NULL;
}

static struct privilege_baseline_entry *find_baseline(uint32_t pid) {
    for (int i = 0; i < MAX_PRIV_BASELINE; i++) {
        if (privilege_baseline[i].used && privilege_baseline[i].pid == pid)
            return &privilege_baseline[i];
    }
    return NULL;
}

static struct privilege_baseline_entry *alloc_baseline(uint32_t pid) {
    for (int i = 0; i < MAX_PRIV_BASELINE; i++) {
        if (!privilege_baseline[i].used) {
            privilege_baseline[i].used = 1;
            privilege_baseline[i].pid = pid;
            privilege_baseline[i].generation = 0;
            privilege_baseline[i].uid = 0;
            privilege_baseline[i].euid = 0;
            privilege_baseline[i].cap_effective = 0;
            privilege_baseline[i].comm[0] = '\0';
            return &privilege_baseline[i];
        }
    }

    // Recycle the oldest baseline entry if table is full.
    int oldest = 0;
    for (int i = 1; i < MAX_PRIV_BASELINE; i++) {
        if (privilege_baseline[i].generation < privilege_baseline[oldest].generation)
            oldest = i;
    }

    privilege_baseline[oldest].used = 1;
    privilege_baseline[oldest].pid = pid;
    privilege_baseline[oldest].generation = 0;
    privilege_baseline[oldest].uid = 0;
    privilege_baseline[oldest].euid = 0;
    privilege_baseline[oldest].cap_effective = 0;
    privilege_baseline[oldest].comm[0] = '\0';
    return &privilege_baseline[oldest];
}

static int is_legitimate_priv_transition(const struct vmi_process *proc) {
    return string_in_list(proc->comm, legitimate_transition_names);
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

    // files_struct pointer
    if (active_offsets->files_offset != 0) {
        (void)read_task_field(s, task_gva, active_offsets->files_offset,
                              &out->files_addr, sizeof(out->files_addr));
    }

    // nsproxy pointer
    if (active_offsets->nsproxy_offset != 0) {
        (void)read_task_field(s, task_gva, active_offsets->nsproxy_offset,
                              &out->nsproxy_addr, sizeof(out->nsproxy_addr));
    }

    // start_time
    if (active_offsets->start_time_offset != 0) {
        (void)read_task_field(s, task_gva, active_offsets->start_time_offset,
                              &out->start_time, sizeof(out->start_time));
    }

    // flags
    if (active_offsets->flags_offset != 0) {
        (void)read_task_field(s, task_gva, active_offsets->flags_offset,
                              &out->flags, sizeof(out->flags));
    }

    // cred pointer
    if (read_task_field(s, task_gva, active_offsets->cred_offset,
                        &out->cred_addr, sizeof(out->cred_addr)) < 0)
        return -1;

    // Read uid/gid from the cred struct
    if (out->cred_addr) {
        (void)vmi_read_virtual(s, s->kernel_pgd,
                               out->cred_addr + active_offsets->cred_uid_offset,
                               &out->uid, sizeof(out->uid));
        (void)vmi_read_virtual(s, s->kernel_pgd,
                               out->cred_addr + active_offsets->cred_gid_offset,
                               &out->gid, sizeof(out->gid));
        (void)vmi_read_virtual(s, s->kernel_pgd,
                               out->cred_addr + active_offsets->cred_euid_offset,
                               &out->euid, sizeof(out->euid));
        if (active_offsets->cred_egid_offset != 0) {
            (void)vmi_read_virtual(s, s->kernel_pgd,
                                   out->cred_addr + active_offsets->cred_egid_offset,
                                   &out->egid, sizeof(out->egid));
        }
        if (active_offsets->cred_cap_effective_offset != 0) {
            (void)vmi_read_virtual(s, s->kernel_pgd,
                                   out->cred_addr + active_offsets->cred_cap_effective_offset,
                                   &out->cap_effective,
                                   sizeof(out->cap_effective));
        }
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
        printf("[TaskWalker] %-6s %-6s %-6s %-16s %-5s %-5s %-10s %-18s\n",
            "PID", "TGID", "PPID", "COMM", "UID", "EUID", "CAP_EFF", "TASK_ADDR");
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

                printf("[TaskWalker] %-6u %-6u %-6u %-16s %-5u %-5u 0x%08lx 0x%lx\n",
                             proc.pid,
                             proc.tgid,
                             proc.ppid,
                             proc.comm,
                             proc.uid,
                             proc.euid,
                             proc.cap_effective,
                             proc.task_addr);

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

    struct vmi_process *procs = calloc(MAX_TASK_SNAPSHOT, sizeof(*procs));
    if (!procs)
        return -1;

    int nr = snapshot_processes(s, procs, MAX_TASK_SNAPSHOT);
    if (nr < 0) {
        free(procs);
        return -1;
    }

    privilege_generation++;
    int detections = 0;

    for (int i = 0; i < nr; i++) {
        struct vmi_process *proc = &procs[i];
        if (proc->pid <= 1 || proc->mm_addr == 0)
            continue;

        struct privilege_baseline_entry *entry = find_baseline(proc->pid);
        if (!entry)
            entry = alloc_baseline(proc->pid);
        if (!entry)
            continue;

        int had_baseline = (entry->generation != 0);
        if (had_baseline) {
            int root_transition = (entry->euid != 0 && proc->euid == 0);
            int caps_expanded = ((proc->cap_effective & ~entry->cap_effective) != 0);

            if (root_transition && !is_legitimate_priv_transition(proc)) {
                char reason[96];
                snprintf(reason, sizeof(reason),
                         "priv_escalation pid=%u comm=%s", proc->pid, proc->comm);
                printf("[TaskWalker] ⚠ PRIV ESCALATION: PID %u (%s) euid %u->%u\n",
                       proc->pid, proc->comm, entry->euid, proc->euid);
                bridge_signal_suspicious(proc->pid, reason);
                detections++;
            }

            if (caps_expanded && !is_legitimate_priv_transition(proc)) {
                char reason[96];
                snprintf(reason, sizeof(reason),
                         "cap_expansion pid=%u comm=%s", proc->pid, proc->comm);
                printf("[TaskWalker] ⚠ CAP EXPANSION: PID %u (%s) 0x%lx->0x%lx\n",
                       proc->pid,
                       proc->comm,
                       entry->cap_effective,
                       proc->cap_effective);
                bridge_signal_suspicious(proc->pid, reason);
                detections++;
            }
        }

        entry->uid = proc->uid;
        entry->euid = proc->euid;
        entry->cap_effective = proc->cap_effective;
        strncpy(entry->comm, proc->comm, sizeof(entry->comm) - 1);
        entry->comm[sizeof(entry->comm) - 1] = '\0';
        entry->generation = privilege_generation;
        entry->used = 1;
    }

    free(procs);
    return detections;
}

int task_walker_detect_orphans(struct vmi_session *s) {
    if (!s || s->init_task_addr == 0)
        return -1;

    ensure_offsets_profile_selected();

    struct vmi_process *procs = calloc(MAX_TASK_SNAPSHOT, sizeof(*procs));
    if (!procs)
        return -1;

    int nr = snapshot_processes(s, procs, MAX_TASK_SNAPSHOT);
    if (nr < 0) {
        free(procs);
        return -1;
    }

    int detections = 0;
    for (int i = 0; i < nr; i++) {
        if (procs[i].ppid <= 1)
            continue;

        if (!pid_exists(procs, nr, procs[i].ppid)) {
            char reason[96];
            snprintf(reason, sizeof(reason),
                     "orphan_process pid=%u ppid=%u", procs[i].pid, procs[i].ppid);
            printf("[TaskWalker] ⚠ ORPHAN: PID %u (%s) missing parent %u\n",
                   procs[i].pid, procs[i].comm, procs[i].ppid);
            bridge_signal_suspicious(procs[i].pid, reason);
            detections++;
        }
    }

    free(procs);
    return detections;
}

int task_walker_detect_fork_bomb(struct vmi_session *s, uint32_t threshold) {
    if (!s || s->init_task_addr == 0)
        return -1;

    ensure_offsets_profile_selected();

    if (threshold == 0)
        threshold = DEFAULT_FORK_BOMB_THRESHOLD;

    struct vmi_process *procs = calloc(MAX_TASK_SNAPSHOT, sizeof(*procs));
    if (!procs)
        return -1;

    int nr = snapshot_processes(s, procs, MAX_TASK_SNAPSHOT);
    if (nr < 0) {
        free(procs);
        return -1;
    }

    int detections = 0;
    for (int i = 0; i < nr; i++) {
        uint32_t parent_pid = procs[i].pid;
        if (parent_pid == 0)
            continue;

        int already_counted = 0;
        for (int k = 0; k < i; k++) {
            if (procs[k].pid == parent_pid) {
                already_counted = 1;
                break;
            }
        }
        if (already_counted)
            continue;

        uint32_t children = 0;
        for (int j = 0; j < nr; j++) {
            if (procs[j].ppid == parent_pid)
                children++;
        }

        if (children >= threshold) {
            char reason[96];
            snprintf(reason, sizeof(reason),
                     "fork_bomb pid=%u children=%u", parent_pid, children);
            printf("[TaskWalker] ⚠ FORK BOMB PATTERN: parent PID %u has %u children\n",
                   parent_pid, children);
            bridge_signal_suspicious(parent_pid, reason);
            detections++;
        }
    }

    free(procs);
    return detections;
}

int task_walker_detect_suspicious_ancestry(struct vmi_session *s) {
    if (!s || s->init_task_addr == 0)
        return -1;

    ensure_offsets_profile_selected();

    struct vmi_process *procs = calloc(MAX_TASK_SNAPSHOT, sizeof(*procs));
    if (!procs)
        return -1;

    int nr = snapshot_processes(s, procs, MAX_TASK_SNAPSHOT);
    if (nr < 0) {
        free(procs);
        return -1;
    }

    int detections = 0;
    for (int i = 0; i < nr; i++) {
        if (!string_in_list(procs[i].comm, shell_names))
            continue;

        if (procs[i].ppid == 0)
            continue;

        struct vmi_process *parent = find_process_by_pid(procs, nr, procs[i].ppid);
        if (!parent)
            continue;

        if (string_in_list(parent->comm, web_tier_names)) {
            char reason[96];
            snprintf(reason, sizeof(reason),
                     "suspicious_ancestry pid=%u parent=%u", procs[i].pid, parent->pid);
            printf("[TaskWalker] ⚠ SUSPICIOUS ANCESTRY: %s(%u) spawned shell %s(%u)\n",
                   parent->comm,
                   parent->pid,
                   procs[i].comm,
                   procs[i].pid);
            bridge_signal_suspicious(procs[i].pid, reason);
            detections++;
        }
    }

    free(procs);
    return detections;
}
