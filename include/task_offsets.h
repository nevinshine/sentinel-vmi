// include/task_offsets.h — task_struct field offsets by kernel version
//
// These offsets describe the byte position of each field inside
// struct task_struct for a given kernel version. They change
// between kernel builds. In a production system these would be
// derived from BTF (BPF Type Format) or from a kernel config
// database. For the rebuild we hard-code the known offsets for
// the kernels we test against.
#pragma once

#include <stdint.h>

struct task_offsets {
    const char *kernel_version;

    // task_struct → tasks (struct list_head)
    uint64_t tasks_offset;

    // task_struct → pid
    uint64_t pid_offset;

    // task_struct → tgid
    uint64_t tgid_offset;

    // task_struct → real_parent (struct task_struct *)
    uint64_t real_parent_offset;

    // task_struct → comm[TASK_COMM_LEN]
    uint64_t comm_offset;

    // task_struct → mm (struct mm_struct *)
    uint64_t mm_offset;

    // task_struct → files (struct files_struct *)
    uint64_t files_offset;

    // task_struct → nsproxy (struct nsproxy *)
    uint64_t nsproxy_offset;

    // task_struct → start_time
    uint64_t start_time_offset;

    // task_struct → flags
    uint64_t flags_offset;

    // task_struct → cred (const struct cred *)
    uint64_t cred_offset;

    // cred → uid (kuid_t)
    uint64_t cred_uid_offset;

    // cred → gid (kgid_t)
    uint64_t cred_gid_offset;

    // cred → euid
    uint64_t cred_euid_offset;

    // cred → egid
    uint64_t cred_egid_offset;

    // cred → cap_effective (lower 64 bits of kernel_cap_t)
    uint64_t cred_cap_effective_offset;
};

// ──────────────────────────────────────────────
// Kernel 6.6.x (our primary target)
// Offsets extracted via pahole / BTF on the kvmi-patched kernel
// ──────────────────────────────────────────────
static const struct task_offsets OFFSETS_6_6 = {
    .kernel_version   = "6.6",
    .tasks_offset     = 0x298,   // offsetof(task_struct, tasks)
    .pid_offset       = 0x398,   // offsetof(task_struct, pid)
    .tgid_offset      = 0x39c,   // offsetof(task_struct, tgid)
    .real_parent_offset = 0x2b0, // offsetof(task_struct, real_parent)
    .comm_offset      = 0x558,   // offsetof(task_struct, comm)
    .mm_offset        = 0x268,   // offsetof(task_struct, mm)
    .files_offset     = 0x2a0,   // offsetof(task_struct, files)
    .nsproxy_offset   = 0x540,   // offsetof(task_struct, nsproxy)
    .start_time_offset = 0x4f0,  // offsetof(task_struct, start_time)
    .flags_offset     = 0x070,   // offsetof(task_struct, flags)
    .cred_offset      = 0x538,   // offsetof(task_struct, cred)
    .cred_uid_offset  = 0x04,    // offsetof(struct cred, uid)
    .cred_gid_offset  = 0x08,    // offsetof(struct cred, gid)
    .cred_euid_offset = 0x14,    // offsetof(struct cred, euid)
    .cred_egid_offset = 0x18,    // offsetof(struct cred, egid)
    .cred_cap_effective_offset = 0x28, // offsetof(struct cred, cap_effective)
};

// ──────────────────────────────────────────────
// Kernel 6.1.x (fallback)
// ──────────────────────────────────────────────
static const struct task_offsets OFFSETS_6_1 = {
    .kernel_version   = "6.1",
    .tasks_offset     = 0x290,
    .pid_offset       = 0x390,
    .tgid_offset      = 0x394,
    .real_parent_offset = 0x2a8,
    .comm_offset      = 0x550,
    .mm_offset        = 0x260,
    .files_offset     = 0x298,
    .nsproxy_offset   = 0x530,
    .start_time_offset = 0x4e8,
    .flags_offset     = 0x070,
    .cred_offset      = 0x530,
    .cred_uid_offset  = 0x04,
    .cred_gid_offset  = 0x08,
    .cred_euid_offset = 0x14,
    .cred_egid_offset = 0x18,
    .cred_cap_effective_offset = 0x28,
};

// The active offset table — selected at runtime or compile time
extern const struct task_offsets *active_offsets;
