// include/sentinel_vmi.h — Sentinel VMI shared definitions
#pragma once

#include <stdint.h>
#include <stddef.h>
#include <linux/kvm.h>

// ──────────────────────────────────────────────
// VMI Session — KVM introspection state
// ──────────────────────────────────────────────

#define VMI_MAX_VCPUS       64
#define VMI_PAGE_SIZE       4096
#define VMI_PAGE_SHIFT      12
#define VMI_MEMSLOT_F_REMOTE_PROCESS (1U << 31)

// KVM memslot for guest-physical → host-virtual translation
struct vmi_memslot {
    uint64_t guest_phys_addr;   // GPA start
    uint64_t memory_size;       // slot size in bytes
    void     *userspace_addr;   // host VA mapped
    uint32_t slot;
    uint32_t flags;
};

struct vmi_session {
    int      kvm_fd;                        // /dev/kvm
    int      vm_fd;                         // VM file descriptor
    int      vcpu_fds[VMI_MAX_VCPUS];       // vCPU file descriptors
    int      nr_vcpus;

    // Guest memory map (memslots)
    struct vmi_memslot *memslots;
    int      nr_memslots;

    // Runtime attachment metadata
    int      qemu_pid;                      // target QEMU PID (if discovered)
    int      control_fd;                    // QMP/KVMI control channel fd

    // NPT Guard state
    uint64_t syscall_table_gpa;             // guest-physical addr of sys_call_table
    uint64_t syscall_table_gva;             // guest-virtual addr
    int      npt_armed;                     // 1 if guard is active

    // Kernel profile (Phase 2)
    uint64_t kaslr_offset;                  // KASLR slide
    uint64_t init_task_addr;                // &init_task (GVA)
    uint64_t kernel_pgd;                    // guest CR3 / kernel page table base
};

// ──────────────────────────────────────────────
// Phase 1 — kvmi_setup.c
// ──────────────────────────────────────────────
struct vmi_session *kvmi_setup(const char *vm_name);
void kvmi_teardown(struct vmi_session *session);

// ──────────────────────────────────────────────
// Phase 1 — memory.c
// ──────────────────────────────────────────────
int  vmi_read_physical(struct vmi_session *s,
                       uint64_t gpa,
                       void *buf,
                       size_t size);
int  vmi_write_physical(struct vmi_session *s,
                        uint64_t gpa,
                        const void *buf,
                        size_t size);
int  vmi_gva_to_gpa(struct vmi_session *s,
                    uint64_t cr3,
                    uint64_t gva,
                    uint64_t *gpa);
int  vmi_read_virtual(struct vmi_session *s,
                      uint64_t cr3,
                      uint64_t gva,
                      void *buf,
                      size_t size);

// ──────────────────────────────────────────────
// Phase 2 — task_walker.c
// ──────────────────────────────────────────────

#define TASK_COMM_LEN   16

struct vmi_process {
    uint64_t task_addr;         // GVA of task_struct
    uint32_t pid;
    uint32_t tgid;
    uint32_t uid;
    uint32_t gid;
    char     comm[TASK_COMM_LEN];
    uint64_t mm_addr;           // mm_struct pointer
    uint64_t cred_addr;         // cred struct pointer
};

void task_walker_dump(struct vmi_session *s);
int  task_walker_find_pid(struct vmi_session *s,
                          uint32_t pid,
                          uint64_t *task_addr);
int  task_walker_read_process(struct vmi_session *s,
                              uint64_t task_gva,
                              struct vmi_process *out);
int  task_walker_detect_privilege_escalation(struct vmi_session *s);

// ──────────────────────────────────────────────
// Phase 3 — npt_guard.c / npf_handler.c
// ──────────────────────────────────────────────
int  npt_guard_arm(struct vmi_session *s);
void npt_guard_disarm(struct vmi_session *s);
void npt_guard_handle_events(struct vmi_session *s);

int  npf_handler_init(struct vmi_session *s);
void npf_handler_process(struct vmi_session *s,
                         uint64_t gpa,
                         int write_access);

// ──────────────────────────────────────────────
// Phase 4 — bridge.c
// ──────────────────────────────────────────────
int  bridge_init(void);
void bridge_teardown(void);
void bridge_signal_malicious(uint32_t pid,
                             const char *reason);
void bridge_signal_suspicious(uint32_t pid,
                              const char *reason);
void bridge_flush_alerts(void);
