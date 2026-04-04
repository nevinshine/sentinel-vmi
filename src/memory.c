// src/memory.c — Phase 1: Guest Physical Memory Access
//
// Provides raw memory read/write to the guest via KVM memslots,
// and a 4-level page table walker for GVA → GPA translation.
// This is the primitive that everything above it depends on.
// No guest cooperation. No trust.

#include "sentinel_vmi.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/uio.h>

// x86-64 page table constants
#define PT_ENTRY_SIZE       8
#define PT_ENTRIES          512
#define PT_PRESENT          (1ULL << 0)
#define PT_WRITABLE         (1ULL << 1)
#define PT_PAGESIZE         (1ULL << 7)   // huge page bit
#define PT_ADDR_MASK        0x000FFFFFFFFFF000ULL

// Extract page table indices from a virtual address
#define PML4_INDEX(va)  (((va) >> 39) & 0x1FF)
#define PDPT_INDEX(va)  (((va) >> 30) & 0x1FF)
#define PD_INDEX(va)    (((va) >> 21) & 0x1FF)
#define PT_INDEX(va)    (((va) >> 12) & 0x1FF)
#define PAGE_OFFSET(va) ((va) & 0xFFF)

// ──────────────────────────────────────────────
// GPA → memslot lookup
// ──────────────────────────────────────────────

static struct vmi_memslot *find_memslot(struct vmi_session *s,
                                        uint64_t gpa,
                                        uint64_t *offset) {
    for (int i = 0; i < s->nr_memslots; i++) {
        struct vmi_memslot *slot = &s->memslots[i];
        if (gpa >= slot->guest_phys_addr &&
            gpa < slot->guest_phys_addr + slot->memory_size) {
            if (offset)
                *offset = gpa - slot->guest_phys_addr;
            return slot;
        }
    }
    return NULL;
}

static int read_remote_process(struct vmi_session *s,
                               uint64_t remote_addr,
                               void *buf,
                               size_t size) {
    if (!s || s->qemu_pid <= 0 || !buf || size == 0)
        return -1;

    size_t done = 0;
    while (done < size) {
        struct iovec local_iov = {
            .iov_base = (char *)buf + done,
            .iov_len = size - done,
        };
        struct iovec remote_iov = {
            .iov_base = (void *)(uintptr_t)(remote_addr + done),
            .iov_len = size - done,
        };

        ssize_t n = process_vm_readv(s->qemu_pid,
                                     &local_iov,
                                     1,
                                     &remote_iov,
                                     1,
                                     0);
        if (n <= 0)
            return -1;

        done += (size_t)n;
    }

    return 0;
}

static int write_remote_process(struct vmi_session *s,
                                uint64_t remote_addr,
                                const void *buf,
                                size_t size) {
    if (!s || s->qemu_pid <= 0 || !buf || size == 0)
        return -1;

    size_t done = 0;
    while (done < size) {
        struct iovec local_iov = {
            .iov_base = (void *)((const char *)buf + done),
            .iov_len = size - done,
        };
        struct iovec remote_iov = {
            .iov_base = (void *)(uintptr_t)(remote_addr + done),
            .iov_len = size - done,
        };

        ssize_t n = process_vm_writev(s->qemu_pid,
                                      &local_iov,
                                      1,
                                      &remote_iov,
                                      1,
                                      0);
        if (n <= 0)
            return -1;

        done += (size_t)n;
    }

    return 0;
}

static int read_via_memslots(struct vmi_session *s,
                             uint64_t gpa,
                             void *buf,
                             size_t size) {
    if (!s || !buf || size == 0 || !s->memslots || s->nr_memslots <= 0)
        return -1;

    size_t done = 0;
    while (done < size) {
        uint64_t current_gpa = gpa + done;
        uint64_t offset = 0;
        struct vmi_memslot *slot = find_memslot(s, current_gpa, &offset);
        if (!slot)
            return -1;

        uint64_t available = slot->memory_size - offset;
        size_t chunk = size - done;
        if ((uint64_t)chunk > available)
            chunk = (size_t)available;

        uint64_t host_addr = (uint64_t)(uintptr_t)slot->userspace_addr + offset;
        if (slot->flags & VMI_MEMSLOT_F_REMOTE_PROCESS) {
            if (read_remote_process(s, host_addr, (char *)buf + done, chunk) < 0)
                return -1;
        } else {
            memcpy((char *)buf + done, (void *)(uintptr_t)host_addr, chunk);
        }

        done += chunk;
    }

    return 0;
}

static int write_via_memslots(struct vmi_session *s,
                              uint64_t gpa,
                              const void *buf,
                              size_t size) {
    if (!s || !buf || size == 0 || !s->memslots || s->nr_memslots <= 0)
        return -1;

    size_t done = 0;
    while (done < size) {
        uint64_t current_gpa = gpa + done;
        uint64_t offset = 0;
        struct vmi_memslot *slot = find_memslot(s, current_gpa, &offset);
        if (!slot)
            return -1;

        uint64_t available = slot->memory_size - offset;
        size_t chunk = size - done;
        if ((uint64_t)chunk > available)
            chunk = (size_t)available;

        uint64_t host_addr = (uint64_t)(uintptr_t)slot->userspace_addr + offset;
        if (slot->flags & VMI_MEMSLOT_F_REMOTE_PROCESS) {
            if (write_remote_process(s, host_addr,
                                     (const char *)buf + done, chunk) < 0) {
                return -1;
            }
        } else {
            memcpy((void *)(uintptr_t)host_addr, (const char *)buf + done, chunk);
        }

        done += chunk;
    }

    return 0;
}

// ──────────────────────────────────────────────
// Fallback: Read via /proc/pid/mem or /dev/mem
// Used when memslots aren't populated yet
// ──────────────────────────────────────────────

static int read_via_devmem(uint64_t gpa, void *buf, size_t size) {
    int fd = open("/dev/mem", O_RDONLY);
    if (fd < 0) {
        // /dev/mem may be restricted — this is expected
        return -1;
    }

    if (lseek(fd, (off_t)gpa, SEEK_SET) == (off_t)-1) {
        close(fd);
        return -1;
    }

    ssize_t n = read(fd, buf, size);
    close(fd);
    return (n == (ssize_t)size) ? 0 : -1;
}

// ──────────────────────────────────────────────
// Public: Read guest physical memory
// ──────────────────────────────────────────────

int vmi_read_physical(struct vmi_session *s,
                      uint64_t gpa,
                      void *buf,
                      size_t size) {
    if (!s || !buf || size == 0) return -1;

    // Try memslot-mapped access first
    if (read_via_memslots(s, gpa, buf, size) == 0)
        return 0;

    // Fallback: /dev/mem (requires permissions)
    if (read_via_devmem(gpa, buf, size) == 0)
        return 0;

    fprintf(stderr, "[Memory] Failed to read GPA 0x%lx (size %zu)\n",
            gpa, size);
    return -1;
}

// ──────────────────────────────────────────────
// Public: Write guest physical memory
// ──────────────────────────────────────────────

int vmi_write_physical(struct vmi_session *s,
                       uint64_t gpa,
                       const void *buf,
                       size_t size) {
    if (!s || !buf || size == 0) return -1;

    if (write_via_memslots(s, gpa, buf, size) == 0)
        return 0;

    fprintf(stderr, "[Memory] Failed to write GPA 0x%lx (size %zu)\n",
            gpa, size);
    return -1;
}

// ──────────────────────────────────────────────
// Public: 4-level Page Table Walk (GVA → GPA)
//
// Walks the x86-64 paging hierarchy:
//   CR3 → PML4 → PDPT → PD → PT → Physical Page
//
// Handles 2MB and 1GB huge pages.
// ──────────────────────────────────────────────

int vmi_gva_to_gpa(struct vmi_session *s,
                   uint64_t cr3,
                   uint64_t gva,
                   uint64_t *gpa) {
    if (!s || !gpa) return -1;

    uint64_t pml4_base = cr3 & PT_ADDR_MASK;
    uint64_t entry;

    // Level 4: PML4
    uint64_t pml4e_addr = pml4_base + PML4_INDEX(gva) * PT_ENTRY_SIZE;
    if (vmi_read_physical(s, pml4e_addr, &entry, sizeof(entry)) < 0) {
        fprintf(stderr, "[Memory] PML4 read failed at 0x%lx\n", pml4e_addr);
        return -1;
    }
    if (!(entry & PT_PRESENT)) {
        fprintf(stderr, "[Memory] PML4E not present for GVA 0x%lx\n", gva);
        return -1;
    }

    // Level 3: PDPT
    uint64_t pdpt_base = entry & PT_ADDR_MASK;
    uint64_t pdpte_addr = pdpt_base + PDPT_INDEX(gva) * PT_ENTRY_SIZE;
    if (vmi_read_physical(s, pdpte_addr, &entry, sizeof(entry)) < 0)
        return -1;
    if (!(entry & PT_PRESENT)) return -1;

    // Check for 1GB huge page
    if (entry & PT_PAGESIZE) {
        *gpa = (entry & 0x000FFFFFC0000000ULL) | (gva & 0x3FFFFFFF);
        return 0;
    }

    // Level 2: PD
    uint64_t pd_base = entry & PT_ADDR_MASK;
    uint64_t pde_addr = pd_base + PD_INDEX(gva) * PT_ENTRY_SIZE;
    if (vmi_read_physical(s, pde_addr, &entry, sizeof(entry)) < 0)
        return -1;
    if (!(entry & PT_PRESENT)) return -1;

    // Check for 2MB huge page
    if (entry & PT_PAGESIZE) {
        *gpa = (entry & 0x000FFFFFFFE00000ULL) | (gva & 0x1FFFFF);
        return 0;
    }

    // Level 1: PT
    uint64_t pt_base = entry & PT_ADDR_MASK;
    uint64_t pte_addr = pt_base + PT_INDEX(gva) * PT_ENTRY_SIZE;
    if (vmi_read_physical(s, pte_addr, &entry, sizeof(entry)) < 0)
        return -1;
    if (!(entry & PT_PRESENT)) return -1;

    *gpa = (entry & PT_ADDR_MASK) | PAGE_OFFSET(gva);
    return 0;
}

// ──────────────────────────────────────────────
// Public: Read guest virtual memory
// Translates GVA → GPA then reads. Handles page boundaries.
// ──────────────────────────────────────────────

int vmi_read_virtual(struct vmi_session *s,
                     uint64_t cr3,
                     uint64_t gva,
                     void *buf,
                     size_t size) {
    if (!s || !buf || size == 0) return -1;

    size_t bytes_read = 0;
    uint8_t *out = (uint8_t *)buf;

    while (bytes_read < size) {
        // How many bytes left on this page?
        size_t page_remaining = VMI_PAGE_SIZE - (gva & (VMI_PAGE_SIZE - 1));
        size_t chunk = size - bytes_read;
        if (chunk > page_remaining)
            chunk = page_remaining;

        // Translate this page
        uint64_t gpa;
        if (vmi_gva_to_gpa(s, cr3, gva, &gpa) < 0)
            return -1;

        // Read the chunk
        if (vmi_read_physical(s, gpa, out + bytes_read, chunk) < 0)
            return -1;

        bytes_read += chunk;
        gva += chunk;
    }

    return 0;
}
