// src/integrity.c — Sentinel VMI Memory Integrity Verification Layer
//
// Implements the Executable Provenance Engine to semantically attest
// the ownership, canonicality, and structural legitimacy of execution
// pointers across the kernel.

#include "sentinel_vmi.h"
#include <stdio.h>
#include <string.h>

// ──────────────────────────────────────────────
// API: Executable Provenance Engine
// ──────────────────────────────────────────────
struct executable_provenance vmi_check_provenance(struct vmi_session *s, struct symbol_table *syms, uint64_t ptr) {
    struct executable_provenance prov = {0};
    
    // 1. Canonicality Check
    prov.canonical = mmu_is_canonical(ptr);
    if (!prov.canonical) {
        prov.classification = PROV_NONCANONICAL;
        return prov;
    }
    
    // 2. Memory mapping check
    // Try to translate the GVA to GPA to see if it's mapped.
    uint64_t gpa;
    if (vmi_gva_to_gpa(s, s->kernel_pgd, ptr, &gpa) < 0) {
        prov.mapped = false;
        prov.classification = PROV_UNMAPPED;
        return prov;
    }
    prov.mapped = true;
    prov.executable = true; // In a full implementation, we'd check the NX bit in the PTE.
    prov.writable = false;  // In a full implementation, we'd check the RW bit in the PTE.
    
    // 3. Symbol Ownership
    uint64_t offset = 0;
    const struct symbol *sym = symbol_reverse_resolve(syms, ptr, &offset);
    if (sym) {
        prov.symbol_backed = true;
        prov.symbol_addr = sym->addr;
        prov.symbol_offset = offset;
        prov.symbol = sym;
    } else {
        prov.symbol_backed = false;
    }
    
    // 4. Region Classification
    const struct memory_region *region = vmi_find_region(s, ptr);
    if (region) {
        if (region->type == REGION_CORE_TEXT) {
            prov.classification = PROV_CORE_TEXT;
        } else if (region->type == REGION_DYNAMIC_EXEC || region->type == REGION_MODULE_CANDIDATE) {
            prov.classification = PROV_MODULE_TEXT; // Or DYNAMIC_EXEC
        } else {
            prov.classification = PROV_UNKNOWN;
        }
    } else {
        if (prov.symbol_backed) {
            prov.classification = PROV_MODULE_TEXT;
        } else {
            prov.classification = PROV_UNKNOWN;
        }
    }
    
    return prov;
}

// ──────────────────────────────────────────────
// API: Syscall Table Validation
// ──────────────────────────────────────────────
int vmi_validate_syscall_table(struct vmi_session *s, struct symbol_table *syms) {
    printf("[Integrity] ═══════════════════════════════════════\n");
    printf("[Integrity] Starting Memory Integrity Attestation\n");
    printf("[Integrity] ═══════════════════════════════════════\n");
    
    uint64_t sys_call_table = symbol_resolve(syms, "sys_call_table");
    if (!sys_call_table) {
        printf("[Integrity] ✗ FAIL: Cannot resolve sys_call_table\n");
        return -1;
    }
    
    // Determine the number of syscalls dynamically
    uint64_t nr_syscalls = 335; // Default for x86_64
    // We could extract NR_syscalls from symbols or BTF later if available
    
    printf("[Integrity] Attesting %lu system calls at 0x%lx...\n", nr_syscalls, sys_call_table);
    
    int anomalies = 0;
    
    for (uint64_t i = 0; i < nr_syscalls; i++) {
        uint64_t syscall_ptr = 0;
        if (vmi_read_virtual(s, s->kernel_pgd, sys_call_table + (i * 8), &syscall_ptr, sizeof(syscall_ptr)) < 0) {
            printf("[Integrity] ✗ FAIL: Could not read syscall %lu\n", i);
            return -1;
        }
        
        // Tier 1: Executable Legitimacy
        struct executable_provenance prov = vmi_check_provenance(s, syms, syscall_ptr);
        enum integrity_score score = INTEGRITY_TRUSTED;
        
        if (prov.classification == PROV_UNMAPPED || prov.classification == PROV_NONCANONICAL) {
            score = INTEGRITY_ANOMALOUS;
        } else if (prov.classification == PROV_MODULE_TEXT) {
            // Syscall table shouldn't typically point directly into a module
            score = INTEGRITY_SUSPICIOUS;
        } else if (prov.classification == PROV_UNKNOWN) {
            score = INTEGRITY_ANOMALOUS;
        }
        
        // Tier 2: Semantic Correctness
        if (score == INTEGRITY_TRUSTED && prov.symbol_backed) {
            bool semantic_match = true;
            
            // Hardcoded semantic expectations for the first few syscalls
            if (i == 0 && !strstr(prov.symbol->name, "read")) semantic_match = false;
            if (i == 1 && !strstr(prov.symbol->name, "write")) semantic_match = false;
            if (i == 2 && !strstr(prov.symbol->name, "open")) semantic_match = false;
            if (i == 3 && !strstr(prov.symbol->name, "close")) semantic_match = false;
            
            // General fallback for others
            if (semantic_match && 
                strncmp(prov.symbol->name, "sys_", 4) != 0 &&
                strncmp(prov.symbol->name, "__x64_sys_", 10) != 0 &&
                strncmp(prov.symbol->name, "__ia32_sys_", 11) != 0 &&
                strncmp(prov.symbol->name, "stub_", 5) != 0 &&
                strncmp(prov.symbol->name, "sys_ni_syscall", 14) != 0) {
                semantic_match = false;
            }
            
            if (!semantic_match) {
                score = INTEGRITY_ANOMALOUS;
            }
        }
        
        // Tier 3: MMU Authority Attestation
        struct page_walk_result walk;
        if (vmi_mmu_translate(s, s->kernel_pgd, syscall_ptr, &walk) == 0) {
            if (!walk.executable) {
                score = INTEGRITY_ANOMALOUS;
                printf("[Integrity] ⚠ MMU INTEGRITY VIOLATION: Syscall %lu target 0x%lx is not executable!\n", i, syscall_ptr);
            }
        }
        
        struct executable_edge edge = {0};
        edge.source_addr = sys_call_table + (i * 8);
        edge.target_addr = syscall_ptr;
        edge.source_region = vmi_find_region(s, edge.source_addr);
        edge.target_region = vmi_find_region(s, edge.target_addr);
        edge.type = EDGE_SYSCALL_TABLE;
        edge.stability = EDGE_IMMUTABLE;
        edge.score = score;
        
        if (score == INTEGRITY_ANOMALOUS) {
            printf("[Integrity] ⚠ ANOMALY DETECTED: Syscall %lu -> 0x%lx\n", i, syscall_ptr);
            if (edge.source_region && edge.target_region) {
                printf("    ↳ Edge crossed semantic boundary: %s -> %s\n", edge.source_region->name, edge.target_region->name);
            }
            if (prov.symbol_backed) {
                printf("    ↳ Resolves to: %s + 0x%lx (Class: %d)\n", prov.symbol->name, prov.symbol_offset, prov.classification);
            } else {
                printf("    ↳ Unbacked by symbols! (Class: %d)\n", prov.classification);
            }
            anomalies++;
        } else if (score == INTEGRITY_SUSPICIOUS) {
            printf("[Integrity] ⚠ SUSPICIOUS: Syscall %lu -> 0x%lx\n", i, syscall_ptr);
            if (edge.source_region && edge.target_region) {
                printf("    ↳ Edge crossed semantic boundary: %s -> %s\n", edge.source_region->name, edge.target_region->name);
            }
            if (prov.symbol_backed) {
                printf("    ↳ Resolves to module/unknown: %s + 0x%lx (Class: %d)\n", prov.symbol->name, prov.symbol_offset, prov.classification);
            }
            anomalies++;
        }
    }
    
    if (anomalies == 0) {
        printf("[Integrity] ✓ Executable Provenance Invariants Satisfied. 0 Anomalies.\n");
    } else {
        printf("[Integrity] ✗ FAILED: %d Integrity Anomalies Detected!\n", anomalies);
    }
    
    return anomalies;
}
