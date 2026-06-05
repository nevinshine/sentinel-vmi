// src/differential.c — Sentinel VMI Differential Semantic Replay Engine
//
// Detects execution drift and structural mutations across two snapshot
// states by comparing Executable Provenance and Semantic Topology.

#include "sentinel_vmi.h"
#include "task_offsets.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct task_state {
    uint32_t pid;
    uint32_t tgid;
    uint64_t task_addr;
    uint64_t cred_addr;
    uint64_t real_parent_addr;
    uint64_t mm_addr;
    char comm[16];
};

static int collect_tasks(struct vmi_session *s, struct symbol_table *syms, struct task_state **tasks_out, size_t *count_out) {
    uint64_t init_task = symbol_resolve(syms, "init_task");
    if (!init_task) return -1;
    
    size_t capacity = 1024;
    struct task_state *tasks = malloc(capacity * sizeof(struct task_state));
    size_t count = 0;
    
    uint64_t current_task = init_task;
    for (int i = 0; i < 8192; i++) {
        struct task_state t = {0};
        t.task_addr = current_task;
        
        vmi_read_virtual(s, s->kernel_pgd, current_task + active_offsets->pid_offset, &t.pid, 4);
        vmi_read_virtual(s, s->kernel_pgd, current_task + active_offsets->tgid_offset, &t.tgid, 4);
        vmi_read_virtual(s, s->kernel_pgd, current_task + active_offsets->cred_offset, &t.cred_addr, 8);
        vmi_read_virtual(s, s->kernel_pgd, current_task + active_offsets->real_parent_offset, &t.real_parent_addr, 8);
        vmi_read_virtual(s, s->kernel_pgd, current_task + active_offsets->mm_offset, &t.mm_addr, 8);
        vmi_read_virtual(s, s->kernel_pgd, current_task + active_offsets->comm_offset, t.comm, 16);
        t.comm[15] = '\0';
        
        if (count >= capacity) {
            capacity *= 2;
            tasks = realloc(tasks, capacity * sizeof(struct task_state));
        }
        tasks[count++] = t;
        
        uint64_t tasks_next = 0;
        vmi_read_virtual(s, s->kernel_pgd, current_task + active_offsets->tasks_offset, &tasks_next, 8);
        if (!tasks_next) break;
        
        current_task = tasks_next - active_offsets->tasks_offset;
        if (current_task == init_task) break;
    }
    
    *tasks_out = tasks;
    *count_out = count;
    return 0;
}

int vmi_differential_replay(struct vmi_session *session_a, struct vmi_session *session_b, struct symbol_table *syms, struct semantic_transition **out_transitions, size_t *out_count) {
    printf("[Differential] ═══════════════════════════════════════\n");
    printf("[Differential] Starting Differential Semantic Replay\n");
    printf("[Differential] ═══════════════════════════════════════\n");
    
    int anomalies = 0;
    size_t t_capacity = 16;
    struct semantic_transition *transitions = malloc(t_capacity * sizeof(struct semantic_transition));
    size_t t_count = 0;
    
    // 1. Syscall Table Drift (VOLATILITY_STABLE)
    uint64_t sys_call_table = symbol_resolve(syms, "sys_call_table");
    if (sys_call_table) {
        printf("[Differential] Analyzing Syscall Table Drift (VOLATILITY_STABLE)...\n");
        uint64_t nr_syscalls = 335;
        for (uint64_t i = 0; i < nr_syscalls; i++) {
            uint64_t ptr_a = 0, ptr_b = 0;
            vmi_read_virtual(session_a, session_a->kernel_pgd, sys_call_table + (i * 8), &ptr_a, 8);
            vmi_read_virtual(session_b, session_b->kernel_pgd, sys_call_table + (i * 8), &ptr_b, 8);
            
            struct page_walk_result walk_a = {0};
            struct page_walk_result walk_b = {0};
            bool walk_a_ok = vmi_mmu_translate(session_a, session_a->kernel_pgd, ptr_a, &walk_a) == 0;
            bool walk_b_ok = vmi_mmu_translate(session_b, session_b->kernel_pgd, ptr_b, &walk_b) == 0;
            
            bool mmu_drift = false;
            if (walk_a_ok && walk_b_ok) {
                if (walk_a.executable != walk_b.executable || walk_a.writable != walk_b.writable) {
                    mmu_drift = true;
                }
            }
            
            if (ptr_a != ptr_b || mmu_drift) {
                struct executable_provenance prov_a = vmi_check_provenance(session_a, syms, ptr_a);
                struct executable_provenance prov_b = vmi_check_provenance(session_b, syms, ptr_b);
                
                const struct memory_region *src_region = vmi_find_region(session_b, sys_call_table + (i * 8));
                const struct memory_region *tgt_region_a = vmi_find_region(session_a, ptr_a);
                const struct memory_region *tgt_region_b = vmi_find_region(session_b, ptr_b);
                
                if (t_count >= t_capacity) {
                    t_capacity *= 2;
                    transitions = realloc(transitions, t_capacity * sizeof(*transitions));
                }
                
                struct semantic_transition *t = &transitions[t_count++];
                memset(t, 0, sizeof(*t));
                t->expected = VOL_STABLE;
                t->before.source_addr = sys_call_table + (i * 8);
                t->before.target_addr = ptr_a;
                t->before.source_region = src_region;
                t->before.target_region = tgt_region_a;
                t->before.type = EDGE_SYSCALL_TABLE;
                t->before.stability = EDGE_IMMUTABLE;
                
                t->after = t->before;
                t->after.target_addr = ptr_b;
                t->after.target_region = tgt_region_b;
                
                float confidence = 0.0f;
                
                if (ptr_a != ptr_b) {
                    // Syscall table edge retargeted. This is an immutable edge!
                    confidence = 0.99f;
                    snprintf(t->description, sizeof(t->description), "Syscall %lu edge retargeted", i);
                } else if (mmu_drift) {
                    if (tgt_region_a && !tgt_region_a->contract.allow_permission_change) {
                        confidence = 0.99f;
                    } else {
                        confidence = 0.50f;
                    }
                    snprintf(t->description, sizeof(t->description), "Syscall %lu target MMU permission drift", i);
                }
                
                t->confidence_malicious = confidence;
                
                printf("[Differential] ⚠ TEMPORAL DRIFT DETECTED: %s\n", t->description);
                if (ptr_a != ptr_b) {
                    printf("    ↳ State A: 0x%lx (%s)\n", ptr_a, prov_a.symbol_backed ? prov_a.symbol->name : "unbacked");
                    printf("    ↳ State B: 0x%lx (%s)\n", ptr_b, prov_b.symbol_backed ? prov_b.symbol->name : "unbacked");
                } else {
                    printf("    ↳ State A: 0x%lx (Permissions: %c%c%c)\n", ptr_a, walk_a.present?'R':'-', walk_a.writable?'W':'-', walk_a.executable?'X':'-');
                    printf("    ↳ State B: 0x%lx (Permissions: %c%c%c)\n", ptr_b, walk_b.present?'R':'-', walk_b.writable?'W':'-', walk_b.executable?'X':'-');
                }
                
                if (src_region && tgt_region_a && tgt_region_b) {
                    if (tgt_region_a->type != tgt_region_b->type) {
                        printf("    ↳ Execution edge crossed trust boundary: %s -> %s\n", tgt_region_a->name, tgt_region_b->name);
                    }
                }
                
                printf("    ↳ Volatility Expectation: STABLE -> CONFIDENCE MALICIOUS: %.2f\n", confidence);
                anomalies++;
            }
        }
    }
    
    // 2. Task Graph Drift (VOLATILITY_SEMISTABLE)
    printf("[Differential] Analyzing Task Graph Topology (VOLATILITY_SEMISTABLE)...\n");
    struct task_state *tasks_a = NULL;
    struct task_state *tasks_b = NULL;
    size_t count_a = 0, count_b = 0;
    
    if (collect_tasks(session_a, syms, &tasks_a, &count_a) == 0 &&
        collect_tasks(session_b, syms, &tasks_b, &count_b) == 0) {
        
        for (size_t i = 0; i < count_a; i++) {
            struct task_state ta = tasks_a[i];
            for (size_t j = 0; j < count_b; j++) {
                struct task_state tb = tasks_b[j];
                if (ta.pid == tb.pid) {
                    if (ta.cred_addr != tb.cred_addr || ta.real_parent_addr != tb.real_parent_addr || ta.task_addr != tb.task_addr) {
                        if (t_count >= t_capacity) {
                            t_capacity *= 2;
                            transitions = realloc(transitions, t_capacity * sizeof(*transitions));
                        }
                        struct semantic_transition *t = &transitions[t_count++];
                        memset(t, 0, sizeof(*t));
                        t->expected = VOL_SEMISTABLE;
                        
                        if (ta.cred_addr != tb.cred_addr) {
                            t->confidence_malicious = 0.95f;
                            snprintf(t->description, sizeof(t->description), "PID %u (%s) cred mutated", ta.pid, ta.comm);
                            printf("[Differential] ⚠ TEMPORAL DRIFT DETECTED: %s\n", t->description);
                            printf("    ↳ State A: 0x%lx\n", ta.cred_addr);
                            printf("    ↳ State B: 0x%lx\n", tb.cred_addr);
                        } else if (ta.real_parent_addr != tb.real_parent_addr) {
                            t->confidence_malicious = 0.85f;
                            snprintf(t->description, sizeof(t->description), "PID %u (%s) real_parent mutated", ta.pid, ta.comm);
                            printf("[Differential] ⚠ TEMPORAL DRIFT DETECTED: %s\n", t->description);
                            printf("    ↳ State A: 0x%lx\n", ta.real_parent_addr);
                            printf("    ↳ State B: 0x%lx\n", tb.real_parent_addr);
                        } else if (ta.task_addr != tb.task_addr) {
                            t->confidence_malicious = 0.98f;
                            snprintf(t->description, sizeof(t->description), "PID %u (%s) task_struct address changed", ta.pid, ta.comm);
                            printf("[Differential] ⚠ TEMPORAL DRIFT DETECTED: %s\n", t->description);
                            printf("    ↳ State A: 0x%lx\n", ta.task_addr);
                            printf("    ↳ State B: 0x%lx\n", tb.task_addr);
                        }
                        
                        printf("    ↳ Volatility Expectation: SEMISTABLE -> CONFIDENCE MALICIOUS: %.2f\n", t->confidence_malicious);
                        anomalies++;
                    }
                    break;
                }
            }
        }
    }
    
    if (tasks_a) free(tasks_a);
    if (tasks_b) free(tasks_b);
    
    if (anomalies == 0) {
        printf("[Differential] ✓ Temporal Invariants Satisfied. 0 Anomalies.\n");
    } else {
        printf("[Differential] ✗ FAILED: %d Temporal Anomalies Detected!\n", anomalies);
    }
    
    if (out_transitions) *out_transitions = transitions;
    else free(transitions);
    
    if (out_count) *out_count = t_count;
    
    return anomalies;
}
