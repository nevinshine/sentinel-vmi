// src/ept/ept_mediation.c — Phase 12: Active EPT/NPT Mediation Engine
//
// Governs execution transitions by intercepting VMExits (EPT violations),
// validating them against the semantic topology and volatility contracts,
// and computing probabilistic policy decisions (e.g. MEDIATE_TRAP).

#include "sentinel_vmi.h"
#include <stdio.h>
#include <string.h>
#include <time.h>

struct mediation_decision vmi_handle_ept_violation(struct vmi_session *s, struct symbol_table *syms, uint64_t gpa, uint64_t gva, uint64_t raw_cr3, uint64_t rip, uint32_t vcpu_id, bool is_write, bool is_exec) {
    struct mediation_decision decision = {0};
    decision.action = MEDIATE_ALLOW;
    decision.scope = SCOPE_NONE;
    decision.confidence = 0.0f;
    decision.reason = "Nominal transition";
    
    // 0. Resolve Actor (Best Effort, Lock-Free if possible)
    struct semantic_actor *actor = NULL;
    task_walker_reconstruct_actor(s, raw_cr3, rip, vcpu_id, &actor);
    
    // 1. Resolve Region & Symbol (Use gpa to avoid unused warning)
    (void)gpa;
    const struct memory_region *target_region = vmi_find_region(s, gva);
    if (!target_region) {
        decision.action = MEDIATE_TRAP;
        decision.scope = SCOPE_VCPU;
        decision.reason = "Write to unknown semantic region";
        return decision;
    }
    
    uint64_t offset = 0;
    const struct symbol *sym = symbol_reverse_resolve(syms, gva, &offset);
    
    // 2. Compute Fast-Path Semantic Energy (Integer Only)
    bool has_cap = actor && (actor->authority.capabilities & CAP_KERNEL_MODIFY);
    uint32_t energy = 0;
    
    if (is_write && (target_region->type == REGION_CORE_TEXT || target_region->type == REGION_CORE_RODATA)) {
        energy += (1 << 8); // Conservation Break
        if (sym && strcmp(sym->name, "sys_call_table") == 0) {
            energy += (1 << 10); // Major structural anomaly
            if (!has_cap) {
                energy += (1 << 12); // Authority break
            }
        }
    }
    
    // Compute Survivability Class
    enum survivability_class surv_class = SURVIVE_DISCARDABLE;
    if (energy >= (1 << 10)) {
        surv_class = SURVIVE_CRITICAL;
    } else if (energy >= (1 << 8)) {
        surv_class = SURVIVE_IMPORTANT;
    } else if (energy > 0) {
        surv_class = SURVIVE_BEST_EFFORT;
    }
    
    // 3. Lossy Compression & Dynamic Backpressure
    if (s->vcpu_rings && s->nr_vcpus > 0) {
        struct sensor_ring *ring = &s->vcpu_rings[vcpu_id % s->nr_vcpus];
        uint32_t epsilon = atomic_load_explicit(&ring->dynamic_epsilon, memory_order_relaxed);
        
        // Semantic forgetting: discard low energy if below epsilon
        if (energy < epsilon && surv_class != SURVIVE_CRITICAL) {
            return decision; // Silent drop
        }
        
        // Advance local semantic epoch
        s->vcpu_epochs[vcpu_id % s->nr_vcpus]++;
        
        uint32_t tail = atomic_load_explicit(&ring->tail, memory_order_relaxed);
        uint32_t head = atomic_load_explicit(&ring->head, memory_order_acquire);
        
        if ((tail + 1) % SENSOR_RING_SIZE == head) {
            // Ring is full: Increase consumer backpressure
            atomic_fetch_add(&ring->dynamic_epsilon, (1 << 6)); // Step up epsilon
            
            // Priority Dropping
            if (surv_class != SURVIVE_CRITICAL) {
                return decision; // Tail drop medium/low energy
            }
            
            // Critical Event: We must survive. Overwrite oldest by bumping head.
            atomic_compare_exchange_strong(&ring->head, &head, (head + 1) % SENSOR_RING_SIZE);
        }
        
        // Enqueue
        struct semantic_event *ev = &ring->entries[tail];
        ev->cr3 = raw_cr3;
        ev->rip = rip;
        ev->local_epoch = s->vcpu_epochs[vcpu_id % s->nr_vcpus];
        ev->vcpu_id = vcpu_id;
        ev->event_type = EV_CONSERVATION_BREAK;
        ev->semantic_energy = energy;
        ev->survivability = surv_class;
        ev->flags = (is_write ? 1 : 0) | (is_exec ? 2 : 0) | (has_cap ? 4 : 0);
        ev->fence_type = FENCE_NONE;
        
        // Stage 2B: Local Causal Clustering Hash
        ev->causal_id = rotl64(ev->cr3, 17) ^
                        rotl64(ev->rip, 31) ^
                        rotl64(ev->local_epoch, 7) ^
                        rotl64(ev->vcpu_id, 13) ^
                        ev->event_type;
        
        atomic_store_explicit(&ring->tail, (tail + 1) % SENSOR_RING_SIZE, memory_order_release);
        
        // Immediate deterministic mitigation in fast-path
        if (energy > (1 << 10)) {
            decision.action = MEDIATE_INJECT_PF;
            decision.scope = SCOPE_VCPU;
            decision.reason = "High energy semantic anomaly (Fast-Path reject)";
            decision.confidence = 0.99f;
            return decision;
        }
    }
    
    return decision;
}
