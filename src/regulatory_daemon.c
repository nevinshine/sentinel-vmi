#include "sentinel_vmi.h"
#include <stdio.h>
#include <unistd.h>
#include <stdatomic.h>

// ──────────────────────────────────────────────
// Stage 2C: Adaptive Semantic Scheduler
// ──────────────────────────────────────────────
void regulatory_daemon_loop(struct vmi_session *s) {
    if (!s->numa_zones || s->nr_numa_zones <= 0) return;
    
    printf("[RegulatoryDaemon] Starting adaptive semantic scheduling (NUMA-aware)...\n");
    
    bool events_processed = false;
    
    // Process intra-NUMA rings sequentially (NUMA-aware scheduling)
    for (uint32_t nz = 0; nz < s->nr_numa_zones; nz++) {
        struct numa_zone *zone = &s->numa_zones[nz];
        
        // Skip zone if it's completely collapsed and we need to shed load
        if (s->active_collapse == COLLAPSE_RECONSTRUCTION && zone->budget.reconstruction_cycles == 0) {
            continue;
        }
        
        for (uint32_t i = 0; i < zone->nr_rings; i++) {
            struct sensor_ring *ring = &zone->local_rings[i];
            
            // Hysteretic Epsilon Decay (Daemon acts as congestion controller)
            uint32_t current_eps = atomic_load_explicit(&ring->dynamic_epsilon, memory_order_relaxed);
            if (current_eps > 0) {
                // Decay slowly compared to fast-path burst increments
                uint32_t new_eps = current_eps > 4 ? current_eps - 4 : 0;
                atomic_store_explicit(&ring->dynamic_epsilon, new_eps, memory_order_relaxed);
            }
            
            uint32_t head = atomic_load_explicit(&ring->head, memory_order_relaxed);
            uint32_t tail = atomic_load_explicit(&ring->tail, memory_order_acquire);
            
            while (head != tail) {
                events_processed = true;
                struct semantic_event *ev = &ring->entries[head];
                
                // 1. Evaluate Starvation & Budget Before Reconstruction
                if (zone->budget.reconstruction_cycles == 0) {
                    s->starvation.starvation_score += 10;
                    s->semantic_debt += 5; // We threw away events
                    
                    if (s->starvation.starvation_score > 1000) {
                        s->active_collapse = COLLAPSE_RECONSTRUCTION;
                    }
                    
                    // Tail drop at consumer
                    head = (head + 1) % SENSOR_RING_SIZE;
                    atomic_store_explicit(&ring->head, head, memory_order_release);
                    continue;
                }
                
                // 2. Compute Nonlinear Reconstruction Cost
                uint32_t base_cost = 10;
                uint32_t crossings = 0; // Mock: 0 if local ring, >0 if cross-ring causality
                uint32_t orphan_depth = (ev->causal_id % 7 == 0) ? 2 : 0;
                float confidence_penalty = 1.0f; // Mock
                
                uint32_t cost = base_cost * (1 + crossings * crossings) * (1 + orphan_depth * orphan_depth) * confidence_penalty;
                
                // 3. Deduct from Observability Budget
                if (zone->budget.reconstruction_cycles >= cost) {
                    zone->budget.reconstruction_cycles -= cost;
                } else {
                    zone->budget.reconstruction_cycles = 0;
                }
                
                // 4. Update Pressure States
                zone->pressure.saturation_velocity++; // simplified
                
                printf("[RegulatoryDaemon] Reconstructing edge [Cost: %u]: vCPU %u, CausalID 0x%lx\n",
                       cost, ev->vcpu_id, ev->causal_id);
                
                // 5. Advance the SPSC consumer head
                head = (head + 1) % SENSOR_RING_SIZE;
                atomic_store_explicit(&ring->head, head, memory_order_release);
                
                tail = atomic_load_explicit(&ring->tail, memory_order_acquire);
            }
        }
    }
    
    if (events_processed) {
        printf("[RegulatoryDaemon] Adaptive scheduling cycle complete. Debt: %u, Starvation: %u, Collapse: %d\n",
               s->semantic_debt, s->starvation.starvation_score, s->active_collapse);
    }
}
