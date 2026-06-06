#include "sentinel_vmi.h"
#include <stdio.h>
#include <unistd.h>
#include <stdatomic.h>

// ──────────────────────────────────────────────
// Stage 2A: Userspace Regulatory Daemon Mock
// ──────────────────────────────────────────────
void regulatory_daemon_loop(struct vmi_session *s) {
    if (!s->vcpu_rings || s->nr_vcpus <= 0) return;
    
    printf("[RegulatoryDaemon] Starting bounded semantic reconstruction...\n");
    
    // In a real system, this runs pinned to the NUMA node of the vCPUs.
    // For this test harness, we will drain exactly one pass of the queues,
    // rather than looping infinitely, to allow the test suite to progress.
    
    bool events_processed = false;
    
    for (int i = 0; i < s->nr_vcpus; i++) {
        struct sensor_ring *ring = &s->vcpu_rings[i];
        
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
            
            // 1. Sliding Ecological Reconstruction Boundary
            // We do not replay the entire history. We only reconstruct 
            // the lineage fragment relevant to this localized epoch.
            printf("[RegulatoryDaemon] Reconstructing event: vCPU %u, Epoch %lu, CR3 0x%lx, Energy %u, Survivability %d\n",
                   ev->vcpu_id, ev->local_epoch, ev->cr3, ev->semantic_energy, ev->survivability);
            
            // 2. Advance the SPSC consumer head
            head = (head + 1) % SENSOR_RING_SIZE;
            atomic_store_explicit(&ring->head, head, memory_order_release);
            
            // Recompute tail occasionally to batch-drain
            tail = atomic_load_explicit(&ring->tail, memory_order_acquire);
        }
    }
    
    if (events_processed) {
        printf("[RegulatoryDaemon] Sliding window reconstruction complete.\n");
    }
}
