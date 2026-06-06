// tests/test_collapse.c — Sentinel Stage 2C Synthetic Collapse Benchmark
//
// Injects massive adversarial pressure into the SPSC rings to trigger
// multidimensional observability collapse, starving the Regulatory Daemon.

#include "sentinel_vmi.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    printf("\n[Test] ═══════════════════════════════════════\n");
    printf("[Test] Sentinel Stage 2C: Collapse Mechanics\n");
    printf("[Test] ═══════════════════════════════════════\n\n");

    // Initialize mock session with NUMA topology
    struct vmi_session s = {0};
    s.nr_numa_zones = 2;
    s.numa_zones = calloc(s.nr_numa_zones, sizeof(struct numa_zone));
    
    uint32_t global_vcpu_id = 0;
    
    for (uint32_t nz = 0; nz < s.nr_numa_zones; nz++) {
        struct numa_zone *zone = &s.numa_zones[nz];
        zone->numa_id = nz;
        zone->nr_rings = 4;
        zone->local_rings = calloc(zone->nr_rings, sizeof(struct sensor_ring));
        
        // Base budget
        zone->budget.reconstruction_cycles = 5000;
        zone->budget.memory_budget = 1024 * 1024 * 100; // 100MB
        zone->budget.orphan_budget = 1000;
        zone->budget.ambiguity_budget = 5000;
        
        // Seed rings
        for (uint32_t i = 0; i < zone->nr_rings; i++) {
            struct sensor_ring *ring = &zone->local_rings[i];
            
            // Inject synthetic migration storm: 500 events
            uint32_t head = 0;
            uint32_t tail = 500;
            ring->head = head;
            ring->tail = tail;
            
            for (uint32_t e = head; e < tail; e++) {
                struct semantic_event *ev = &ring->entries[e];
                ev->cr3 = 0x1000 + nz * 0x100;
                ev->rip = 0xffffffff81000000 + e * 0x10;
                ev->local_epoch = e;
                ev->vcpu_id = global_vcpu_id;
                ev->event_type = EV_MIGRATION;
                ev->semantic_energy = 100; // Moderate energy
                ev->fence_type = FENCE_NONE; // No fences, pure ambiguity
                ev->causal_id = rotl64(ev->cr3, 17) ^ rotl64(ev->rip, 31) ^ rotl64(ev->local_epoch, 7) ^ rotl64(ev->vcpu_id, 13) ^ ev->event_type;
            }
            global_vcpu_id++;
        }
    }
    
    // Initial State Print
    printf("[Collapse] Initial Observability Budget: %u cycles/zone\n", s.numa_zones[0].budget.reconstruction_cycles);
    
    // Cycle 1: Daemon processes storm
    regulatory_daemon_loop(&s);
    
    // Check collapse
    printf("\n[Collapse] Evaluation:\n");
    printf("[Collapse] NUMA 0 Remaining Budget: %u cycles\n", s.numa_zones[0].budget.reconstruction_cycles);
    printf("[Collapse] NUMA 1 Remaining Budget: %u cycles\n", s.numa_zones[1].budget.reconstruction_cycles);
    printf("[Collapse] Semantic Debt: %u\n", s.semantic_debt);
    printf("[Collapse] Starvation Score: %u\n", s.starvation.starvation_score);
    
    if (s.active_collapse == COLLAPSE_RECONSTRUCTION) {
        printf("[Collapse] Result: SUCCESS (Daemon triggered graceful RECONSTRUCTION COLLAPSE under pressure).\n");
    } else {
        printf("[Collapse] Result: FAILED (Daemon failed to shed load or starve appropriately).\n");
        return 1;
    }
    
    // Cleanup
    for (uint32_t nz = 0; nz < s.nr_numa_zones; nz++) {
        free(s.numa_zones[nz].local_rings);
    }
    free(s.numa_zones);

    return 0;
}
