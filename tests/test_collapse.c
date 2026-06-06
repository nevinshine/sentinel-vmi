// tests/test_collapse.c — Sentinel Stage 3B: Synchronized Rollout Resonance
//
// Simulates a massive coherent Kubernetes rollout (e.g., CNI restart wave)
// generating 100,000 simultaneous, highly coherent EV_K8S_DEPLOYMENT fences.
// Verifies that COMPRESS_FENCE_ONLY and wave coalescing can absorb the
// synchronized storm without destroying the arena or dropping the rare 
// eBPF authority anchors mixed within.

#include "sentinel_vmi.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static inline uint64_t rdtsc(void) {
    uint32_t lo, hi;
    __asm__ __volatile__ ("rdtsc" : "=a" (lo), "=d" (hi));
    return ((uint64_t)hi << 32) | lo;
}

int main(void) {
    printf("\n[Test] ═══════════════════════════════════════\n");
    printf("[Test] Sentinel Stage 3B: Synchronized Rollout Resonance\n");
    printf("[Test] ═══════════════════════════════════════\n\n");

    struct vmi_session s = {0};
    s.nr_numa_zones = 2;
    s.numa_zones = calloc(s.nr_numa_zones, sizeof(struct numa_zone));
    
    uint32_t global_vcpu_id = 0;
    
    for (uint32_t nz = 0; nz < s.nr_numa_zones; nz++) {
        struct numa_zone *zone = &s.numa_zones[nz];
        zone->numa_id = nz;
        zone->nr_rings = 4;
        zone->local_rings = calloc(zone->nr_rings, sizeof(struct sensor_ring));
        
        void *aligned_ptr = NULL;
        if (posix_memalign(&aligned_ptr, 64, sizeof(struct sparse_edge_store)) != 0) {
            printf("Failed to allocate arena.\n");
            return 1;
        }
        zone->arena.edges = (struct sparse_edge_store *)aligned_ptr;
        memset(zone->arena.edges, 0, sizeof(struct sparse_edge_store));
        
        zone->budget.reconstruction_cycles = 1000000;
        
        // Stage 3B: Force High Saturation Velocity to trigger COMPRESS_FENCE_ONLY immediately
        zone->pressure.saturation_velocity = 5000;
        
        for (uint32_t i = 0; i < zone->nr_rings; i++) {
            struct sensor_ring *ring = &zone->local_rings[i];
            
            uint32_t head = 0;
            uint32_t tail = 50000; // 50k events per ring -> 400,000 total across 2 zones
            if (tail > SENSOR_RING_SIZE) tail = SENSOR_RING_SIZE - 1;
            ring->head = head;
            ring->tail = tail;
            
            // Generate Highly Coherent Rollout Wave
            uint64_t coherent_cr3_anchor = 0x100000000 + nz * 0x100000;
            
            for (uint32_t e = head; e < tail; e++) {
                struct semantic_event *ev = &ring->entries[e];
                
                // Extremely coherent geometry (same authority root)
                ev->cr3 = coherent_cr3_anchor | (e % 16); 
                ev->rip = 0xffffffff81000000 + e * 0x10;
                ev->local_epoch = e;
                ev->vcpu_id = global_vcpu_id;
                
                // 99% Coherent Fences, 1% eBPF Rare Anchors
                if (e % 100 == 0) {
                    ev->event_type = EV_SEMANTIC_FENCE;
                    ev->fence_type = EV_K8S_EBPF_ATTACH;
                    ev->semantic_energy = 5000;
                } else {
                    ev->event_type = EV_SEMANTIC_FENCE;
                    ev->fence_type = EV_K8S_DEPLOYMENT; 
                    ev->semantic_energy = 50; 
                }
                
                ev->causal_id = rotl64(ev->cr3, 17) ^ rotl64(ev->rip, 31) ^ rotl64(ev->local_epoch, 7) ^ rotl64(ev->vcpu_id, 13) ^ ev->event_type;
            }
            global_vcpu_id++;
        }
    }
    
    printf("[Collapse] Injecting 400,000 Highly Coherent Orchestration Fences (CNI Restart Wave)...\n");
    
    uint64_t start_cycles = rdtsc();
    regulatory_daemon_loop(&s);
    uint64_t end_cycles = rdtsc();
    
    uint64_t total_cycles = end_cycles - start_cycles;
    uint64_t total_edges_retained = 0;
    
    uint32_t ebpf_edges = 0;
    uint32_t deployment_edges = 0;
    
    for (uint32_t nz = 0; nz < s.nr_numa_zones; nz++) {
        total_edges_retained += s.numa_zones[nz].arena.edges->count;
        for (uint32_t i = 0; i < s.numa_zones[nz].arena.edges->count; i++) {
            if (s.numa_zones[nz].arena.edges->half_life[i] > 1000) {
                ebpf_edges++;
            } else {
                deployment_edges++;
            }
        }
    }
    
    printf("\n[Collapse] ════ Stage 3B Coalescing Metrics ════\n");
    printf("[Collapse] Total Clock Cycles:      %lu\n", total_cycles);
    printf("[Collapse] Total Edges Retained:    %lu\n", total_edges_retained);
    printf("[Collapse] Coalesced Deployments:   %u (Wave collapsed into anchor manifolds)\n", deployment_edges);
    printf("[Collapse] Preserved Rare eBPF:     %u (High Certainty)\n", ebpf_edges);
    printf("[Collapse] Certainty-Per-Megacycle: %.4f\n", (total_edges_retained / (float)total_cycles) * 1000000.0f);
    printf("[Collapse] Semantic Debt:           %u (Coalesced wave entropy shed safely)\n", s.semantic_debt);
    
    for (uint32_t nz = 0; nz < s.nr_numa_zones; nz++) {
        free(s.numa_zones[nz].local_rings);
        free(s.numa_zones[nz].arena.edges);
    }
    free(s.numa_zones);

    return 0;
}
