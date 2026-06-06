#include "sentinel_vmi.h"
#include <stdio.h>
#include <unistd.h>
#include <stdatomic.h>
#include <immintrin.h>
#include <string.h>

// ──────────────────────────────────────────────
// Stage 3A: Orchestration Thermodynamics
// ──────────────────────────────────────────────
static uint16_t get_fence_half_life(enum semantic_fence_type fence) {
    switch (fence) {
        case EV_K8S_DEPLOYMENT: return 10;      // Pod/ephemeral (extremely short)
        case EV_K8S_NAMESPACE_MUTATION: return 500; // Medium
        case EV_K8S_SERVICEACCOUNT_SHIFT: return 5000; // Long
        case EV_K8S_EBPF_ATTACH: 
        case EV_BPF_MAP_MUTATION: 
        case EV_BPF_PRIV_ESCALATION: return 10000; // Very long
        default: return 100; // Standard process
    }
}

static q8_8_t get_fence_decay_rate(enum semantic_fence_type fence) {
    switch (fence) {
        case EV_K8S_DEPLOYMENT: return F32_TO_Q8_8(0.50f); // Rapid decay
        case EV_K8S_EBPF_ATTACH:
        case EV_BPF_MAP_MUTATION: return F32_TO_Q8_8(0.999f); // Almost no decay
        default: return F32_TO_Q8_8(0.99f);
    }
}

// ──────────────────────────────────────────────
// Stage 2D/3A: AVX2 Semantic Compression
// ──────────────────────────────────────────────
static void avx2_decay_confidence(struct sparse_edge_store *store) {
    if (!store || store->count == 0) return;
    
    // Vectorized Q8.8 multiplication
    // confidence[i] = (confidence[i] * decay_rate[i]) >> 8
    uint32_t count = store->count;
    uint32_t vec_count = count & ~15; // Process 16 shorts (256-bit) at a time
    
    for (uint32_t i = 0; i < vec_count; i += 16) {
        __m256i conf = _mm256_load_si256((__m256i*)&store->confidence[i]);
        __m256i decay = _mm256_load_si256((__m256i*)&store->decay_rate[i]);
        
        __m256i result = _mm256_mullo_epi16(conf, decay);
        result = _mm256_srli_epi16(result, 8); // Q8.8 shift
        
        _mm256_store_si256((__m256i*)&store->confidence[i], result);
    }
    
    // Tail loop
    for (uint32_t i = vec_count; i < count; i++) {
        store->confidence[i] = (store->confidence[i] * store->decay_rate[i]) >> 8;
    }
}

// ──────────────────────────────────────────────
// Stage 2C/2D: Adaptive Semantic Scheduler
// ──────────────────────────────────────────────
void regulatory_daemon_loop(struct vmi_session *s) {
    if (!s->numa_zones || s->nr_numa_zones <= 0) return;
    
    printf("[RegulatoryDaemon] Starting adaptive semantic scheduling (NUMA-aware/SIMD)...\n");
    
    bool events_processed = false;
    
    // Process intra-NUMA rings sequentially
    for (uint32_t nz = 0; nz < s->nr_numa_zones; nz++) {
        struct numa_zone *zone = &s->numa_zones[nz];
        
        // Stage 2D: Anticipatory Compression
        if (zone->pressure.saturation_velocity > 1000) {
            zone->active_compression = COMPRESS_FENCE_ONLY;
        } else if (zone->pressure.saturation_velocity > 500) {
            zone->active_compression = COMPRESS_PROBABILISTIC;
        } else {
            zone->active_compression = COMPRESS_NONE;
        }
        
        // Stage 2D: Arena Hard Reset Mechanics
        if (s->active_collapse == COLLAPSE_RECONSTRUCTION || 
            (zone->arena.edges && zone->arena.edges->count >= ARENA_MAX_EDGES - 1024)) {
            
            struct collapse_summary summary = {0};
            summary.entropy_density = zone->arena.edges ? zone->arena.edges->count : 0;
            summary.semantic_debt_snapshot = s->semantic_debt;
            
            printf("[RegulatoryDaemon] ⚠ HARD ARENA RESET: Emitting collapse summary. Entropy density: %u, Debt: %u\n",
                   summary.entropy_density, summary.semantic_debt_snapshot);
                   
            if (zone->arena.edges) {
                zone->arena.edges->count = 0; // Pure bump pointer reset (Topological amnesia)
            }
            s->active_collapse = COLLAPSE_NONE; // Recover
            zone->budget.reconstruction_cycles = 5000; // Refill
        }
        
        // Decay existing topology confidence
        if (zone->arena.edges) {
            avx2_decay_confidence(zone->arena.edges);
        }
        
        for (uint32_t i = 0; i < zone->nr_rings; i++) {
            struct sensor_ring *ring = &zone->local_rings[i];
            
            uint32_t current_eps = atomic_load_explicit(&ring->dynamic_epsilon, memory_order_relaxed);
            if (current_eps > 0) {
                uint32_t new_eps = current_eps > 4 ? current_eps - 4 : 0;
                atomic_store_explicit(&ring->dynamic_epsilon, new_eps, memory_order_relaxed);
            }
            
            uint32_t head = atomic_load_explicit(&ring->head, memory_order_relaxed);
            uint32_t tail = atomic_load_explicit(&ring->tail, memory_order_acquire);
            
            while (head != tail) {
                events_processed = true;
                struct semantic_event *ev = &ring->entries[head];
                
                // Active Compression Shedding
                if (zone->active_compression == COMPRESS_FENCE_ONLY && ev->fence_type == FENCE_NONE) {
                    s->semantic_debt += 2;
                    head = (head + 1) % SENSOR_RING_SIZE;
                    atomic_store_explicit(&ring->head, head, memory_order_release);
                    continue;
                }
                
                if (zone->budget.reconstruction_cycles == 0) {
                    s->starvation.starvation_score += 10;
                    s->semantic_debt += 5; 
                    
                    if (s->starvation.starvation_score > 1000) {
                        s->active_collapse = COLLAPSE_RECONSTRUCTION;
                    }
                    
                    head = (head + 1) % SENSOR_RING_SIZE;
                    atomic_store_explicit(&ring->head, head, memory_order_release);
                    continue;
                }
                
                uint32_t base_cost = 10;
                uint32_t crossings = 0; 
                uint32_t orphan_depth = (ev->causal_id % 7 == 0) ? 2 : 0;
                float confidence_penalty = 1.0f; 
                
                uint32_t cost = base_cost * (1 + crossings * crossings) * (1 + orphan_depth * orphan_depth) * confidence_penalty;
                
                if (zone->budget.reconstruction_cycles >= cost) {
                    zone->budget.reconstruction_cycles -= cost;
                } else {
                    zone->budget.reconstruction_cycles = 0;
                }
                
                zone->pressure.saturation_velocity++;
                
                // Stage 2D: Bump pointer allocation into sparse_edge_store
                if (zone->arena.edges && zone->arena.edges->count < ARENA_MAX_EDGES) {
                    uint32_t edge_idx = zone->arena.edges->count++;
                    zone->arena.edges->edge_hashes[edge_idx] = ev->causal_id;
                    zone->arena.edges->confidence[edge_idx] = F32_TO_Q8_8(1.0f);
                    zone->arena.edges->decay_rate[edge_idx] = get_fence_decay_rate(ev->fence_type);
                    zone->arena.edges->half_life[edge_idx] = get_fence_half_life(ev->fence_type);
                    zone->arena.edges->reconstruction_cost[edge_idx] = cost;
                }
                
                // printf omitted for throughput
                
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
