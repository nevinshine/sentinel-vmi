#include <stdio.h>
#include <stdlib.h>
#include "sentinel_vmi.h"

// Calculate effective stabilization energy (incorporating semantic friction)
static float calculate_effective_energy(float base_energy, struct semantic_friction *friction) {
    float total_friction = friction->authority_friction + friction->namespace_friction + friction->execution_friction;
    return base_energy * (1.0f + total_friction);
}

// Infer attractor type dynamically (Healthy vs Parasitic)
static void infer_attractor_type(struct vmi_session *s) {
    struct local_basin *basin = &s->field.active_basin;
    struct topology_scar *scars = &basin->scars;
    
    // Stable topology (low curvature/entropy) but with deep historical scars -> Parasitic
    if (basin->local_curvature < 0.5f && basin->local_entropy < 1.0f) {
        if (scars->conservation_violation > 0.5f || scars->illegitimate_authority_origin > 0.5f) {
            basin->attractor = ATTRACTOR_PARASITIC;
        } else {
            basin->attractor = ATTRACTOR_HEALTHY;
        }
    } else if (basin->local_entropy > 5.0f && basin->local_curvature > 2.0f) {
        basin->attractor = ATTRACTOR_COLLAPSING;
    } else if (basin->local_entropy > 3.0f) {
        basin->attractor = ATTRACTOR_MALIGNANT;
    } else {
        basin->attractor = ATTRACTOR_DEGRADED;
    }
}

// Phase 20: Continuous Equilibrium Regulation (Macro-Timescale Slow Path)
void vmi_regulate_equilibrium(struct vmi_session *s) {
    // 1. Attractor inference based on topology scars and current stability
    infer_attractor_type(s);
    
    struct local_basin *basin = &s->field.active_basin;
    
    // 2. Deadzone filtering
    if (basin->local_curvature < s->field.deadzone.curvature_deadzone && 
        basin->local_flux < s->field.deadzone.flux_deadzone &&
        s->field.shear.authority_shear < s->field.deadzone.shear_deadzone) {
        
        // Small fluctuations. Intentionally ignore to prevent chatter.
        if (s->field.phase != PHASE_ORDERED) {
            s->field.phase = PHASE_ORDERED;
            printf("[Equilibrium] Field entered PHASE_ORDERED (Deadzones active). Regulation relaxed.\n");
        }
        return;
    }
    
    // 3. Evaluate Semantic Resonance
    float total_resonance = s->field.resonance.transition_resonance + 
                            s->field.resonance.authority_resonance + 
                            s->field.resonance.namespace_resonance;
    
    if (total_resonance > 3.0f) {
        s->field.resonance.resonant_instability = true;
        s->field.phase = PHASE_TURBULENT;
        printf("[Equilibrium] ⚠ RESONANCE DETECTED: Synchronized benign transitions amplifying instability.\n");
    } else {
        s->field.resonance.resonant_instability = false;
        if (basin->attractor == ATTRACTOR_COLLAPSING) {
            s->field.phase = PHASE_COLLAPSED;
        } else if (basin->attractor == ATTRACTOR_PARASITIC) {
            s->field.phase = PHASE_META_STABLE;
        } else {
            s->field.phase = PHASE_TRANSITIONAL;
        }
    }
    
    // 4. Homeostatic Recovery Check
    // If the system's elasticity is strong enough to naturally rebound from the current rate of destabilization, avoid intervention.
    float destabilization_rate = basin->local_entropy * basin->local_curvature;
    if (s->field.elasticity.recovery_elasticity > destabilization_rate && !s->field.resonance.resonant_instability) {
        printf("[Equilibrium] ↳ Homeostatic Recovery permitted: Elasticity (%.2f) > Destabilization Rate (%.2f). Avoiding intervention.\n", 
               s->field.elasticity.recovery_elasticity, destabilization_rate);
        return;
    }
    
    // 5. Active Stabilization Search (if Homeostasis fails)
    if (basin->attractor == ATTRACTOR_COLLAPSING || basin->attractor == ATTRACTOR_PARASITIC || s->field.resonance.resonant_instability) {
        printf("[Equilibrium] ⚠ Active Regulation Triggered (Phase: %d, Attractor: %d)\n", s->field.phase, basin->attractor);
        
        struct stabilization_chain chains[2];
        chains[0].nr_steps = 1; chains[0].steps[0].action_class = STABILIZE_THROTTLE; chains[0].steps[0].scope = SCOPE_THREAD;
        chains[1].nr_steps = 1; chains[1].steps[0].action_class = STABILIZE_QUARANTINE; chains[1].steps[0].scope = SCOPE_VCPU;
        
        int best_chain_idx = -1;
        float best_minimality = -1.0f;
        
        for (int i = 0; i < 2; i++) {
            struct counterfactual_result res = vmi_simulate_intervention(s, &chains[i]);
            
            // Integrate Semantic Friction
            res.stabilization_energy = calculate_effective_energy(res.stabilization_energy, &s->field.friction);
            
            if (res.chain.steps[0].legality == STABILIZATION_OPTIMAL || res.chain.steps[0].legality == STABILIZATION_CONSTRAINED) {
                if (res.chain.steps[0].intervention_minimality > best_minimality) {
                    best_minimality = res.chain.steps[0].intervention_minimality;
                    best_chain_idx = i;
                }
            }
        }
        
        if (best_chain_idx != -1) {
            enum stabilization_class chosen_class = chains[best_chain_idx].steps[0].action_class;
            printf("[Equilibrium] ↳ Minimum-Energy Steering applied: %s (Minimality: %.2f)\n", 
                   chosen_class == STABILIZE_THROTTLE ? "STABILIZE_THROTTLE" : "STABILIZE_QUARANTINE",
                   best_minimality);
                   
            // Update historical memory to avoid recursive observer dominance
            s->field.control_memory.historical_gain = chains[best_chain_idx].steps[0].projected_stability_gain;
            s->field.control_memory.historical_distortion = chains[best_chain_idx].steps[0].projected_topology_distortion;
            s->field.control_memory.destabilizing_pattern = false;
        } else {
            printf("[Equilibrium] ⚠ WARNING: No optimal regulatory path found. Trusting Homeostasis to avoid observer poisoning.\n");
            // DO NOT automatically freeze here. Let Homeostasis try to catch it, or let the EPT fast-path catch explicit violations.
        }
    }
}
