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

// Phase 21: Semantic Phase Mechanics & Criticality
static void calculate_compressibility(struct vmi_session *s) {
    float elasticity = s->field.elasticity.recovery_elasticity;
    float curvature = s->field.active_basin.local_curvature;
    float flux = s->field.legitimacy_flux;
    float coupling = s->field.local_coupling.upstream_influence + s->field.local_coupling.downstream_influence;
    float criticality = s->field.criticality.propagation_criticality;
    
    float denominator = curvature + flux + coupling + criticality;
    if (denominator < 0.01f) denominator = 0.01f;
    
    s->field.compressibility.execution_compressibility = elasticity / denominator;
}

static void evaluate_metastability(struct vmi_session *s) {
    static float peak_elasticity = 0.0f;
    if (s->field.elasticity.recovery_elasticity > peak_elasticity) {
        peak_elasticity = s->field.elasticity.recovery_elasticity;
    }
    
    s->field.active_basin.metastability_margin = peak_elasticity - s->field.elasticity.recovery_elasticity;
    
    if (s->field.active_basin.metastability_margin > 2.0f && s->field.compressibility.execution_compressibility < 0.5f) {
        s->field.active_basin.metastable = true;
    } else {
        s->field.active_basin.metastable = false;
    }
}

static void update_observer_energy(struct vmi_session *s, float intervention_cost) {
    float recovery_decay_factor = 1.0f;
    if (s->field.elasticity.recovery_elasticity > 1.0f && s->field.active_basin.local_curvature < 0.5f) {
        recovery_decay_factor = 0.95f; // Decay by 5%
    }
    s->field.observer.observer_energy_integral *= recovery_decay_factor;
    s->field.observer.observer_energy_integral += intervention_cost;
}

static float calculate_fingerprint_distance(struct topology_fingerprint *a, struct topology_fingerprint *b) {
    float d_curv = a->curvature - b->curvature;
    float d_flux = a->flux - b->flux;
    float d_ent = a->entropy - b->entropy;
    float d_shear = a->shear - b->shear;
    float d_res = a->resonance - b->resonance;
    
    return (2.0f * d_res * d_res) + (1.5f * d_curv * d_curv) + (1.0f * d_flux * d_flux) + (0.8f * d_ent * d_ent) + (0.5f * d_shear * d_shear);
}

static void evaluate_phase_transition(struct vmi_session *s, enum semantic_phase proposed_next) {
    if (s->field.phase == proposed_next) {
        s->field.phase_state.dwell_epochs = 0;
        return;
    }
    
    s->field.phase_state.prev = s->field.phase;
    s->field.phase_state.next = proposed_next;
    s->field.phase_state.dwell_epochs++;
    
    // Accumulate phase energy while dwelling
    s->field.phase_energy += (s->field.active_basin.local_curvature * s->field.legitimacy_flux);
    
    if (s->field.phase_state.dwell_epochs > 3 || s->field.phase_energy > 5.0f) {
        s->field.phase = proposed_next;
        s->field.phase_state.dwell_epochs = 0;
        s->field.phase_energy = 0.0f;
        printf("[Equilibrium] Phase Transition: %d -> %d\n", s->field.phase_state.prev, s->field.phase_state.next);
    }
}

// Phase 20: Continuous Equilibrium Regulation (Macro-Timescale Slow Path)
void vmi_regulate_equilibrium(struct vmi_session *s) {
    // 1. Attractor inference based on topology scars and current stability
    infer_attractor_type(s);
    
    struct local_basin *basin = &s->field.active_basin;
    
    // Phase 21 Additions:
    calculate_compressibility(s);
    evaluate_metastability(s);
    update_observer_energy(s, 0.0f); // Decay existing observer energy naturally
    
    // 2. Deadzone filtering
    if (basin->local_curvature < s->field.deadzone.curvature_deadzone && 
        basin->local_flux < s->field.deadzone.flux_deadzone &&
        s->field.shear.authority_shear < s->field.deadzone.shear_deadzone) {
        
        // Small fluctuations. Intentionally ignore to prevent chatter.
        evaluate_phase_transition(s, PHASE_ORDERED);
        return;
    }
    
    // 3. Evaluate Semantic Resonance
    float total_resonance = s->field.resonance.transition_resonance + 
                            s->field.resonance.authority_resonance + 
                            s->field.resonance.namespace_resonance;
    
    enum semantic_phase proposed_phase = s->field.phase;
    if (total_resonance > 3.0f) {
        s->field.resonance.resonant_instability = true;
        proposed_phase = PHASE_TURBULENT;
        printf("[Equilibrium] ⚠ RESONANCE DETECTED: Synchronized benign transitions amplifying instability.\n");
    } else {
        s->field.resonance.resonant_instability = false;
        if (basin->attractor == ATTRACTOR_COLLAPSING) {
            proposed_phase = PHASE_COLLAPSED;
        } else if (basin->attractor == ATTRACTOR_PARASITIC) {
            proposed_phase = PHASE_META_STABLE;
        } else {
            proposed_phase = PHASE_TRANSITIONAL;
        }
    }
    
    evaluate_phase_transition(s, proposed_phase);
    
    // 4. Homeostatic Recovery Check
    float destabilization_rate = basin->local_entropy * basin->local_curvature;
    if (s->field.elasticity.recovery_elasticity > destabilization_rate && !s->field.resonance.resonant_instability) {
        printf("[Equilibrium] ↳ Homeostatic Recovery permitted: Elasticity (%.2f) > Destabilization Rate (%.2f). Avoiding intervention.\n", 
               s->field.elasticity.recovery_elasticity, destabilization_rate);
        return;
    }
    
    // 5. Active Stabilization Search (if Homeostasis fails)
    if (basin->attractor == ATTRACTOR_COLLAPSING || basin->attractor == ATTRACTOR_PARASITIC || s->field.resonance.resonant_instability) {
        
        // Phase 21: Metastability observer poisoning check
        if (basin->metastable || s->field.observer.observer_energy_integral > 50.0f) {
            printf("[Equilibrium] ⚠ Metastable/Poisoned System: Bounding interventions strictly to observe-only.\n");
            update_observer_energy(s, 0.5f);
            return;
        }
        
        printf("[Equilibrium] ⚠ Active Regulation Triggered (Phase: %d, Attractor: %d)\n", s->field.phase, basin->attractor);
        
        struct stabilization_chain chains[2];
        chains[0].nr_steps = 1; chains[0].steps[0].action_class = STABILIZE_THROTTLE; chains[0].steps[0].scope = SCOPE_THREAD;
        chains[1].nr_steps = 1; chains[1].steps[0].action_class = STABILIZE_QUARANTINE; chains[1].steps[0].scope = SCOPE_VCPU;
        
        int best_chain_idx = -1;
        float best_minimality = -1.0f;
        
        struct topology_fingerprint current_fp = {
            .curvature = basin->local_curvature,
            .shear = s->field.shear.authority_shear,
            .flux = s->field.legitimacy_flux,
            .entropy = basin->local_entropy,
            .resonance = total_resonance
        };
        
        float dist = calculate_fingerprint_distance(&current_fp, &s->field.control_memory.fingerprint);
        
        for (int i = 0; i < 2; i++) {
            struct counterfactual_result res = vmi_simulate_intervention(s, &chains[i]);
            res.stabilization_energy = calculate_effective_energy(res.stabilization_energy, &s->field.friction);
            
            // Apply memory bias based on fingerprint distance
            if (dist < 1.0f && s->field.control_memory.destabilizing_pattern) {
                res.stabilization_energy *= 1.5f; // Penalize historically destructive paths
            }
            
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
                   
            s->field.control_memory.historical_gain = chains[best_chain_idx].steps[0].projected_stability_gain;
            s->field.control_memory.historical_distortion = chains[best_chain_idx].steps[0].projected_topology_distortion;
            s->field.control_memory.destabilizing_pattern = false;
            s->field.control_memory.fingerprint = current_fp;
            
            update_observer_energy(s, 2.0f);
        } else {
            printf("[Equilibrium] ⚠ WARNING: No optimal regulatory path found. Trusting Homeostasis to avoid observer poisoning.\n");
        }
    }
}
