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
    
    // Phase 22: Anisotropic compressibility
    s->field.compressibility.authority_axis = (s->field.elasticity.authority_elasticity) / denominator;
    s->field.compressibility.namespace_axis = (s->field.elasticity.fragmentation_elasticity) / denominator;
    s->field.compressibility.execution_axis = elasticity / denominator;
    s->field.compressibility.cross_axis_coupling = coupling;
}

static void evaluate_metastability(struct vmi_session *s) {
    static float peak_elasticity = 0.0f;
    if (s->field.elasticity.recovery_elasticity > peak_elasticity) {
        peak_elasticity = s->field.elasticity.recovery_elasticity;
    }
    
    s->field.active_basin.metastability_margin = peak_elasticity - s->field.elasticity.recovery_elasticity;
    
    // Phase 22: Latent phase energy as stored strain
    float suppressed_divergence = 1.0f / (s->field.active_basin.local_curvature + 0.01f);
    float reduced_elasticity = s->field.active_basin.metastability_margin;
    float coupling_memory = s->field.compressibility.cross_axis_coupling;
    
    s->field.active_basin.latent_phase_energy = (suppressed_divergence * 0.5f) + (reduced_elasticity * 1.5f) + (coupling_memory * 1.0f);
    
    if (s->field.active_basin.metastability_margin > 2.0f && s->field.compressibility.execution_axis < 0.5f) {
        s->field.active_basin.metastable = true;
    } else {
        s->field.active_basin.metastable = false;
    }
}

static float calculate_fingerprint_distance(struct topology_fingerprint *a, struct topology_fingerprint *b) {
    float d_curv = a->curvature - b->curvature;
    float d_flux = a->flux - b->flux;
    float d_ent = a->entropy - b->entropy;
    float d_shear = a->shear - b->shear;
    float d_res = a->resonance - b->resonance;
    
    // Phase 22: Temporal drift inclusion (spatiotemporal topology distance)
    float d_exp = a->temporal_drift.expansion_rate - b->temporal_drift.expansion_rate;
    float d_con = a->temporal_drift.contraction_rate - b->temporal_drift.contraction_rate;
    float d_prop = a->temporal_drift.propagation_rate - b->temporal_drift.propagation_rate;
    
    float temporal_dist = (d_exp * d_exp) + (d_con * d_con) + (2.0f * d_prop * d_prop);
    float spatial_dist = (2.0f * d_res * d_res) + (1.5f * d_curv * d_curv) + (1.0f * d_flux * d_flux) + (0.8f * d_ent * d_ent) + (0.5f * d_shear * d_shear);
    
    return spatial_dist + temporal_dist;
}

static void update_observer_energy(struct vmi_session *s, struct topology_fingerprint *fp, float intervention_cost, float severity) {
    // Phase 22: Spatial Locality for Observer Energy
    struct observer_scar *scars = s->field.observer.local_scars;
    size_t *nr_scars = &s->field.observer.nr_scars;
    
    int found_idx = -1;
    for (size_t i = 0; i < *nr_scars; i++) {
        if (calculate_fingerprint_distance(&scars[i].region, fp) < 1.0f) {
            found_idx = i;
            break;
        }
    }
    
    if (found_idx != -1) {
        scars[found_idx].accumulated_distortion += intervention_cost;
        scars[found_idx].semantic_severity += severity;
        scars[found_idx].last_epoch = s->field.current_epoch;
    } else {
        // Evict based on semantic priority if full
        if (*nr_scars >= 16) {
            int victim_idx = 0;
            float lowest_priority = 99999.0f;
            for (size_t i = 0; i < 16; i++) {
                float priority = scars[i].semantic_severity - scars[i].recovery_progress;
                if (priority < lowest_priority) {
                    lowest_priority = priority;
                    victim_idx = i;
                }
            }
            found_idx = victim_idx;
        } else {
            found_idx = (*nr_scars)++;
        }
        
        scars[found_idx].region = *fp;
        scars[found_idx].accumulated_distortion = intervention_cost;
        scars[found_idx].recovery_progress = 0.0f;
        scars[found_idx].semantic_severity = severity;
        scars[found_idx].last_epoch = s->field.current_epoch;
    }
    
    // Global integral still tracks overall poisoning
    float recovery_decay_factor = 1.0f;
    if (s->field.elasticity.recovery_elasticity > 1.0f && s->field.active_basin.local_curvature < 0.5f) {
        recovery_decay_factor = 0.95f; // Decay by 5%
        for(size_t i=0; i<*nr_scars; i++) scars[i].recovery_progress += 0.1f;
    }
    s->field.observer.observer_energy_integral *= recovery_decay_factor;
    s->field.observer.observer_energy_integral += intervention_cost;
}

static void evaluate_phase_transition(struct vmi_session *s, enum semantic_phase proposed_next) {
    if (s->field.phase == proposed_next) {
        s->field.phase_state.dwell_epochs = 0;
        return;
    }
    
    s->field.phase_state.prev = s->field.phase;
    s->field.phase_state.next = proposed_next;
    s->field.phase_state.dwell_epochs++;
    
    // Phase 22: Phase Energy Conservation
    float delta_auth = s->field.active_basin.local_curvature * 0.5f;
    float delta_ns = s->field.legitimacy_flux * 0.5f;
    float delta_exec = s->field.active_basin.local_entropy * 0.5f;
    
    s->field.phase_energy.authority_energy += delta_auth;
    s->field.phase_energy.namespace_energy += delta_ns;
    s->field.phase_energy.execution_energy += delta_exec;
    
    float total_phase_energy = s->field.phase_energy.authority_energy + s->field.phase_energy.namespace_energy + s->field.phase_energy.execution_energy;
    
    if (s->field.phase_state.dwell_epochs > 3 || total_phase_energy > 10.0f) {
        s->field.phase = proposed_next;
        s->field.phase_state.dwell_epochs = 0;
        
        // Dissipate a fraction, transfer the rest to latent
        s->field.phase_energy.dissipated_energy += (total_phase_energy * 0.2f);
        s->field.active_basin.latent_phase_energy += (total_phase_energy * 0.8f);
        
        // Reset local active phase tensor
        s->field.phase_energy.authority_energy = 0.0f;
        s->field.phase_energy.namespace_energy = 0.0f;
        s->field.phase_energy.execution_energy = 0.0f;
        
        printf("[Equilibrium] Phase Transition: %d -> %d\n", s->field.phase_state.prev, s->field.phase_state.next);
    }
}

// Phase 20: Continuous Equilibrium Regulation (Macro-Timescale Slow Path)
void vmi_regulate_equilibrium(struct vmi_session *s) {
    // 1. Attractor inference based on topology scars and current stability
    infer_attractor_type(s);
    
    struct local_basin *basin = &s->field.active_basin;
    
    // Phase 21/22 Additions:
    calculate_compressibility(s);
    evaluate_metastability(s);
    
    float total_resonance = s->field.resonance.transition_resonance + 
                            s->field.resonance.authority_resonance + 
                            s->field.resonance.namespace_resonance;
                            
    struct topology_fingerprint current_fp = {
        .curvature = basin->local_curvature,
        .shear = s->field.shear.authority_shear,
        .flux = s->field.legitimacy_flux,
        .entropy = basin->local_entropy,
        .resonance = total_resonance,
        .temporal_drift = { .expansion_rate = 0.1f, .contraction_rate = 0.1f, .propagation_rate = 0.5f }
    };
    
    update_observer_energy(s, &current_fp, 0.0f, 0.0f); // Decay existing observer energy naturally
    
    // Phase 22: Reconfiguration mode inference (differentiating shock vs collapse)
    if (s->field.criticality_cascade.self_amplifying && s->field.criticality_cascade.dissipation_rate < 0.1f) {
        s->field.reconfig_mode = RECONFIG_COLLAPSING;
    } else if (total_resonance > 3.0f && basin->local_entropy < 2.0f) {
        s->field.reconfig_mode = RECONFIG_ADAPTIVE;
        s->field.criticality_cascade.dissipation_rate += 0.5f; // Healthily absorbing the shock
    } else if (s->field.active_basin.latent_phase_energy > 15.0f && basin->local_curvature < 0.5f) {
        s->field.reconfig_mode = RECONFIG_PARASITIC;
    } else {
        s->field.reconfig_mode = RECONFIG_NONE;
    }
    
    // 2. Deadzone filtering
    if (basin->local_curvature < s->field.deadzone.curvature_deadzone && 
        basin->local_flux < s->field.deadzone.flux_deadzone &&
        s->field.shear.authority_shear < s->field.deadzone.shear_deadzone) {
        
        // Small fluctuations. Intentionally ignore to prevent chatter.
        evaluate_phase_transition(s, PHASE_ORDERED);
        return;
    }
    
    // 3. Evaluate Semantic Resonance
    
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
            update_observer_energy(s, &current_fp, 0.5f, 5.0f);
            return;
        }
        
        printf("[Equilibrium] ⚠ Active Regulation Triggered (Phase: %d, Attractor: %d)\n", s->field.phase, basin->attractor);
        
        struct stabilization_chain chains[2];
        chains[0].nr_steps = 1; chains[0].steps[0].action_class = STABILIZE_THROTTLE; chains[0].steps[0].scope = SCOPE_THREAD;
        chains[1].nr_steps = 1; chains[1].steps[0].action_class = STABILIZE_QUARANTINE; chains[1].steps[0].scope = SCOPE_VCPU;
        
        int best_chain_idx = -1;
        float best_minimality = -1.0f;
        
        float dist = calculate_fingerprint_distance(&current_fp, &s->field.top_memory.fingerprint);
        
        for (int i = 0; i < 2; i++) {
            struct counterfactual_result res = vmi_simulate_intervention(s, &chains[i]);
            res.stabilization_energy = calculate_effective_energy(res.stabilization_energy, &s->field.friction);
            
            // Apply memory bias based on fingerprint distance
            if (dist < 1.0f && s->field.top_memory.destabilizing_pattern) {
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
                   
            s->field.int_memory.historical_gain = chains[best_chain_idx].steps[0].projected_stability_gain;
            s->field.int_memory.historical_distortion = chains[best_chain_idx].steps[0].projected_topology_distortion;
            s->field.top_memory.destabilizing_pattern = false;
            s->field.top_memory.fingerprint = current_fp;
            
            update_observer_energy(s, &current_fp, 2.0f, 10.0f);
        } else {
            printf("[Equilibrium] ⚠ WARNING: No optimal regulatory path found. Trusting Homeostasis to avoid observer poisoning.\n");
        }
    }
}
