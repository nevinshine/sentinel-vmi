#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sentinel_vmi.h"

// Calculate intervention minimality = stability_gain / topology_distortion
static float calculate_minimality(float gain, float distortion) {
    if (distortion <= 0.0f) {
        return gain > 0.0f ? 999.0f : 0.0f; // Infinite minimality if no distortion but positive gain
    }
    return gain / distortion;
}

// Map field entropy, curvature, and flux to projection confidence
static float calculate_projection_confidence(struct semantic_overlay *overlay) {
    float instability_factor = overlay->projected_field.active_basin.local_entropy + 
                               overlay->projected_field.active_basin.local_curvature + 
                               overlay->projected_field.active_basin.local_flux;
                               
    float confidence = 1.0f - (instability_factor * 0.1f);
    if (confidence < 0.1f) confidence = 0.1f;
    if (confidence > 1.0f) confidence = 1.0f;
    return confidence;
}

// Differential overlay simulation for a single candidate
static void simulate_candidate(struct vmi_session *s, struct stabilization_candidate *cand, struct semantic_overlay *overlay) {
    // 1. Initial differential state
    overlay->overlay_epoch = s->field.current_epoch + 1;
    memcpy(&overlay->projected_field, &s->field, sizeof(struct semantic_field));
    
    // 2. Apply hypothetical intervention
    switch (cand->action_class) {
        case STABILIZE_OBSERVE:
            cand->projected_topology_distortion = 0.0f;
            cand->observer_cost = 0.1f;
            cand->topology_recovery_cost = 0.0f;
            cand->reversibility_score = 1.0f;
            overlay->delta_auth_mass = 0.0f;
            overlay->delta_entropy = 0.5f; // Entropy grows slightly if we only observe
            break;
            
        case STABILIZE_QUARANTINE:
            cand->projected_topology_distortion = 2.0f;
            cand->observer_cost = 2.5f;
            cand->topology_recovery_cost = 1.0f;
            cand->reversibility_score = 0.9f;
            overlay->delta_auth_mass = -1.0f;
            overlay->delta_entropy = -2.0f;
            break;
            
        case STABILIZE_FREEZE:
            cand->projected_topology_distortion = 10.0f;
            cand->observer_cost = 10.0f;
            cand->topology_recovery_cost = 8.0f;
            cand->reversibility_score = 0.1f;
            overlay->delta_auth_mass = -10.0f;
            overlay->delta_entropy = -10.0f;
            break;
            
        default:
            cand->projected_topology_distortion = 1.0f;
            cand->observer_cost = 1.0f;
            cand->topology_recovery_cost = 1.0f;
            cand->reversibility_score = 0.5f;
            overlay->delta_auth_mass = -0.5f;
            overlay->delta_entropy = -0.5f;
            break;
    }
    
    // 3. Project new state
    overlay->projected_field.last_authority_mass += overlay->delta_auth_mass;
    if (overlay->projected_field.last_authority_mass < 0.0f) overlay->projected_field.last_authority_mass = 0.0f;
    
    overlay->projected_field.active_basin.local_entropy += overlay->delta_entropy;
    if (overlay->projected_field.active_basin.local_entropy < 0.0f) overlay->projected_field.active_basin.local_entropy = 0.0f;
    
    // Stability gain is essentially how much entropy/volatility we suppressed
    cand->projected_stability_gain = (s->field.active_basin.local_entropy - overlay->projected_field.active_basin.local_entropy);
    if (cand->projected_stability_gain < 0.0f) cand->projected_stability_gain = 0.0f;
    
    cand->intervention_minimality = calculate_minimality(cand->projected_stability_gain, cand->projected_topology_distortion);
    
    // Recovery Integrity: How semantically coherent the topology remains after stabilization
    // If distortion is high and reversibility is low, integrity crashes.
    cand->recovery_integrity = 1.0f - (cand->projected_topology_distortion * (1.0f - cand->reversibility_score) * 0.1f);
    if (cand->recovery_integrity < 0.0f) cand->recovery_integrity = 0.0f;
    
    // Legality Constraints
    if (cand->recovery_integrity < 0.2f) {
        cand->legality = STABILIZATION_DESTRUCTIVE;
    } else if (overlay->projected_field.last_authority_mass < (s->field.last_legitimacy_mass * 0.1f)) {
        cand->legality = STABILIZATION_ILLEGAL; // Violated conservation of legitimate authority
    } else if (cand->intervention_minimality > 2.0f && cand->reversibility_score > 0.8f) {
        cand->legality = STABILIZATION_OPTIMAL;
    } else {
        cand->legality = STABILIZATION_CONSTRAINED;
    }
    
    // Observer Dominance constraint:
    // If observer distortion > topology recovery gain, we MUST reduce force or flag as destructive.
    if (cand->observer_cost > cand->projected_stability_gain + 0.5f && cand->legality != STABILIZATION_ILLEGAL) {
        cand->legality = STABILIZATION_DESTRUCTIVE;
    }
}

// Simulates a chain of interventions using differential overlays
struct counterfactual_result vmi_simulate_intervention(struct vmi_session *s, struct stabilization_chain *chain) {
    struct counterfactual_result res = {0};
    struct semantic_overlay overlay = {0};
    
    res.chain = *chain;
    
    for (size_t i = 0; i < chain->nr_steps; i++) {
        simulate_candidate(s, &res.chain.steps[i], &overlay);
        
        res.chain.cumulative_distortion += res.chain.steps[i].projected_topology_distortion;
        res.chain.cumulative_recovery += res.chain.steps[i].projected_stability_gain;
        
        // If an illegal or highly destructive path is hit, abort chain projection
        if (res.chain.steps[i].legality == STABILIZATION_ILLEGAL) {
            res.projected_state = FIELD_IRRECOVERABLE;
            res.stable = false;
            return res;
        }
    }
    
    res.projected_entropy = overlay.projected_field.active_basin.local_entropy;
    res.projected_flux = overlay.projected_field.active_basin.local_flux;
    res.projected_curvature = overlay.projected_field.active_basin.local_curvature;
    
    float confidence = calculate_projection_confidence(&overlay);
    
    res.stabilization_energy = res.chain.cumulative_distortion;
    
    if (res.projected_entropy < 5.0f && res.chain.cumulative_distortion < s->field.elasticity.recovery_elasticity * confidence) {
        res.projected_state = FIELD_COHERENT;
        res.stable = true;
    } else {
        res.projected_state = FIELD_COLLAPSING;
        res.stable = false;
    }
    
    return res;
}
