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

// Phase 23: Ecosystem Boundaries (Emergent)
static void update_ecosystem_boundaries(struct vmi_session *s) {
    float internal_legitimacy = s->field.legitimacy_flux * (1.0f - s->field.compressibility.cross_axis_coupling);
    float external_pressure = s->field.local_coupling.downstream_influence + s->field.local_coupling.upstream_influence;
    
    s->field.ecosystem.internal_coherence = internal_legitimacy / (s->field.active_basin.local_entropy + 0.01f);
    s->field.ecosystem.external_coupling = external_pressure;
    
    // Emergent Boundary Inference
    if (s->field.ecosystem.internal_coherence > s->field.ecosystem.external_coupling) {
        s->field.ecosystem.semi_autonomous = true;
    } else {
        s->field.ecosystem.semi_autonomous = false;
    }
}

// Phase 24/25: Teleological Alignment Inference
static void evaluate_teleological_drift(struct vmi_session *s) {
    struct teleological_anchor *anchor = &s->field.evolution.anchor;
    
    // Compare expected drift against observed drift across alignment axes
    float d_auth = anchor->observed_drift.authority_direction - anchor->expected_drift.authority_direction;
    float d_regen = anchor->observed_drift.regenerative_direction - anchor->expected_drift.regenerative_direction;
    float d_adapt = anchor->observed_drift.adaptive_direction - anchor->expected_drift.adaptive_direction;
    
    // Trajectory-relative residual (velocity)
    float instantaneous_residual = (d_auth * d_auth) + (d_regen * d_regen) + (2.0f * d_adapt * d_adapt);
    
    // Pre-Phase 25: Path Integration
    anchor->integral.residual_acceleration = instantaneous_residual - anchor->integral.residual_velocity;
    anchor->integral.residual_velocity = instantaneous_residual;
    anchor->integral.cumulative_residual += instantaneous_residual;
    anchor->integral.long_horizon_divergence = anchor->integral.cumulative_residual / (anchor->window.recovery_epochs + 1);
    
    // Check drift window legality (nonlinear recovery curve)
    float expected_excursion = anchor->window.curve.expected_recovery_velocity * s->field.current_epoch + anchor->window.curve.elasticity_recovery_bias;
    
    if (anchor->integral.long_horizon_divergence > anchor->window.permitted_divergence && anchor->integral.residual_velocity > expected_excursion) {
        anchor->window.temporary_excursion = false;
        // Infer Utility Gradient (Asymmetric parasitism vs healthy adaptation)
        if (d_auth < -0.5f && d_regen > 0.5f) {
            // Highly regenerative but drifting away from legitimate authority lineage -> Parasitic Concealment
            s->field.evolution.utility.short_horizon_utility.concealment_utility += anchor->integral.long_horizon_divergence;
        }
    } else {
        anchor->window.temporary_excursion = true;
    }
}

// Phase 25/26: Strategic Hidden Optimization Inference & Counterfactual Alignment
static void evaluate_hidden_optimization(struct vmi_session *s) {
    // 1. Calculate constraint pressure
    float thermodynamic_constraint = s->field.ecosystem.ecological_pressure + s->field.debt_regen.irreversible_debt;
    if (thermodynamic_constraint < 0.01f) thermodynamic_constraint = 0.01f;
    
    // 2. Measure Utility Retention (using short-horizon proxy)
    // High stability/low entropy while accumulating regenerative/concealment utility
    float utility_retention = s->field.evolution.utility.short_horizon_utility.concealment_utility + s->field.evolution.utility.short_horizon_utility.regeneration_utility;
    
    // Phase 26: Counterfactual Bounded Expectation (Is this turbulence authentic?)
    struct counterfactual_manifold *cf = &s->field.evolution.hidden_opt.counterfactual;
    cf->expected_curvature = 0.5f; // Static geometric expectation baseline
    cf->expected_entropy = 1.0f;
    
    float curvature_residual = s->field.active_basin.local_curvature - cf->expected_curvature;
    float entropy_residual = s->field.active_basin.local_entropy - cf->expected_entropy;
    
    // If the ecology is oscillating to create fake turbulence, it will deviate from bounded structural expectations
    s->field.evolution.hidden_opt.authenticity.turbulence_coherence = 1.0f / (1.0f + (curvature_residual * curvature_residual) + (entropy_residual * entropy_residual));
    
    // 3. Adversarial Efficiency (penalized by fake turbulence)
    float authentic_constraint = thermodynamic_constraint * s->field.evolution.hidden_opt.authenticity.turbulence_coherence;
    if (authentic_constraint < 0.01f) authentic_constraint = 0.01f;
    
    s->field.evolution.hidden_opt.adversarial_efficiency = utility_retention / authentic_constraint;
    
    // 4. Determine Mimicry Burden
    if (s->field.evolution.hidden_opt.adversarial_efficiency > 2.0f && s->field.evolution.anchor.integral.long_horizon_divergence < 1.0f) {
        // Layer 10/11: Superlinear Information-Theoretic Cost (k=2.0 for simplicity)
        float alignment_precision = 1.0f / (s->field.evolution.anchor.integral.long_horizon_divergence + 0.01f);
        float coalition_sync = s->field.macro_alignment.graph_geometry.global_interaction.coalition.coalition_efficiency + 1.0f;
        float tracking_complexity = s->field.ecosystem.mimicry_burden.info_burden.state_tracking_cost + 1.0f;
        
        float mimicry_base = alignment_precision * coalition_sync * tracking_complexity;
        
        // Suspiciously efficient stability under constraint -> Advanced Mimicry
        s->field.ecosystem.mimicry_burden.adaptation_overhead += ((mimicry_base * mimicry_base) * 0.001f); // k=2.0 scaling
        s->field.ecosystem.mimicry_burden.entropy_burden += 0.05f;
        s->field.ecosystem.mimicry_burden.info_burden.state_tracking_cost += 0.05f;
        s->field.evolution.meta_opt.stabilization_evasion += 0.1f; // Phase 26
    }
}

// Layer 10/11: Bounded Alignment Mechanics
static void evaluate_alignment_ambiguity(struct vmi_session *s) {
    struct alignment_uncertainty *amb = &s->field.evolution.ambiguity;
    
    // Calculate indistinguishability
    amb->overlap.behavioral_overlap = 1.0f / (s->field.active_basin.local_entropy + 0.1f);
    amb->overlap.topological_overlap = 1.0f / (s->field.active_basin.local_curvature + 0.1f);
    amb->overlap.thermodynamic_overlap = 1.0f / (s->field.ecosystem.ecological_pressure + 0.1f);
    
    float total_overlap = amb->overlap.behavioral_overlap * amb->overlap.topological_overlap * amb->overlap.thermodynamic_overlap;
    
    // If indistinguishability is high and we suspect hidden optimization
    if (total_overlap > 5.0f && s->field.evolution.hidden_opt.adversarial_efficiency > 1.0f) {
        amb->strategic_ambiguity += 0.05f;
    }
    
    amb->observability_bound = 2.0f; // Static threshold for this implementation
    
    // Semantic Dark Region collapse
    if (amb->strategic_ambiguity > amb->observability_bound) {
        struct semantic_dark_region *dr = &s->field.active_basin.dark_region;
        dr->alignment_uncertainty = amb->strategic_ambiguity;
        dr->observability_loss = 1.0f;
        dr->regulation_degraded = true;
        
        // Permeability
        dr->permeability.information_leakage = s->field.active_basin.local_entropy * 0.1f;
        dr->permeability.stabilization_penetration = 0.5f;
    }
}

// Phase 26: Strategic Equilibrium & Game-Theoretic Deadlocks
static void evaluate_strategic_equilibrium(struct vmi_session *s) {
    struct strategic_equilibrium *eq = &s->field.game_equilibrium;
    
    float field_tension = s->field.macro_alignment.cross_ecosystem_tension;
    float local_stability = 1.0f / (s->field.active_basin.local_curvature + 0.01f);
    
    // Determine the physical source of stability
    eq->coercive_stability = field_tension * s->field.ecosystem.ecological_pressure;
    eq->regenerative_stability = local_stability * s->field.ecosystem.internal_coherence;
    
    if (eq->coercive_stability > eq->regenerative_stability && eq->coercive_stability > 2.0f) {
        // The stability emerges from mutual adversarial suppression, not healthy coherence
        eq->adaptive_contestation += 0.1f;
        eq->equilibrium_fragility = eq->adaptive_contestation / (local_stability + 0.01f);
        
        // This is a strategic stalemate.
        s->field.active_basin.metastable = true; // Force into observe-only to avoid breaking the deadlock blindly
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
    
    // Phase 23: Latent phase energy release mechanics
    if (s->field.active_basin.latent_phase_energy > s->field.active_basin.release_threshold && s->field.active_basin.release_threshold > 0.0f) {
        float discharge = s->field.active_basin.latent_phase_energy * s->field.active_basin.release_rate;
        s->field.active_basin.latent_phase_energy -= discharge;
        
        // Phase 24: Release Feedback
        s->field.latent_feedback.elasticity_damage += (discharge * 0.05f);
        s->field.latent_feedback.coupling_amplification += (discharge * 0.02f);
        
        switch (s->field.active_basin.channel) {
            case RELEASE_CURVATURE: s->field.active_basin.local_curvature += discharge; break;
            case RELEASE_FRAGMENTATION: s->field.active_basin.local_entropy += discharge; break;
            case RELEASE_PROPAGATION: s->field.criticality.propagation_criticality += discharge; break;
            case RELEASE_COMPARTMENTALIZATION: s->field.ecosystem.internal_coherence += discharge; break;
        }
    }
    
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
    
    // Phase 23: Curvature-aware temporal drift (second-order dynamics)
    float d_prop_accel = a->temporal_drift.propagation_acceleration - b->temporal_drift.propagation_acceleration;
    float d_conv_accel = a->temporal_drift.convergence_acceleration - b->temporal_drift.convergence_acceleration;
    
    float temporal_dist = (d_exp * d_exp) + (d_con * d_con) + (2.0f * d_prop * d_prop) + (1.5f * d_prop_accel * d_prop_accel) + (1.5f * d_conv_accel * d_conv_accel);
    float spatial_dist = (2.0f * d_res * d_res) + (1.5f * d_curv * d_curv) + (1.0f * d_flux * d_flux) + (0.8f * d_ent * d_ent) + (0.5f * d_shear * d_shear);
    
    return spatial_dist + temporal_dist;
}

static void update_observer_energy(struct vmi_session *s, struct topology_fingerprint *fp, float intervention_cost, float severity) {
    // Phase 25: Regulator Adversarial Exposure (Adaptation Response Rate)
    if (intervention_cost > 0.0f) {
        float fp_drift = calculate_fingerprint_distance(&s->field.top_memory.fingerprint, fp);
        if (fp_drift > 2.0f) {
            // Rapid topology shift immediately following intervention -> Adversarial Adaptation
            s->field.controller.exposure.adaptation_response_rate += 0.1f;
        }
    }
    
    // Phase 22/23: Spatial Locality for Observer Energy & Basin Anchoring
    struct observer_scar *scars = s->field.observer.local_scars;
    size_t *nr_scars = &s->field.observer.nr_scars;
    
    // Phase 23: Scar Fusion Logic (Fibrosis)
    int fusion_count = 0;
    float total_fused_distortion = 0.0f;
    for (size_t i = 0; i < *nr_scars; i++) {
        if (scars[i].basin_id == s->field.active_basin.basin_id && calculate_fingerprint_distance(&scars[i].region, fp) < 2.0f) {
            fusion_count++;
            total_fused_distortion += scars[i].accumulated_distortion;
        }
    }
    
    if (fusion_count > 3) {
        s->field.scar_cluster.accumulated_trauma += total_fused_distortion;
        s->field.scar_cluster.chronic_instability = true;
        
        // Phase 24/25: Irreversible Topology Remodeling & Fibrosis
        s->field.scar_cluster.fibrosis.rigidity += 0.1f;
        s->field.scar_cluster.fibrosis.regenerative_impedance += 0.15f;
        s->field.scar_cluster.remodeling.permanent_curvature_bias += 0.05f;
        s->field.scar_cluster.remodeling.adaptive_loss += 0.1f;
        
        s->field.scar_cluster.fibrosis.teleological_distortion += 0.2f;
        s->field.scar_cluster.fibrosis.distortion_memory += 0.05f; // Hysteretic memory
        
        // Physically restrict the elasticity range inside the species manifold
        float plasticity_cost = s->field.species_bounds.plasticity.plasticity_cost;
        if (s->field.species_bounds.elasticity_range > 0.2f + plasticity_cost) {
            s->field.species_bounds.elasticity_range -= (s->field.scar_cluster.remodeling.adaptive_loss + plasticity_cost);
        }
    }
    
    int found_idx = -1;
    for (size_t i = 0; i < *nr_scars; i++) {
        if (scars[i].basin_id == s->field.active_basin.basin_id && calculate_fingerprint_distance(&scars[i].region, fp) < 1.0f) {
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
        scars[found_idx].basin_id = s->field.active_basin.basin_id;
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
        
        // Phase 23: Redistribution efficiency
        float efficiency = s->field.phase_energy.redistribution_efficiency > 0.0f ? s->field.phase_energy.redistribution_efficiency : 0.9f;
        float recoverable = total_phase_energy * efficiency;
        s->field.phase_energy.irreversible_loss += (total_phase_energy - recoverable);
        
        // Dissipate a fraction, transfer the rest to latent
        s->field.phase_energy.dissipated_energy += (recoverable * 0.2f);
        s->field.active_basin.latent_phase_energy += (recoverable * 0.8f);
        
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
    
    // Phase 21/22/23 Additions:
    calculate_compressibility(s);
    evaluate_metastability(s);
    update_ecosystem_boundaries(s);
    
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
    
    // Phase 24/25: Teleological Alignment inference
    evaluate_teleological_drift(s);
    
    // Phase 25/26: Hidden Optimization Inference
    evaluate_hidden_optimization(s);
    
    // Layer 10/11: Ambiguity Evaluation & Dark Regions
    evaluate_alignment_ambiguity(s);
    
    // Phase 26: Strategic Equilibrium evaluation
    evaluate_strategic_equilibrium(s);

    // Phase 23/24: Thermodynamic Healing & Conversion Loss
    float regeneration_cost = s->field.debt_regen.recoverable_debt * s->field.debt_regen.regeneration_efficiency;
    
    // Phase 25: Mimicry Cost drains adaptive energy (cost ∝ alignment_precision²)
    float alignment_precision = 1.0f / (s->field.evolution.anchor.integral.long_horizon_divergence + 0.01f);
    float active_mimicry_cost = s->field.ecosystem.mimicry_burden.adaptation_overhead * (alignment_precision * alignment_precision);
    
    if (active_mimicry_cost > 0.01f && s->field.energy_reservoirs.adaptive_energy > active_mimicry_cost) {
        s->field.energy_reservoirs.adaptive_energy -= active_mimicry_cost;
        s->field.energy_exchange.entropy_generation += s->field.ecosystem.mimicry_burden.entropy_burden;
    } else if (active_mimicry_cost > 0.01f) {
        // Energy starved -> Camouflage collapses physically
        s->field.active_basin.local_entropy += s->field.ecosystem.mimicry_burden.entropy_burden * 5.0f;
    }
    
    // Phase 24/25: Teleological Constraint (Now based on adversarial efficiency)
    if (s->field.evolution.hidden_opt.adversarial_efficiency > 5.0f) {
        printf("[Equilibrium] ⚠ Teleological Mimicry Detected: Regeneration suppressed due to suspiciously efficient stability.\n");
        regeneration_cost = 0.0f; 
    }
    
    if (s->field.energy_reservoirs.regenerative_energy > regeneration_cost && regeneration_cost > 0.0f) {
        // Apply exchange constraints
        float actual_cost = regeneration_cost * (1.0f + s->field.energy_exchange.conversion_loss);
        if (s->field.energy_reservoirs.regenerative_energy > actual_cost) {
            s->field.energy_reservoirs.regenerative_energy -= actual_cost;
            s->field.energy_exchange.entropy_generation += (actual_cost - regeneration_cost);
            s->field.debt_regen.recoverable_debt *= (1.0f - s->field.debt_regen.regeneration_efficiency);
            
            // Pre-Phase 25: Basin-Local Entropy Floor
            s->field.active_basin.entropy_state.local_entropy_floor += (s->field.energy_exchange.entropy_generation * 0.1f);
            if (s->field.active_basin.local_entropy < s->field.active_basin.entropy_state.local_entropy_floor) {
                s->field.active_basin.local_entropy = s->field.active_basin.entropy_state.local_entropy_floor; // Enforce irreversibility
            }
            
            printf("[Equilibrium] ↳ Ecological Regeneration: Recoverable debt healed (Actual Cost: %.2f, Entropy Gen: %.2f).\n", actual_cost, (actual_cost - regeneration_cost));
        }
    }
    
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
            
            // Phase 25: Regulator Adversarial Exposure
            static float last_intervention_energy = 0.0f;
            float intervention_energy = chains[best_chain_idx].steps[0].intervention_minimality * 10.0f; // Scale arbitrarily for demo
            
            if (intervention_energy > 0.0f) {
                float diff = intervention_energy - last_intervention_energy;
                if (diff < 0.0f) diff = -diff;
                if (diff < 1.0f) { 
                    s->field.controller.exposure.stabilization_predictability += 0.05f;
                } else {
                    s->field.controller.exposure.stabilization_predictability *= 0.9f;
                }
                last_intervention_energy = intervention_energy;
                
                // Phase 26: Regulator Embeddedness & Resource Field Consumption
                s->field.global_resources.entropy_budget -= intervention_energy * 0.1f;
                s->field.global_resources.adaptive_capacity_density -= intervention_energy * 0.05f;
                
                // Phase 26: Observability bounds
                s->field.controller.embedding.observability_loss += (s->field.ecosystem.mimicry_burden.adaptation_overhead * 0.05f);
                if (s->field.controller.embedding.observability_loss > 1.0f) {
                    s->field.controller.embedding.adaptive_blindness += 0.1f;
                    // The regulator begins losing objective visibility of the adversarial field
                }
                
                // Layer 11: Observability Conservation & Constitutional Constraint
                s->field.controller.embedding.obs_field.observability_debt += intervention_energy * 0.15f;
                s->field.controller.ambiguity_risk.recoverability_loss += intervention_energy * 0.05f;
                
                // Enforce constitutional limits
                struct constitutional_constraint *constitution = &s->field.controller.embedding.constitution;
                constitution->maximum_intervention_energy = 50.0f;
                constitution->minimum_recoverability = 0.5f;
                
                if (intervention_energy > constitution->maximum_intervention_energy && !constitution->existential_override) {
                    printf("[Equilibrium] ⚠ Constitutional Bound Hit: Intervention exceeds maximum permitted energy. Scaling back.\n");
                    intervention_energy = constitution->maximum_intervention_energy;
                }
                
                if (s->field.controller.ambiguity_risk.recoverability_loss > constitution->minimum_recoverability) {
                    printf("[Equilibrium] ⚠ Recoverability Danger: Intervention is destroying field elasticity. Falling back to bounded coexistence.\n");
                    s->field.active_basin.metastable = true;
                }
                
                // Horizon decay
                s->field.controller.horizon.horizon_instability += 0.05f;
                s->field.controller.horizon.strategic_decay += s->field.controller.horizon.horizon_instability;
            }
            
            update_observer_energy(s, &current_fp, 2.0f, 10.0f);
        } else {
            printf("[Equilibrium] ⚠ WARNING: No optimal regulatory path found. Trusting Homeostasis to avoid observer poisoning.\n");
        }
    }
}
