// src/ept/ept_mediation.c — Phase 12: Active EPT/NPT Mediation Engine
//
// Governs execution transitions by intercepting VMExits (EPT violations),
// validating them against the semantic topology and volatility contracts,
// and computing probabilistic policy decisions (e.g. MEDIATE_TRAP).

#include "sentinel_vmi.h"
#include <stdio.h>
#include <string.h>
#include <time.h>

struct mediation_decision vmi_handle_ept_violation(struct vmi_session *s, struct symbol_table *syms, uint64_t gpa, uint64_t gva, uint64_t raw_cr3, uint64_t rip, uint32_t vcpu_id, bool is_write, bool is_exec) {
    struct mediation_decision decision = {0};
    decision.action = MEDIATE_ALLOW;
    decision.scope = SCOPE_NONE;
    decision.confidence = 0.0f;
    decision.reason = "Nominal transition";
    
    printf("[Mediation] ═══════════════════════════════════════\n");
    printf("[Mediation] Evaluating EPT Violation at GPA 0x%lx (GVA 0x%lx)\n", gpa, gva);
    printf("[Mediation] Access type: %s %s\n", is_write ? "WRITE" : "", is_exec ? "EXEC" : "");
    printf("[Mediation] Current Semantic Inertia: %.2f (Temp: %.2f)\n", s->field.inertia.topology_resistance, s->field.semantic_temperature);
    
    // 0. Semantic Actor Reconstruction (Phase 13)
    struct semantic_actor *actor = NULL;
    if (task_walker_reconstruct_actor(s, raw_cr3, rip, vcpu_id, &actor) == 0 && actor != NULL) {
        printf("[Mediation] ↳ Actor Identity: PID %u (%s) | Domain: %s\n", actor->identity.pid, actor->comm, 
            actor->domain == ACTOR_KERNEL ? "KERNEL" : "USERSPACE");
        if (actor->is_kthread) {
            printf("[Mediation] ↳ Execution Lineage: Kernel Thread (borrowed active_mm: 0x%lx)\n", actor->active_mm);
        }
    } else {
        printf("[Mediation] ⚠ Failed to reconstruct semantic actor for CR3 0x%lx\n", raw_cr3);
    }

    // 1. Resolve Region
    const struct memory_region *target_region = vmi_find_region(s, gva);
    if (!target_region) {
        printf("[Mediation] ⚠ Unknown Region Target\n");
        decision.action = MEDIATE_TRAP;
        decision.scope = SCOPE_VCPU;
        decision.confidence = 0.85f;
        decision.reason = "Write to unknown semantic region";
        return decision;
    }
    
    // 2. Resolve Symbol
    uint64_t offset = 0;
    const struct symbol *sym = symbol_reverse_resolve(syms, gva, &offset);
    
    printf("[Mediation] ↳ Target Region: %s\n", target_region->name);
    if (sym) {
        printf("[Mediation] ↳ Target Symbol: %s + 0x%lx\n", sym->name, offset);
    }
    
    // 3. Teleological Enforcement based on Contract
    if (is_write) {
        if (target_region->type == REGION_CORE_TEXT || target_region->type == REGION_CORE_RODATA) {
            
            // First Target Lockdown: sys_call_table
            if (sym && strcmp(sym->name, "sys_call_table") == 0) {
                printf("[Mediation] ⚠ ANOMALY: Write attempt to sys_call_table!\n");
                
                // Evaluate Teleological Authority Continuity
                bool has_cap = actor && (actor->authority.capabilities & CAP_KERNEL_MODIFY);
                float composite_legitimacy = 0.0f;
                if (actor) {
                    composite_legitimacy = (actor->authority.legitimacy.structural + actor->authority.legitimacy.provenance) / 2.0f;
                }
                
                if (has_cap && composite_legitimacy >= 0.8f) {
                    // This is legitimately impossible unless we implement trusted dynamic kernel loading,
                    // but it demonstrates the authority calculus correctly.
                    printf("[Mediation] ↳ Authority valid. Actor possesses CAP_KERNEL_MODIFY and legitimacy %.2f >= 0.80.\n", composite_legitimacy);
                    decision.action = MEDIATE_ALLOW;
                    return decision;
                }
                
                printf("[Mediation] ⚠ AUTHORITY DRIFT: Actor lacks valid CAP_KERNEL_MODIFY continuity!\n");
                
                // Decay Authority Legitimacy
                if (actor) {
                    actor->authority.legitimacy.structural *= 0.1f; // Massive collapse
                    actor->authority.legitimacy.behavioral *= 0.5f;
                    
                    enum authority_state prev = actor->authority.state;
                    actor->authority.state = AUTHORITY_REVOKED;
                    
                    // Log the Authority Transition
                    struct authority_transition at = {0};
                    at.id = (uint64_t)time(NULL) ^ (actor->identity.pid << 16) ^ 0xBEEF;
                    at.semantic_epoch = s->semantic_epoch;
                    at.actor = actor->identity;
                    at.capabilities_revoked = CAP_KERNEL_MODIFY | CAP_EXEC_TRANSFORM;
                    at.vector_delta.structural = -0.9f;
                    at.prev_state = prev;
                    at.next_state = actor->authority.state;
                    vmi_log_authority_transition(s, &at);
                    
                    actor->authority.capabilities &= ~at.capabilities_revoked;
                }
                
                // Apply exponential debt decay to integrity dimension
                float old_integrity_debt = 0.0f;
                float integrity = 0.0f;
                float momentum = 0.0f;
                if (actor) {
                    old_integrity_debt = actor->debt.integrity;
                    actor->debt.integrity = actor->debt.integrity * DEBT_DECAY_FACTOR + (-TRUST_DELTA_SYSCALL_DRIFT);
                    actor->semantic_momentum = actor->debt.integrity - old_integrity_debt;
                    integrity = actor->debt.integrity;
                    momentum = actor->semantic_momentum;
                }
                
                printf("[Mediation] ↳ Semantic Debt (Integrity) increased to %.2f (Momentum: %+.2f)\n", integrity, momentum);
                // Thermodynamic Update
                s->field.legitimacy.structural *= 0.5f;
                s->field.capability_pressure += 1.0f;
                s->field.semantic_temperature += 0.5f;
                s->field.momentum.legitimacy_acceleration -= 0.5f;
                
                if (s->field.momentum.legitimacy_acceleration <= -1.0f) {
                    s->field.collapse_hysteresis += 1.0f;
                }
                
                vmi_calculate_thermodynamics(s);
                vmi_project_trajectory(s);
                
                if (s->field.closure_state == FIELD_COLLAPSING || s->field.closure_state == FIELD_IRRECOVERABLE || s->field.collapse_hysteresis >= 3.0f) {
                    printf("[Mediation] ⚠ TRUST COLLAPSE: Field mathematically collapsed. Forcing FREEZE.\n");
                    decision.action = MEDIATE_FREEZE;
                    decision.scope = SCOPE_VM;
                    s->field.observer.intervention_disruption += 10.0f;
                } else {
                    // Phase 19: Counterfactual Stabilization Replay
                    struct stabilization_chain chains[3];
                    memset(chains, 0, sizeof(chains));
                    
                    chains[0].nr_steps = 1; chains[0].steps[0].action_class = STABILIZE_QUARANTINE; chains[0].steps[0].scope = SCOPE_VCPU;
                    chains[1].nr_steps = 1; chains[1].steps[0].action_class = STABILIZE_OBSERVE; chains[1].steps[0].scope = SCOPE_VCPU;
                    chains[2].nr_steps = 1; chains[2].steps[0].action_class = STABILIZE_FREEZE; chains[2].steps[0].scope = SCOPE_VM;
                    
                    int best_chain_idx = -1;
                    float best_minimality = -1.0f;
                    
                    for (int i = 0; i < 3; i++) {
                        struct counterfactual_result res = vmi_simulate_intervention(s, &chains[i]);
                        if (res.chain.steps[0].legality == STABILIZATION_OPTIMAL || res.chain.steps[0].legality == STABILIZATION_CONSTRAINED) {
                            if (res.chain.steps[0].intervention_minimality > best_minimality) {
                                best_minimality = res.chain.steps[0].intervention_minimality;
                                best_chain_idx = i;
                            }
                        }
                    }
                    
                    if (best_chain_idx != -1) {
                        enum stabilization_class chosen_class = chains[best_chain_idx].steps[0].action_class;
                        printf("[Mediation] ↳ Action: Applying %s via counterfactual stabilization (Minimality: %.2f).\n",
                                chosen_class == STABILIZE_QUARANTINE ? "STABILIZE_QUARANTINE" :
                                chosen_class == STABILIZE_FREEZE ? "STABILIZE_FREEZE" : "STABILIZE_OBSERVE",
                                best_minimality);
                                
                        if (chosen_class == STABILIZE_QUARANTINE) {
                            if (actor) actor->authority.state = AUTHORITY_QUARANTINED;
                            decision.action = MEDIATE_INJECT_PF;
                            decision.scope = SCOPE_VCPU;
                            s->field.observer.intervention_disruption += 2.0f;
                        } else if (chosen_class == STABILIZE_FREEZE) {
                            decision.action = MEDIATE_FREEZE;
                            decision.scope = SCOPE_VM;
                            s->field.observer.intervention_disruption += 10.0f;
                        } else {
                            decision.action = MEDIATE_INJECT_PF;
                            decision.scope = SCOPE_VCPU;
                            s->field.observer.intervention_disruption += 0.5f;
                        }
                    } else {
                        printf("[Mediation] ⚠ WARNING: No optimal or constrained stabilization path found! Falling back to global freeze.\n");
                        decision.action = MEDIATE_FREEZE;
                        decision.scope = SCOPE_VM;
                        s->field.observer.intervention_disruption += 10.0f;
                    }
                }
                decision.confidence = 1.0f;
                decision.reason = "Phase 19 Semantic Control Theory";
                
                // Track if Sentinel is dominating the field flux
                if (s->field.observer.intervention_disruption > s->field.trajectory.escape_velocity) {
                    s->field.observer.observer_dominating = true;
                    printf("[Mediation] ⚠ WARNING: Observer intervention is dominating topological flux!\n");
                } else {
                    s->field.observer.observer_dominating = false;
                }
                
                printf("[Mediation] ↳ Policy Decision: %s (Scope: %d, Confidence: %.2f)\n", 
                        decision.action == MEDIATE_FREEZE ? "MEDIATE_FREEZE" : "MEDIATE_INJECT_PF", 
                        decision.scope, decision.confidence);
                return decision;
            }
            
            // General CORE_TEXT/CORE_RODATA violation
            printf("[Mediation] ⚠ ANOMALY: Write attempt to immutable region %s\n", target_region->name);
            s->field.legitimacy.structural *= 0.1f;
            s->field.semantic_temperature += 1.0f;
            s->field.momentum.legitimacy_acceleration -= 1.0f;
            
            if (s->field.momentum.legitimacy_acceleration <= -1.0f) {
                s->field.collapse_hysteresis += 1.0f;
            }
            
            printf("[Mediation] ↳ Temperature increased to %.2f (Acceleration: %.2f)\n", s->field.semantic_temperature, s->field.momentum.legitimacy_acceleration);
            
            vmi_calculate_thermodynamics(s);
            vmi_project_trajectory(s);
            
            struct stabilization_chain chains[3];
            memset(chains, 0, sizeof(chains));
            
            chains[0].nr_steps = 1; chains[0].steps[0].action_class = STABILIZE_QUARANTINE; chains[0].steps[0].scope = SCOPE_VCPU;
            chains[1].nr_steps = 1; chains[1].steps[0].action_class = STABILIZE_OBSERVE; chains[1].steps[0].scope = SCOPE_VCPU;
            chains[2].nr_steps = 1; chains[2].steps[0].action_class = STABILIZE_FREEZE; chains[2].steps[0].scope = SCOPE_VM;
            
            int best_chain_idx = -1;
            float best_minimality = -1.0f;
            
            for (int i = 0; i < 3; i++) {
                struct counterfactual_result res = vmi_simulate_intervention(s, &chains[i]);
                if (res.chain.steps[0].legality == STABILIZATION_OPTIMAL || res.chain.steps[0].legality == STABILIZATION_CONSTRAINED) {
                    if (res.chain.steps[0].intervention_minimality > best_minimality) {
                        best_minimality = res.chain.steps[0].intervention_minimality;
                        best_chain_idx = i;
                    }
                }
            }
            
            if (best_chain_idx != -1) {
                enum stabilization_class chosen_class = chains[best_chain_idx].steps[0].action_class;
                if (chosen_class == STABILIZE_QUARANTINE) {
                    decision.action = MEDIATE_INJECT_PF; decision.scope = SCOPE_VCPU;
                    s->field.observer.intervention_disruption += 2.0f;
                } else if (chosen_class == STABILIZE_FREEZE) {
                    decision.action = MEDIATE_FREEZE; decision.scope = SCOPE_VM;
                    s->field.observer.intervention_disruption += 10.0f;
                } else {
                    decision.action = MEDIATE_INJECT_PF; decision.scope = SCOPE_VCPU;
                    s->field.observer.intervention_disruption += 0.5f;
                }
            } else {
                decision.action = MEDIATE_FREEZE;
                decision.scope = SCOPE_VM;
                s->field.observer.intervention_disruption += 10.0f;
            }
            decision.confidence = 0.95f;
            decision.reason = "Immutable core region write contract violated";
            
            printf("[Mediation] ↳ Policy Decision: %s (Confidence: %.2f)\n", decision.action == MEDIATE_FREEZE ? "MEDIATE_FREEZE" : "MEDIATE_INJECT_PF", decision.confidence);
            return decision;
        }
    }
    
    printf("[Mediation] ✓ Nominal behavior. Policy Decision: MEDIATE_ALLOW\n");
    return decision;
}
