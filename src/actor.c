// src/actor.c — Phase 13: Semantic Actor Attribution
//
// Converts raw hardware MMU context (CR3) into authoritative
// semantic identity (pid, comm, actor domain) by walking the
// scheduler topology and matching pgd ownership.

#include "sentinel_vmi.h"
#include "task_offsets.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// Mask out lower 12 bits (PCID) and bit 12 (KPTI user page-table marker)
// This normalizes the CR3 to the physical base of the PGD
uint64_t mmu_normalize_cr3(uint64_t raw_cr3) {
    return raw_cr3 & ~0x1FFFULL;
}

void vmi_log_transition(struct vmi_session *s, struct execution_transition *t) {
    if (!s->transition_log) {
        s->transition_capacity = 1024;
        s->transition_log = calloc(s->transition_capacity, sizeof(struct execution_transition));
        s->nr_transitions = 0;
    }
    
    // Epoch advancement decay
    s->field.capability_pressure *= 0.995f;
    if (s->field.semantic_temperature > 0.0f) {
        s->field.semantic_temperature -= 0.01f;
    }
    s->field.inertia.topology_resistance = 1.0f - (s->field.capability_pressure * 0.1f);
    if (s->field.inertia.topology_resistance < 0.1f) s->field.inertia.topology_resistance = 0.1f;
    
    if (s->nr_transitions >= s->transition_capacity) {
        size_t evict = 0;
        for (size_t i = 1; i < s->nr_transitions; i++) {
            if (s->transition_log[i].retention_score < s->transition_log[evict].retention_score) {
                evict = i;
            }
        }
        memcpy(&s->transition_log[evict], t, sizeof(struct execution_transition));
    } else {
        memcpy(&s->transition_log[s->nr_transitions++], t, sizeof(struct execution_transition));
    }
}

void vmi_log_authority_transition(struct vmi_session *s, struct authority_transition *t) {
    if (!s->authority_log) {
        s->authority_capacity = 1024;
        s->authority_log = calloc(s->authority_capacity, sizeof(struct authority_transition));
        s->nr_authority_transitions = 0;
    }
    
    // An authority transition spikes pressure globally
    s->field.capability_pressure += 0.5f;
    s->field.semantic_temperature += 0.2f;
    
    if (s->nr_authority_transitions >= s->authority_capacity) {
        // Simple ring buffer overwrite for now
        size_t evict = s->nr_authority_transitions % s->authority_capacity;
        memcpy(&s->authority_log[evict], t, sizeof(struct authority_transition));
    } else {
        memcpy(&s->authority_log[s->nr_authority_transitions++], t, sizeof(struct authority_transition));
    }
}

static void vmi_derive_initial_authority(struct vmi_session *s, struct semantic_actor *actor) {
    actor->authority.authority_id = (uint64_t)time(NULL) ^ (actor->identity.pid << 16) ^ 0xAAAA;
    actor->authority.domain = actor->domain == ACTOR_KERNEL ? AUTH_DOMAIN_KERNEL : AUTH_DOMAIN_USER;
    actor->authority.granted_epoch = s->semantic_epoch;
    actor->authority.last_validated_epoch = s->semantic_epoch;
    actor->authority.authority_decay_rate = 0.01f;
    
    actor->authority.origin.lineage_valid = false;
    actor->authority.origin.derivation_confidence = 0.5f;
    
    // Derived from proximity
    actor->authority.legitimacy.structural = 1.0f;
    actor->authority.legitimacy.behavioral = 1.0f;
    actor->authority.legitimacy.continuity = 1.0f;
    actor->authority.legitimacy.provenance = 1.0f;
    
    actor->authority.capabilities = 0;
    // Kthreads organically get KERNEL_MODIFY rights
    if (actor->is_kthread) {
        actor->authority.capabilities |= CAP_KERNEL_MODIFY | CAP_PRIVILEGED_MEMORY;
        actor->authority.potential.escalation = 1.0f;
    } else {
        // Userspace starts restricted
        actor->authority.capabilities |= CAP_EXEC_TRANSFORM | CAP_NAMESPACE_TRANSITION;
        actor->authority.potential.escalation = 0.1f;
        actor->authority.potential.destabilization = 0.2f;
    }
    
    actor->authority.capability_ceilings = ~0ULL; // No ceiling by default
    actor->authority.state = AUTHORITY_TRUSTED;
}

void vmi_calculate_thermodynamics(struct vmi_session *s) {
    if (s->nr_actors == 0) return;
    
    uint32_t cap_counts[8] = {0};
    uint64_t active_auths = 0;
    
    for (size_t i = 0; i < s->nr_actors; i++) {
        struct execution_authority *auth = &s->actor_cache[i].authority;
        if (auth->state != AUTHORITY_TERMINAL && auth->state != AUTHORITY_REVOKED) {
            active_auths++;
            for (int bit = 0; bit < 8; bit++) {
                if (auth->capabilities & (1ULL << bit)) {
                    cap_counts[bit]++;
                }
            }
        }
    }
    
    s->field.active_authorities = active_auths;
    
    // Shannon entropy approximation over capability ownership
    float entropy = 0.0f;
    for (int bit = 0; bit < 8; bit++) {
        if (cap_counts[bit] > 0) {
            float p = (float)cap_counts[bit] / (float)active_auths;
            entropy -= p * 0.693f; // Approximation of log2(p) for scale
        }
    }
    
    s->field.authority_entropy = entropy;
    // Centralization is inversely proportional to dispersion
    s->field.authority_centralization = 1.0f / (1.0f + entropy);
    
    // Phase 17: Structural Legitimacy Flux and Conservation
    float auth_mass = 0.0f;
    float leg_mass = 0.0f;
    
    for (size_t i = 0; i < s->nr_actors; i++) {
        struct execution_authority *auth = &s->actor_cache[i].authority;
        auth_mass += (float)__builtin_popcountll(auth->capabilities);
        leg_mass += (auth->legitimacy.structural + auth->legitimacy.behavioral + auth->legitimacy.continuity + auth->legitimacy.provenance);
        
        // Topology-Relative Authority Curvature
        if (s->actor_cache[i].parent_pid > 0) {
            for (size_t p = 0; p < s->nr_actors; p++) {
                if (s->actor_cache[p].identity.pid == s->actor_cache[i].parent_pid) {
                    float p_leg = s->actor_cache[p].authority.legitimacy.structural;
                    float c_leg = auth->legitimacy.structural;
                    float delta = p_leg - c_leg;
                    if (delta > s->field.authority_curvature) s->field.authority_curvature = delta;
                    break;
                }
            }
        }
    }
    
    float old_auth_mass = s->field.last_authority_mass;
    s->field.last_authority_mass = auth_mass;
    s->field.last_legitimacy_mass = leg_mass;
    
    // Volatility mass derived purely from structural churn, not policy
    float current_vol_mass = (s->field.semantic_temperature * 10.0f) + (s->nr_authority_transitions * 0.5f);
    s->field.last_volatility_mass = current_vol_mass;
    
    // Differential Conservation
    s->field.conservation.authority_delta = auth_mass - old_auth_mass;
    s->field.conservation.expected_delta = 0.0f; // Simplified expected delta (e.g. from known forks)
    s->field.conservation.observed_delta = s->field.conservation.authority_delta;
    s->field.conservation.residual_error = s->field.conservation.observed_delta - s->field.conservation.expected_delta;
    
    // Legitimacy flux: rate of legitimacy transfer
    if (s->field.conservation.residual_error > 0.0f) {
        s->field.legitimacy_flux += 0.1f;
    } else {
        s->field.legitimacy_flux *= 0.95f;
    }
    
    // Closure State Evaluation
    if (s->field.conservation.residual_error > 5.0f || s->field.authority_curvature > 0.8f) {
        s->field.closure_state = FIELD_DIVERGENT;
        if (s->field.collapse_hysteresis > 2.0f) s->field.closure_state = FIELD_COLLAPSING;
    }
}

void vmi_project_trajectory(struct vmi_session *s) {
    // 1. Trajectory Curvature (d^2(divergence)/d(epoch^2))
    float old_velocity = s->field.trajectory.divergence_velocity;
    s->field.trajectory.divergence_velocity = s->field.conservation.residual_error;
    float acceleration = s->field.trajectory.divergence_velocity - old_velocity;
    s->field.trajectory.divergence_acceleration = acceleration;
    s->field.trajectory.trajectory_curvature = acceleration;
    
    // 2. Escape Velocity (Native geometric stabilization required)
    s->field.trajectory.escape_velocity = (s->field.authority_entropy * 5.0f) + (s->field.trajectory.trajectory_curvature * 10.0f);
    
    // 3. Adaptive Projection Horizon
    float flux = s->field.legitimacy_flux > 0.0f ? s->field.legitimacy_flux : 0.0f;
    float vel = s->field.trajectory.divergence_velocity > 0.0f ? s->field.trajectory.divergence_velocity : 0.0f;
    uint64_t base_horizon = 100;
    s->field.constraints.max_projection_epochs = (uint64_t)(base_horizon / (1.0f + vel + flux));
    if (s->field.constraints.max_projection_epochs < 1) s->field.constraints.max_projection_epochs = 1;
    
    // 4. Counterfactual Reachability
    if (s->field.trajectory.trajectory_curvature > 0.5f && s->field.constraints.max_projection_epochs < 10) {
        s->field.boundaries.reachability = REACHABILITY_INEVITABLE;
        s->field.anticipated_collapse = COLLAPSE_CASCADING;
    } else if (s->field.trajectory.divergence_velocity > 1.0f) {
        s->field.boundaries.reachability = REACHABILITY_PROBABLE;
        s->field.anticipated_collapse = COLLAPSE_PROPAGATING;
    } else {
        s->field.boundaries.reachability = REACHABILITY_CONSTRAINED;
        s->field.anticipated_collapse = COLLAPSE_NONE;
    }
    
    // 5. Basin of Stability
    if (s->field.trajectory.trajectory_curvature < 0.0f) {
        s->field.basin.attractor = ATTRACTOR_STABLE;
    } else if (s->field.trajectory.trajectory_curvature > 0.5f) {
        s->field.basin.attractor = ATTRACTOR_COLLAPSING;
    } else {
        s->field.basin.attractor = ATTRACTOR_OSCILLATORY;
    }
}

// Helper: read task field
static int read_field(struct vmi_session *s, uint64_t task_gva, uint64_t offset, void *buf, size_t size) {
    return vmi_read_virtual(s, s->kernel_pgd, task_gva + offset, buf, size);
}

static struct semantic_actor *find_or_create_actor(struct vmi_session *s, pid_t pid, uint64_t start_time) {
    if (!s->actor_cache) {
        s->actor_cache_capacity = 128;
        s->actor_cache = calloc(s->actor_cache_capacity, sizeof(struct semantic_actor));
        s->nr_actors = 0;
    }
    
    // Search cache
    for (size_t i = 0; i < s->nr_actors; i++) {
        if (s->actor_cache[i].identity.pid == pid && s->actor_cache[i].identity.start_time == start_time) {
            return &s->actor_cache[i];
        }
    }
    
    // Evict or expand (LRU simplified: overwrite oldest if full)
    if (s->nr_actors >= s->actor_cache_capacity) {
        size_t oldest = 0;
        for (size_t i = 1; i < s->nr_actors; i++) {
            if (s->actor_cache[i].last_seen_timestamp < s->actor_cache[oldest].last_seen_timestamp) {
                // Protect high-debt actors from immediate eviction
                float debt_i = s->actor_cache[i].debt.integrity + s->actor_cache[i].debt.provenance;
                float debt_old = s->actor_cache[oldest].debt.integrity + s->actor_cache[oldest].debt.provenance;
                if (debt_i <= debt_old) {
                    oldest = i;
                }
            }
        }
        // Evict
        memset(&s->actor_cache[oldest], 0, sizeof(struct semantic_actor));
        s->actor_cache[oldest].identity.pid = pid;
        s->actor_cache[oldest].identity.start_time = start_time;
        return &s->actor_cache[oldest];
    }
    
    // Create new
    struct semantic_actor *actor = &s->actor_cache[s->nr_actors++];
    actor->identity.pid = pid;
    actor->identity.start_time = start_time;
    actor->execution_epoch = 1;
    return actor;
}

int task_walker_reconstruct_actor(struct vmi_session *s, uint64_t raw_cr3, uint64_t rip, uint32_t vcpu_id, struct semantic_actor **out_actor) {
    if (!s || s->init_task_addr == 0 || !active_offsets) return -1;
    
    uint64_t normalized_cr3 = mmu_normalize_cr3(raw_cr3);
    uint64_t current = s->init_task_addr;
    int count = 0;
    
    uint64_t matched_task = 0;
    uint64_t matched_mm = 0;
    uint64_t matched_active_mm = 0;
    
    // 1. Scheduler Topology Walk to find MM ownership
    do {
        uint64_t mm_addr = 0;
        uint64_t active_mm_addr = 0;
        
        read_field(s, current, active_offsets->mm_offset, &mm_addr, sizeof(mm_addr));
        if (active_offsets->active_mm_offset != 0) {
            read_field(s, current, active_offsets->active_mm_offset, &active_mm_addr, sizeof(active_mm_addr));
        }
        
        uint64_t pgd_gva = 0;
        uint64_t pgd_gpa = 0;
        bool found = false;
        
        if (mm_addr) {
            vmi_read_virtual(s, s->kernel_pgd, mm_addr + active_offsets->mm_pgd_offset, &pgd_gva, sizeof(pgd_gva));
            if (pgd_gva && vmi_gva_to_gpa(s, s->kernel_pgd, pgd_gva, &pgd_gpa) == 0) {
                if (pgd_gpa == normalized_cr3) {
                    matched_task = current;
                    matched_mm = mm_addr;
                    matched_active_mm = active_mm_addr;
                    found = true;
                }
            }
        }
        
        if (!found && active_mm_addr) {
            vmi_read_virtual(s, s->kernel_pgd, active_mm_addr + active_offsets->mm_pgd_offset, &pgd_gva, sizeof(pgd_gva));
            if (pgd_gva && vmi_gva_to_gpa(s, s->kernel_pgd, pgd_gva, &pgd_gpa) == 0) {
                if (pgd_gpa == normalized_cr3) {
                    matched_task = current;
                    matched_mm = mm_addr;
                    matched_active_mm = active_mm_addr;
                    found = true;
                }
            }
        }
        
        if (found) break;
        
        // next task
        uint64_t list_next;
        if (read_field(s, current, active_offsets->tasks_offset, &list_next, sizeof(list_next)) < 0) break;
        current = list_next - active_offsets->tasks_offset;
        count++;
    } while (current != s->init_task_addr && count < 4096);
    
    if (!matched_task) {
        printf("[Actor] Debug: Failed to find CR3 0x%lx (normalized 0x%lx) among %d tasks.\n", raw_cr3, normalized_cr3, count);
        return -1;
    }
    
    // 2. Extract semantic state
    pid_t pid = 0, tgid = 0;
    uint64_t start_time = 0;
    char comm[16] = {0};
    
    read_field(s, matched_task, active_offsets->pid_offset, &pid, sizeof(pid));
    read_field(s, matched_task, active_offsets->tgid_offset, &tgid, sizeof(tgid));
    read_field(s, matched_task, active_offsets->start_time_offset, &start_time, sizeof(start_time));
    read_field(s, matched_task, active_offsets->comm_offset, comm, sizeof(comm));
    comm[15] = '\0';
    
    // 3. Obtain persistent actor
    bool is_new_actor = false;
    struct semantic_actor *actor = NULL;
    for (size_t i = 0; i < s->nr_actors; i++) {
        if (s->actor_cache[i].identity.pid == pid && s->actor_cache[i].identity.start_time == start_time) {
            actor = &s->actor_cache[i];
            break;
        }
    }
    if (!actor) {
        is_new_actor = true;
        actor = find_or_create_actor(s, pid, start_time);
    }
    
    // 4. Update transient properties
    actor->task_struct_addr = matched_task;
    actor->mm = matched_mm;
    actor->active_mm = matched_active_mm;
    actor->cr3 = raw_cr3;
    actor->normalized_cr3 = normalized_cr3;
    actor->vcpu_id = vcpu_id;
    actor->rip = rip;
    actor->tgid = tgid;
    strcpy(actor->comm, comm);
    
    // Parent Lineage
    if (active_offsets->real_parent_offset != 0) {
        uint64_t parent_task = 0;
        if (read_field(s, matched_task, active_offsets->real_parent_offset, &parent_task, sizeof(parent_task)) == 0 && parent_task != 0) {
            read_field(s, parent_task, active_offsets->pid_offset, &actor->parent_pid, sizeof(actor->parent_pid));
            read_field(s, parent_task, active_offsets->start_time_offset, &actor->parent_start_time, sizeof(actor->parent_start_time));
        }
    }
    
    // Damped Inheritance on Fork
    if (is_new_actor && actor->parent_pid > 0 && actor->parent_start_time > 0) {
        struct semantic_actor *parent = NULL;
        for (size_t i = 0; i < s->nr_actors; i++) {
            if (s->actor_cache[i].identity.pid == actor->parent_pid && s->actor_cache[i].identity.start_time == actor->parent_start_time) {
                parent = &s->actor_cache[i];
                break;
            }
        }
        if (parent) {
            actor->debt.integrity = parent->debt.integrity * 0.35f;
            actor->debt.provenance = parent->debt.provenance * 0.80f;
            actor->debt.execution = parent->debt.execution * 0.20f;
            actor->debt.policy = parent->debt.policy * 0.50f;
            printf("[Transition] TRANSITION_FORK: PID %u (parent PID %u). Inheriting damped debt (Integ: %.2f, Prov: %.2f)\n", actor->identity.pid, parent->identity.pid, actor->debt.integrity, actor->debt.provenance);
            
            // Authority Propagation for FORK
            actor->authority.legitimacy.structural = parent->authority.legitimacy.structural * 1.0f;
            actor->authority.legitimacy.behavioral = parent->authority.legitimacy.behavioral * 0.9f;
            actor->authority.legitimacy.continuity = parent->authority.legitimacy.continuity * 1.0f;
            actor->authority.legitimacy.provenance = parent->authority.legitimacy.provenance * 1.0f;
            actor->authority.capabilities = parent->authority.capabilities;
            actor->authority.state = parent->authority.state;
            
            // Log Authority Transition if it changed significantly
            // For FORK we just propagate the values.
            
            // Generate FORK Transition
            struct execution_transition t = {0};
            t.id = (uint64_t)time(NULL) ^ (actor->identity.pid << 16);
            t.parent_id = parent->last_transition_id;
            t.timestamp = time(NULL);
            t.semantic_epoch = s->semantic_epoch;
            t.cause = CAUSE_SCHEDULER;
            t.retention_score = parent->debt.integrity + parent->debt.provenance;
            
            t.edge.type = EDGE_FORK;
            t.edge.source = parent->identity;
            t.edge.target = actor->identity;
            t.edge.identity_continuity = 1.0f;
            t.edge.authority_continuity = 1.0f;
            t.edge.start_epoch = s->semantic_epoch;
            t.edge.end_epoch = s->semantic_epoch;
            t.edge.transition_confidence = 0.99f;
            
            vmi_log_transition(s, &t);
            actor->last_transition_id = t.id;
        } else {
            printf("[Transition] TRANSITION_FORK: PID %u. Parent %u not in cache.\n", actor->identity.pid, actor->parent_pid);
        }
    } else if (is_new_actor) {
        printf("[Transition] New actor spawned without valid lineage: PID %u\n", actor->identity.pid);
    }
    
    // Exec Transition Detection (Comm changes)
    if (!is_new_actor && strcmp(actor->comm, comm) != 0) {
        printf("[Transition] TRANSITION_EXEC: PID %u transformed %s -> %s\n", actor->identity.pid, actor->comm, comm);
        
        // Generate EXEC Transition
        struct execution_transition t = {0};
        t.id = (uint64_t)time(NULL) ^ (actor->identity.pid << 16) ^ 0xEEEE;
        t.parent_id = actor->last_transition_id;
        t.timestamp = time(NULL);
        t.semantic_epoch = s->semantic_epoch;
        t.cause = CAUSE_SYSCALL;
        t.retention_score = actor->debt.integrity + actor->debt.provenance;
        
        t.edge.type = EDGE_EXEC;
        t.edge.source = actor->identity;
        t.edge.target = actor->identity;
        t.edge.identity_continuity = 0.5f; // Semantic Rebirth
        t.edge.authority_continuity = 0.8f;
        t.edge.start_epoch = s->semantic_epoch;
        t.edge.end_epoch = s->semantic_epoch;
        t.edge.transition_confidence = 0.99f;
        
        vmi_log_transition(s, &t);
        actor->last_transition_id = t.id;
        
        // Authority Transformation for EXEC (Semantic Rebirth)
        actor->authority.legitimacy.behavioral = 1.0f; // Reset behavior
        actor->authority.legitimacy.continuity *= 0.5f; // Continuity is broken
        // Capabilities are generally preserved but this is where ceilings would apply
        
        strcpy(actor->comm, comm);
        // Partial debt reset on exec
        actor->debt.execution *= 0.50f;
    }
    
    // Namespaces
    uint64_t new_mnt_ns = 0, new_pid_ns = 0, new_user_ns = 0;
    uint64_t nsproxy_addr = 0;
    if (active_offsets->nsproxy_offset != 0) {
        read_field(s, matched_task, active_offsets->nsproxy_offset, &nsproxy_addr, sizeof(nsproxy_addr));
        if (nsproxy_addr) {
            read_field(s, nsproxy_addr, active_offsets->nsproxy_mnt_ns_offset, &new_mnt_ns, sizeof(new_mnt_ns));
            read_field(s, nsproxy_addr, active_offsets->nsproxy_pid_ns_offset, &new_pid_ns, sizeof(new_pid_ns));
        }
    }
    uint64_t cred_addr = 0;
    if (active_offsets->cred_offset != 0) {
        read_field(s, matched_task, active_offsets->cred_offset, &cred_addr, sizeof(cred_addr));
        if (cred_addr) {
            read_field(s, cred_addr, active_offsets->cred_user_ns_offset, &new_user_ns, sizeof(new_user_ns));
        }
    }
    
    // Detect Namespace Transition
    if (!is_new_actor && (actor->mnt_ns != 0 && new_mnt_ns != 0)) {
        if (actor->mnt_ns != new_mnt_ns || actor->pid_ns != new_pid_ns || actor->user_ns != new_user_ns) {
            printf("[Transition] TRANSITION_NAMESPACE_ENTER: PID %u shifted namespaces (mnt: 0x%lx->0x%lx)\n", actor->identity.pid, actor->mnt_ns, new_mnt_ns);
            
            struct execution_transition t = {0};
            t.id = (uint64_t)time(NULL) ^ (actor->identity.pid << 16) ^ 0xAAAA;
            t.parent_id = actor->last_transition_id;
            t.timestamp = time(NULL);
            t.semantic_epoch = s->semantic_epoch;
            t.cause = CAUSE_NAMESPACE_REBIND;
            t.retention_score = actor->debt.integrity + actor->debt.provenance + 5.0f; // High retention
            
            t.edge.type = EDGE_NAMESPACE_ENTER; // Default to enter for now
            t.edge.source = actor->identity;
            t.edge.target = actor->identity;
            t.edge.identity_continuity = 0.9f;
            t.edge.authority_continuity = 0.5f; // Topology discontinuity
            t.edge.start_epoch = s->semantic_epoch;
            t.edge.end_epoch = s->semantic_epoch;
            t.edge.transition_confidence = 0.99f;
            
            vmi_log_transition(s, &t);
            actor->last_transition_id = t.id;
        }
    }
    actor->mnt_ns = new_mnt_ns;
    actor->pid_ns = new_pid_ns;
    actor->user_ns = new_user_ns;
    
    actor->in_kernel = (rip >= 0xffff000000000000ULL);
    actor->is_kthread = (actor->mm == 0 && actor->active_mm != 0);
    actor->borrowed_mm = actor->is_kthread;
    
    if (actor->is_kthread) {
        actor->domain = ACTOR_KERNEL;
    } else {
        actor->domain = actor->in_kernel ? ACTOR_KERNEL : ACTOR_USERSPACE;
    }
    
    actor->attrib_state = ATTRIB_EXACT;
    
    // Seed initial authority
    vmi_derive_initial_authority(s, actor);
    
    actor->attribution_confidence = 1.0f;
    actor->last_seen_rip = rip;
    actor->last_seen_timestamp = time(NULL);
    actor->last_seen_epoch = s->semantic_epoch;
    
    if (out_actor) {
        *out_actor = actor;
    }
    
    return 0;
}
