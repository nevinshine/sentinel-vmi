// include/sentinel_vmi.h — Sentinel VMI shared definitions
#pragma once

#include <linux/kvm.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>

// ──────────────────────────────────────────────
// VMI Session — KVM introspection state
// ──────────────────────────────────────────────

#define VMI_MAX_VCPUS 64
#define VMI_PAGE_SIZE 4096
#define VMI_PAGE_SHIFT 12
#define VMI_MEMSLOT_F_REMOTE_PROCESS (1U << 31)

// KVM memslot for guest-physical → host-virtual translation
struct vmi_memslot {
  uint64_t guest_phys_addr; // GPA start
  uint64_t memory_size;     // slot size in bytes
  void *userspace_addr;     // host VA mapped
  uint32_t slot;
  uint32_t flags;
};

// Phase 16: Distributed Semantic Coherence & Thermodynamics
struct semantic_field_legitimacy {
    float structural;
    float behavioral;
    float continuity;
    float provenance;
};

struct semantic_momentum_field {
    float legitimacy_velocity;
    float legitimacy_acceleration;
};

// Phase 17: Field Closure States & Gradients
enum field_closure_state {
    FIELD_COHERENT,
    FIELD_STRAINED,
    FIELD_DIVERGENT,
    FIELD_COLLAPSING,
    FIELD_IRRECOVERABLE
};

struct conservation_delta {
    float authority_delta;
    float legitimacy_delta;
    float volatility_delta;

    float expected_delta;
    float observed_delta;

    float residual_error;
};

struct pressure_gradient {
    float namespace_gradient;
    float authority_gradient;
    float execution_gradient;
};

// Phase 18: Predictive Semantic Collapse
enum collapse_mode {
    COLLAPSE_NONE,
    COLLAPSE_LOCALIZED,
    COLLAPSE_PROPAGATING,
    COLLAPSE_CASCADING,
    COLLAPSE_IRREVERSIBLE
};

enum reachability_state {
    REACHABILITY_IMPOSSIBLE,
    REACHABILITY_CONSTRAINED,
    REACHABILITY_PROBABLE,
    REACHABILITY_INEVITABLE
};

enum attractor_type {
    ATTRACTOR_HEALTHY,
    ATTRACTOR_DEGRADED,
    ATTRACTOR_MALIGNANT,
    ATTRACTOR_PARASITIC,
    ATTRACTOR_COLLAPSING
};

struct projection_constraints {
    uint64_t max_projection_epochs;
    float max_entropy_growth;
    float max_curvature_growth;
    float max_flux_growth;
    bool bounded;
};

struct counterfactual_boundary {
    float max_projected_curvature;
    float max_projected_flux;
    float instability_threshold;
    enum reachability_state reachability;
};

struct semantic_inertia_vector {
    float topology_resistance;
    float authority_resistance;
    float namespace_resistance;
};

struct stability_basin {
    float equilibrium_radius;
    float recovery_probability;
    enum attractor_type attractor;
    
    // Phase 21
    bool metastable;
    float metastability_margin;
};

struct observer_effect {
    float intervention_disruption;
    float stabilization_gain;
    float topology_distortion;
    float authority_displacement;
    float namespace_disruption;
    bool observer_dominating;
    
    // Phase 21
    float observer_energy_integral;
};

struct stability_gradient {
    float local_stability;
    float neighboring_stability;
    float gradient_strength;
};

struct semantic_shear {
    float namespace_shear;
    float authority_shear;
    float execution_shear;
};

struct semantic_trajectory {
    float stability;
    float collapse_probability;
    float divergence_velocity;
    float divergence_acceleration;
    uint64_t projected_epochs_to_instability;
    float trajectory_curvature;       // d²(divergence)/d(epoch²)
    float escape_velocity;            // Native geometric stabilization force required
    float projection_confidence;
};

// Phase 20/21: Autonomous Equilibrium Steering & Phase Mechanics
enum semantic_phase {
    PHASE_ORDERED,
    PHASE_META_STABLE,
    PHASE_TRANSITIONAL,
    PHASE_TURBULENT,
    PHASE_COLLAPSED
};

struct phase_transition {
    enum semantic_phase prev;
    enum semantic_phase next;
    uint64_t dwell_epochs;
    float transition_energy;
};

struct semantic_compressibility {
    float authority_compressibility;
    float namespace_compressibility;
    float execution_compressibility;
};

struct topology_fingerprint {
    float curvature;
    float shear;
    float flux;
    float entropy;
    float resonance;
};

struct criticality_field {
    float local_criticality;
    float propagation_criticality;
    float collapse_sensitivity;
};

struct criticality_cascade {
    float cascade_probability;
    uint64_t projected_propagation_depth;
    bool self_amplifying;
};

struct topology_scar {
    float conservation_violation;
    float illegitimate_authority_origin;
    float irreversible_divergence;
};

struct semantic_friction {
    float authority_friction;
    float namespace_friction;
    float execution_friction;
};

struct basin_coupling {
    uint64_t source_basin;
    uint64_t target_basin;
    float upstream_influence;
    float downstream_influence;
    float propagation_risk;
};

struct stabilization_memory {
    struct topology_fingerprint fingerprint;
    float historical_gain;
    float historical_distortion;
    bool destabilizing_pattern;
};

struct semantic_resonance {
    float transition_resonance;
    float authority_resonance;
    float namespace_resonance;
    bool resonant_instability;
};

struct semantic_deadzone {
    float curvature_deadzone;
    float shear_deadzone;
    float flux_deadzone;
};

struct semantic_homeostasis {
    float equilibrium_bias;
    float adaptive_damping;
    bool self_correcting;
};

struct equilibrium_controller {
    float correction_rate;
    float damping_factor;
    float stabilization_bias;
    float observer_suppression;
    bool continuous_regulation;
};

// Phase 19: Counterfactual Stabilization Theory
enum stabilization_legality {
    STABILIZATION_ILLEGAL,
    STABILIZATION_DESTRUCTIVE,
    STABILIZATION_CONSTRAINED,
    STABILIZATION_OPTIMAL
};

enum stabilization_class {
    STABILIZE_OBSERVE,
    STABILIZE_THROTTLE,
    STABILIZE_QUARANTINE,
    STABILIZE_ISOLATE,
    STABILIZE_REVOKE,
    STABILIZE_FREEZE
};

enum enforcement_scope {
    SCOPE_NONE = 0,
    SCOPE_THREAD,
    SCOPE_PROCESS,
    SCOPE_VCPU,
    SCOPE_VM,
    SCOPE_HOST
};

struct stabilization_candidate {
    uint64_t candidate_id;
    enum stabilization_class action_class;
    enum enforcement_scope scope;

    float projected_stability_gain;
    float projected_topology_distortion;

    float conservation_recovery;
    float authority_displacement;

    float observer_cost;
    float topology_recovery_cost;
    float intervention_minimality;    // stability_gain / topology_distortion
    float recovery_integrity;
    float reversibility_score;
    float recursive_observer_cost; // Phase 20
    
    enum stabilization_legality legality;
};

struct stabilization_chain {
    struct stabilization_candidate steps[4];
    size_t nr_steps;
    float cumulative_distortion;
    float cumulative_recovery;
};

struct counterfactual_result {
    struct stabilization_chain chain;
    enum field_closure_state projected_state;

    float projected_flux;
    float projected_curvature;
    float projected_entropy;

    float stabilization_energy;
    bool stable;
};

struct semantic_elasticity {
    float recovery_elasticity;
    float fragmentation_elasticity;
    float authority_elasticity;
};

struct local_basin {
    uint64_t basin_id;
    enum attractor_type attractor;
    struct topology_scar scars;
    float local_entropy;
    float local_curvature;
    float local_flux;
    bool isolated;
    bool repairable;
    
    // Phase 21
    bool metastable;
    float metastability_margin;
};


struct semantic_field {
    struct semantic_field_legitimacy legitimacy;
    
    float authority_entropy;
    float authority_centralization;
    float capability_pressure;
    float namespace_instability;
    float execution_fragmentation;
    
    struct semantic_momentum_field momentum;
    struct pressure_gradient pressure;
    struct conservation_delta conservation;
    
    struct semantic_inertia_vector inertia;
    struct semantic_trajectory trajectory;
    struct counterfactual_boundary boundaries;
    struct projection_constraints constraints;
    struct stability_basin basin;
    struct observer_effect observer;
    struct stability_gradient stab_gradient;
    struct semantic_shear shear;
    struct semantic_friction friction;
    struct semantic_resonance resonance;
    struct semantic_deadzone deadzone;
    
    struct semantic_elasticity elasticity;
    struct semantic_homeostasis homeostasis;
    struct equilibrium_controller controller;
    
    struct counterfactual_result optimal_stabilization;
    struct local_basin active_basin;
    struct basin_coupling local_coupling;
    struct stabilization_memory control_memory;
    
    // Phase 21
    struct phase_transition phase_state;
    struct semantic_compressibility compressibility;
    struct criticality_field criticality;
    struct criticality_cascade criticality_cascade;
    float phase_energy;
    
    enum semantic_phase phase;
    
    float semantic_temperature;
    float collapse_hysteresis;
    float authority_gradient;
    
    float legitimacy_flux;
    float authority_curvature;
    
    enum field_closure_state closure_state;
    uint64_t hysteresis_epochs;
    float recovery_gradient;
    
    // Mass state across epochs
    float last_authority_mass;
    float last_legitimacy_mass;
    float last_volatility_mass;
    
    uint64_t active_authorities;
    uint64_t quarantined_authorities;
    
    enum collapse_mode anticipated_collapse;
    
    uint64_t current_epoch;
    uint64_t coherence_epoch;
};

struct semantic_overlay {
    uint64_t overlay_epoch;
    struct semantic_field projected_field;
    
    // Abstract differentials (for zero-latency replay without cloning all actors)
    float delta_auth_mass;
    float delta_leg_mass;
    float delta_volatility;
    float delta_entropy;
};

struct vmi_session {
  int kvm_fd;                  // /dev/kvm
  int vm_fd;                   // VM file descriptor
  int vcpu_fds[VMI_MAX_VCPUS]; // vCPU file descriptors
  int nr_vcpus;

  // Guest memory map (memslots)
  struct vmi_memslot *memslots;
  int nr_memslots;

  // Runtime attachment metadata
  int qemu_pid;       // target QEMU PID (if discovered)
  int control_fd;     // QMP/KVMI control channel fd
  void *kvmi_runtime; // private KVMI runtime state

  // NPT Guard state
  uint64_t syscall_table_gpa; // guest-physical addr of sys_call_table
  uint64_t syscall_table_gva; // guest-virtual addr
  int npt_armed;              // 1 if guard is active

  // Kernel profile (Phase 2)
  uint64_t kaslr_offset;   // KASLR slide
  uint64_t init_task_addr; // &init_task (GVA)
  uint64_t kernel_pgd;     // guest CR3 / kernel page table base
  
  struct memory_region *regions;
  size_t nr_regions;

  // Phase 16: VM-Wide Semantic Field
  struct semantic_field field;
  
  // Phase 13: Semantic Actor Attribution
  struct semantic_actor *actor_cache;
  size_t nr_actors;
  size_t actor_cache_capacity;
  
  // Phase 14: Execution Transition Epochs
  uint64_t semantic_epoch;
  struct execution_transition *transition_log;
  size_t nr_transitions;
  size_t transition_capacity;
  
  // Phase 15: Teleological Authority Log
  struct authority_transition *authority_log;
  size_t nr_authority_transitions;
  size_t authority_capacity;
};

// ──────────────────────────────────────────────
// Phase 1 — kvmi_setup.c
// ──────────────────────────────────────────────
struct vmi_session *kvmi_setup(const char *vm_name);
void kvmi_teardown(struct vmi_session *session);
int kvmi_session_heartbeat(struct vmi_session *session);

// ──────────────────────────────────────────────
// Phase 1 — memory.c
// ──────────────────────────────────────────────
int vmi_read_physical(struct vmi_session *s, uint64_t gpa, void *buf,
                      size_t size);
int vmi_write_physical(struct vmi_session *s, uint64_t gpa, const void *buf,
                       size_t size);
struct page_walk_result {
    uint64_t gpa;
    bool present;
    bool writable;
    bool executable;
    bool user;
    bool hugepage;
};

// Extends vmi_gva_to_gpa to return full MMU authority
int vmi_mmu_translate(struct vmi_session *s, uint64_t cr3, uint64_t gva, struct page_walk_result *out);

int vmi_gva_to_gpa(struct vmi_session *s, uint64_t cr3, uint64_t gva,
                   uint64_t *gpa);
int vmi_read_virtual(struct vmi_session *s, uint64_t cr3, uint64_t gva,
                     void *buf, size_t size);

// ──────────────────────────────────────────────
// Phase 2 — task_walker.c
// ──────────────────────────────────────────────

#define TASK_COMM_LEN 16

struct vmi_process {
  uint64_t task_addr; // GVA of task_struct
  uint32_t pid;
  uint32_t tgid;
  uint32_t ppid;
  uint32_t uid;
  uint32_t gid;
  uint32_t euid;
  uint32_t egid;
  char comm[TASK_COMM_LEN];
  uint64_t mm_addr;       // mm_struct pointer
  uint64_t cred_addr;     // cred struct pointer
  uint64_t files_addr;    // files_struct pointer
  uint64_t nsproxy_addr;  // nsproxy pointer
  uint64_t start_time;    // task start time
  uint64_t flags;         // task flags
  uint64_t cap_effective; // effective capabilities (low 64 bits)
};

void task_walker_dump(struct vmi_session *s);
int task_walker_find_pid(struct vmi_session *s, uint32_t pid,
                         uint64_t *task_addr);
int task_walker_read_process(struct vmi_session *s, uint64_t task_gva,
                             struct vmi_process *out);
int task_walker_detect_privilege_escalation(struct vmi_session *s);
int task_walker_set_offsets_profile(const char *kernel_version);
const char *task_walker_get_offsets_profile(void);
int task_walker_detect_orphans(struct vmi_session *s);
int task_walker_detect_fork_bomb(struct vmi_session *s, uint32_t threshold);
int task_walker_detect_suspicious_ancestry(struct vmi_session *s);

// ──────────────────────────────────────────────
// Phase 3 — npt_guard.c / npf_handler.c
// ──────────────────────────────────────────────
int npt_guard_arm(struct vmi_session *s);
void npt_guard_disarm(struct vmi_session *s);
void npt_guard_handle_events(struct vmi_session *s);

int npf_handler_init(struct vmi_session *s);
void npf_handler_process(struct vmi_session *s, uint64_t gpa, int write_access);
int npf_handler_report_integrity_violation(struct vmi_session *s,
                                           const char *region_name,
                                           uint64_t gpa, uint64_t expected_hash,
                                           uint64_t actual_hash, int critical);

// ──────────────────────────────────────────────
// Phase 6 — heki_server.c
// ──────────────────────────────────────────────
int heki_server_init(struct vmi_session *session, const char *socket_path);
void heki_server_poll(void);

// ──────────────────────────────────────────────
// Phase 4 — bridge.c
// ──────────────────────────────────────────────
int bridge_init(void);
void bridge_teardown(void);
void bridge_signal_malicious(uint32_t pid, const char *reason);
void bridge_signal_suspicious(uint32_t pid, const char *reason);
void bridge_flush_alerts(void);
int npt_guard_protect_dynamic(struct vmi_session *s, uint64_t gpa,
                              uint64_t size, int critical, const char *name);
int npt_guard_check_bounds(uint64_t gpa, const char **region_name,
                           int *is_critical);

// ──────────────────────────────────────────────
// Snapshot Testing API
// ──────────────────────────────────────────────
struct snapshot_metadata {
  char kernel_release[64];
  char kernel_build_id[64];
  char capture_timestamp[64];
  char snapshot_sha256[128];
  char kallsyms_sha256[128];

  char paging_mode[32];
  uint32_t page_shift;

  uint64_t kaslr_slide;
  uint64_t phys_base;

  uint64_t vcpu_rip;
  uint64_t vcpu_rsp;
  uint64_t vcpu_cr3;
};

int validate_snapshot_metadata(const struct snapshot_metadata *meta, uint64_t file_size);
struct vmi_session *vmi_session_from_snapshot(const char *bin_path, const char *json_path);

// ──────────────────────────────────────────────
// Phase 5 — symbols.c
// ──────────────────────────────────────────────
struct symbol {
  uint64_t addr;
  char type;
  char *name;
};

struct symbol_table {
  struct symbol *syms;
  size_t count;
  size_t capacity;
};

struct symbol_table *symbol_table_load(const char *path);
void symbol_table_free(struct symbol_table *table);
uint64_t symbol_resolve(struct symbol_table *table, const char *sym_name);

// ──────────────────────────────────────────────
// Phase 6: Semantic Provenance & Graph Verification
// ──────────────────────────────────────────────

struct vmi_graph_verifier {
    uint32_t *linked_list_pids;
    uint32_t linked_list_count;
    
    uint32_t *radix_tree_pids;
    uint32_t radix_tree_count;
};

// Initializes the provenance engine and runs cross-validation
int provenance_run_cross_validation(struct vmi_session *s, struct symbol_table *syms);

// Simulates a DKOM attack by unlinking a task in physical memory
int provenance_simulate_dkom(struct vmi_session *s, uint32_t target_pid);

// ──────────────────────────────────────────────
// Phase 7: Memory Integrity & Executable Provenance
// ──────────────────────────────────────────────

enum provenance_class {
    PROV_INVALID = 0,
    PROV_CORE_TEXT,
    PROV_MODULE_TEXT,
    PROV_VMALLOC_EXEC,
    PROV_DIRECTMAP_EXEC,
    PROV_USERSPACE,
    PROV_UNMAPPED,
    PROV_NONCANONICAL,
    PROV_UNKNOWN
};

enum integrity_score {
    INTEGRITY_TRUSTED = 0,
    INTEGRITY_SUSPICIOUS,
    INTEGRITY_ANOMALOUS
};

struct executable_provenance {
    enum provenance_class classification;
    bool canonical;
    bool mapped;
    bool executable;
    bool writable;
    bool symbol_backed;
    uint64_t symbol_addr;
    uint64_t symbol_offset;
    const struct symbol *symbol;
};

enum region_type {
    REGION_UNKNOWN = 0,
    REGION_CORE_TEXT,
    REGION_CORE_RODATA,
    REGION_CORE_DATA,
    REGION_MODULE_CANDIDATE,
    REGION_DYNAMIC_EXEC,
    REGION_VMALLOC,
    REGION_DIRECTMAP,
    REGION_USER,
    REGION_FIXMAP,
    REGION_VSYSCALL,
    REGION_PERCPU
};

struct region_permissions {
    bool r;
    bool w;
    bool x;
};

enum volatility_class {
    VOL_STABLE = 0,
    VOL_SEMISTABLE,
    VOL_DYNAMIC,
    VOL_EPHEMERAL
};

struct stability_contract {
    bool allow_exec_transition;
    bool allow_permission_change;
    bool allow_symbol_drift;
    bool allow_edge_retarget;
};

struct memory_region {
    uint64_t region_id;
    uint64_t start;
    uint64_t end;
    struct region_permissions declared;
    struct region_permissions observed;
    struct stability_contract contract;
    enum region_type type;
    const char *name;
};

enum edge_type {
    EDGE_SYSCALL_TABLE = 0,
    EDGE_IDT_HANDLER,
    EDGE_FTRACE_TRAMPOLINE,
    EDGE_OPS_CALLBACK,
    EDGE_TASK_STRUCT
};

enum edge_stability {
    EDGE_IMMUTABLE = 0,
    EDGE_SEMISTABLE,
    EDGE_EXPECTED_DYNAMIC,
    EDGE_UNSTABLE
};

struct executable_edge {
    uint64_t source_addr;
    uint64_t target_addr;
    const struct memory_region *source_region;
    const struct memory_region *target_region;
    enum edge_type type;
    enum edge_stability stability;
    enum integrity_score score;
};

// ──────────────────────────────────────────────
// Phase 13: Semantic Actor Attribution
// ──────────────────────────────────────────────

enum actor_domain {
    ACTOR_USERSPACE,
    ACTOR_KERNEL,
    ACTOR_INTERRUPT,
    ACTOR_UNKNOWN
};

enum attribution_state {
    ATTRIB_EXACT,
    ATTRIB_HEURISTIC,
    ATTRIB_AMBIGUOUS,
    ATTRIB_UNRESOLVED
};

struct actor_identity {
    pid_t pid;
    uint64_t start_time;
};

// Phase 14: Execution Lineage Primitives
typedef uint64_t transition_id_t;

enum execution_intent {
    INTENT_UNKNOWN,
    INTENT_KERNEL_SERVICE,
    INTENT_DAEMON,
    INTENT_TRANSIENT_HELPER,
    INTENT_DEBUGGER,
    INTENT_JIT_RUNTIME,
    INTENT_EXPLOIT
};

enum authority_domain {
    AUTH_DOMAIN_USER,
    AUTH_DOMAIN_KERNEL,
    AUTH_DOMAIN_DYNAMIC_EXEC,
    AUTH_DOMAIN_HYPERVISOR,
    AUTH_DOMAIN_OBSERVED_ONLY
};

enum authority_state {
    AUTHORITY_TRUSTED,
    AUTHORITY_RESTRICTED,
    AUTHORITY_DEGRADED,
    AUTHORITY_QUARANTINED,
    AUTHORITY_REVOKED,
    AUTHORITY_TERMINAL
};

enum teleological_capability {
    CAP_EXEC_TRANSFORM         = (1ULL << 0),
    CAP_NAMESPACE_TRANSITION   = (1ULL << 1),
    CAP_KERNEL_MODIFY          = (1ULL << 2),
    CAP_PTRACE_FOREIGN         = (1ULL << 3),
    CAP_DYNAMIC_EXECUTION      = (1ULL << 4),
    CAP_MODULE_LOAD            = (1ULL << 5),
    CAP_BPF_ATTACH             = (1ULL << 6),
    CAP_PRIVILEGED_MEMORY      = (1ULL << 7)
};

struct legitimacy_vector {
    float structural;
    float behavioral;
    float continuity;
    float provenance;
};

// Phase 17: Semantic Conservation
struct authority_origin {
    transition_id_t source_transition;
    uint64_t parent_authority;
    float derivation_confidence;
    bool lineage_valid;
};

struct semantic_potential {
    float escalation;
    float propagation;
    float concealment;
    float destabilization;
};

struct execution_authority {
    uint64_t authority_id;
    enum authority_domain domain;
    
    struct authority_origin origin;
    struct semantic_potential potential;
    
    struct legitimacy_vector legitimacy;
    
    uint64_t granted_epoch;
    uint64_t last_validated_epoch;
    float authority_decay_rate;
    
    uint64_t capabilities;
    uint64_t capability_ceilings; // Negative capability bounds
    
    enum authority_state state;
};

struct authority_transition {
    uint64_t id;
    uint64_t semantic_epoch;
    struct actor_identity actor;
    
    uint64_t capabilities_revoked;
    uint64_t capabilities_granted;
    
    struct legitimacy_vector vector_delta;
    
    enum authority_state prev_state;
    enum authority_state next_state;
};

struct semantic_debt {
    float integrity;
    float provenance;
    float execution;
    float policy;
};

struct semantic_actor {
    struct actor_identity identity;
    uint32_t vcpu_id;
    
    uint64_t cr3;
    uint64_t normalized_cr3;
    uint64_t task_struct_addr;
    
    uint64_t mm;
    uint64_t active_mm;
    uint64_t rip;
    
    pid_t tgid;
    pid_t ppid;
    uid_t uid;
    gid_t gid;
    char comm[16];
    
    // Lineage Ancestry
    pid_t parent_pid;
    uint64_t parent_start_time;
    transition_id_t last_transition_id;
    enum execution_intent intent;
    
    // Namespace Isolation
    uint64_t mnt_ns;
    uint64_t pid_ns;
    uint64_t user_ns;
    
    enum actor_domain domain;
    enum attribution_state attrib_state;
    
    // Phase 15: Teleological Authority
    struct execution_authority authority;
    
    bool in_kernel;
    bool is_kthread;
    bool borrowed_mm;
    
    uint64_t last_seen_rip;
    uint64_t last_seen_timestamp;
    uint64_t last_seen_epoch;
    uint64_t execution_epoch;
    
    struct semantic_debt debt;
    float semantic_momentum;
    float attribution_confidence;
};

// ...

struct semantic_transition {
    uint64_t timestamp;
    struct executable_edge before;
    struct executable_edge after;
    enum integrity_score score;
    enum volatility_class expected;
    float confidence_malicious; // 0.0 to 1.0 probabilistic threat score
    bool irrecoverable;         // Set to true if semantic trust is destroyed
    struct semantic_actor actor; // Phase 13: The execution lineage that triggered this
    char description[128];
};

enum execution_edge_type {
    EDGE_FORK,
    EDGE_EXEC,
    EDGE_NAMESPACE_ENTER,
    EDGE_NAMESPACE_EXIT,
    EDGE_PTRACE,
    EDGE_MODULE_LOAD,
    EDGE_BPF_ATTACH
};

enum transition_cause {
    CAUSE_UNKNOWN,
    CAUSE_SCHEDULER,
    CAUSE_SYSCALL,
    CAUSE_VMEXIT,
    CAUSE_FAULT,
    CAUSE_MEDIATION,
    CAUSE_NAMESPACE_REBIND
};

struct execution_edge {
    enum execution_edge_type type;
    
    // Source -> Target Semantic Pointers
    struct actor_identity source;
    struct actor_identity target;
    
    // Continuity coefficients (0.0 to 1.0)
    float identity_continuity;
    float authority_continuity;
    
    // Temporal Window
    uint64_t start_epoch;
    uint64_t end_epoch;
    
    // Edge Reliability
    float transition_confidence;
};

struct execution_transition {
    transition_id_t id;
    transition_id_t parent_id;
    uint64_t timestamp;
    uint64_t semantic_epoch;
    enum transition_cause cause;
    float retention_score;
    struct execution_edge edge;
    bool irreversible_transition;
};

struct semantic_epoch {
    uint64_t epoch_id;
    uint64_t timestamp;
    struct semantic_transition *transitions;
    size_t nr_transitions;
};

// Returns the reverse-resolved symbol for a given address, or NULL
const struct symbol *symbol_reverse_resolve(struct symbol_table *table, uint64_t target_addr, uint64_t *offset);

// Region Topology API
int vmi_regions_init(struct vmi_session *s, struct symbol_table *syms);
const struct memory_region *vmi_find_region(struct vmi_session *s, uint64_t addr);

// MMU canonicality check
bool mmu_is_canonical(uint64_t addr);

// Generates the executable provenance for a given pointer
struct executable_provenance vmi_check_provenance(struct vmi_session *s, struct symbol_table *syms, uint64_t ptr);

// Validates the system call table using the provenance engine
int vmi_validate_syscall_table(struct vmi_session *s, struct symbol_table *syms);

// ──────────────────────────────────────────────
// Phase 8: Differential Semantic Replay
// ──────────────────────────────────────────────

// Main entry point for cross-snapshot differential replay API
// Returns number of anomalies and populates the transitions array
int vmi_differential_replay(struct vmi_session *session_a, struct vmi_session *session_b, struct symbol_table *syms, struct semantic_transition **out_transitions, size_t *out_count);

void vmi_log_transition(struct vmi_session *s, struct execution_transition *t);
void vmi_log_authority_transition(struct vmi_session *s, struct authority_transition *t);
void vmi_calculate_thermodynamics(struct vmi_session *s);
void vmi_project_trajectory(struct vmi_session *s);
struct counterfactual_result vmi_simulate_intervention(struct vmi_session *s, struct stabilization_chain *chain);

// Phase 20: Continuous Equilibrium Regulation
void vmi_regulate_equilibrium(struct vmi_session *s);

// ──────────────────────────────────────────────
// Phase 12: Active EPT/NPT Mediation Engine
// ──────────────────────────────────────────────

enum mediation_action {
    MEDIATE_ALLOW = 0,
    MEDIATE_TRAP,
    MEDIATE_WRITE_PROTECT,
    MEDIATE_EXEC_PROTECT,
    MEDIATE_FREEZE,
    MEDIATE_ALERT,
    MEDIATE_INJECT_GP,
    MEDIATE_INJECT_PF
};


struct mediation_decision {
    enum mediation_action action;
    enum enforcement_scope scope;
    float confidence;
    const char *reason;
};

// Trust Deltas
#define TRUST_DELTA_SYSCALL_DRIFT -0.25f
#define TRUST_DELTA_CORE_TEXT_WRITE -0.80f
#define TRUST_COLLAPSE_THRESHOLD 0.0f
#define DEBT_DECAY_FACTOR 0.9f

// Main VMExit entry point for EPT/NPT violation handling
struct mediation_decision vmi_handle_ept_violation(struct vmi_session *s, struct symbol_table *syms, uint64_t gpa, uint64_t gva, uint64_t raw_cr3, uint64_t rip, uint32_t vcpu_id, bool is_write, bool is_exec);

// Normalizes an architecture-specific CR3 (stripping PCID/KPTI)
uint64_t mmu_normalize_cr3(uint64_t raw_cr3);

// Reconstructs the semantic identity behind a CR3 MMU context
int task_walker_reconstruct_actor(struct vmi_session *s, uint64_t raw_cr3, uint64_t rip, uint32_t vcpu_id, struct semantic_actor **out_actor);
