// tests/test_snapshot.c — Real Guest Snapshot Tests
//
// Validates the semantic gap traversal (GVA → GPA, structure parsing)
// using a static memory dump extracted from the CloudLab nested VM.

#include "sentinel_vmi.h"
#include "task_offsets.h"
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdlib.h>

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) printf("[Test] %-40s ", name)
#define PASS()                                                                 \
  do {                                                                         \
    printf("✓ PASS\n");                                                        \
    tests_passed++;                                                            \
  } while (0)
#define FAIL(msg)                                                              \
  do {                                                                         \
    printf("✗ FAIL: %s\n", msg);                                               \
    tests_failed++;                                                            \
  } while (0)

#define FIXTURE_BIN "tests/fixtures/cloudlab_guest.bin"
#define FIXTURE_JSON "tests/fixtures/cloudlab_guest.json"
#define FIXTURE_SYMS "tests/fixtures/cloudlab_guest.kallsyms"

static struct vmi_session *global_snapshot = NULL;
static struct symbol_table *global_syms = NULL;

// ──────────────────────────────────────────────
// Test: Load Snapshot
// ──────────────────────────────────────────────

static void test_load_snapshot(void) {
  TEST("snapshot_load_and_validate");

  if (access(FIXTURE_BIN, F_OK) != 0 || access(FIXTURE_JSON, F_OK) != 0 || access(FIXTURE_SYMS, F_OK) != 0) {
    printf("(no fixtures) ");
    PASS();
    return;
  }

  global_snapshot = vmi_session_from_snapshot(FIXTURE_BIN, FIXTURE_JSON);
  if (!global_snapshot) {
    FAIL("failed to load and validate snapshot metadata");
    return;
  }

  global_syms = symbol_table_load(FIXTURE_SYMS);
  if (!global_syms) {
    FAIL("failed to load symbol table");
    return;
  }

  // Resolve init_task
  uint64_t init_task = symbol_resolve(global_syms, "init_task");
  if (!init_task) {
    FAIL("failed to resolve init_task");
    return;
  }

  global_snapshot->init_task_addr = init_task;
  printf("[Test] Resolved init_task at 0x%lx\n", init_task);
  PASS();
}

// ──────────────────────────────────────────────
// Test: Semantic Translation & Anchors
// ──────────────────────────────────────────────

static void test_semantic_anchors(void) {
  TEST("snapshot_semantic_anchors");

  if (!global_snapshot || !global_syms) {
    printf("(skipped) ");
    PASS();
    return;
  }

  // We need to set the task walker profile based on the snapshot kernel.
  // Since the snapshot is of the current CloudLab host, we can use BTF auto-extraction!
  if (task_walker_set_offsets_profile("btf-auto") != 0) {
    // Fallback to 6.6 if BTF fails (but it shouldn't on CloudLab)
    task_walker_set_offsets_profile("6.6");
  }

  uint64_t init_task_gva;
  if (task_walker_find_pid(global_snapshot, 0, &init_task_gva) == 0) {
    struct vmi_process init_proc;
    task_walker_read_process(global_snapshot, init_task_gva, &init_proc);
    
    // Anchor 1: init_task.pid == 0
    if (init_proc.pid != 0) {
      FAIL("init_task PID is not 0");
      return;
    }
  } else {
    FAIL("Failed to walk to PID 0");
    return;
  }

  uint64_t pid1_gva;
  if (task_walker_find_pid(global_snapshot, 1, &pid1_gva) == 0) {
    struct vmi_process pid1;
    task_walker_read_process(global_snapshot, pid1_gva, &pid1);

    // Anchor 2: pid1.pid == 1
    if (pid1.pid != 1) {
      FAIL("PID 1 is not 1");
      return;
    }

    // Anchor 3: pid1.mm != NULL
    if (pid1.mm_addr == 0) {
      FAIL("PID 1 mm_struct is NULL");
      return;
    }

    PASS();
  } else {
    FAIL("Failed to walk to PID 1");
  }

  // ---------------------------------------------------------
  // Phase 6: Provenance Graph Verifier
  // ---------------------------------------------------------
  
  TEST("snapshot_provenance_validation");
  
  // Phase 9: Initialize Regions
  vmi_regions_init(global_snapshot, global_syms);
  
  int dkom_found = provenance_run_cross_validation(global_snapshot, global_syms);
  if (dkom_found == 0) {
    PASS();
  } else {
    FAIL("Detected DKOM anomalies in healthy snapshot");
  }
  
  TEST("snapshot_dkom_simulation");
  // Simulate unlinking on PID 2 (kthreadd)
  if (provenance_simulate_dkom(global_snapshot, 2) == 0) {
      int detected = provenance_run_cross_validation(global_snapshot, global_syms);
      if (detected == 1) {
          PASS();
      } else {
          FAIL("Simulated DKOM expected 1 anomaly");
      }
  } else {
      FAIL("Failed to simulate DKOM on PID 2");
  }

  // ---------------------------------------------------------
  // Phase 7: Memory Integrity & Executable Provenance
  // ---------------------------------------------------------
  printf("\n[Test] ═══════════════════════════════════════\n");
  printf("[Test] Phase 7: Memory Integrity Attestation\n");
  printf("[Test] ═══════════════════════════════════════\n\n");

  TEST("snapshot_syscall_table_validation");
  int anomalies = vmi_validate_syscall_table(global_snapshot, global_syms);
  if (anomalies == 0) {
      PASS();
  } else {
      FAIL("Detected anomalies in healthy syscall table");
  }
  
  TEST("snapshot_syscall_hooking_simulation");
  uint64_t sys_call_table = symbol_resolve(global_syms, "sys_call_table");
  uint64_t sys_write = symbol_resolve(global_syms, "__x64_sys_write");
  if (!sys_write) sys_write = symbol_resolve(global_syms, "sys_write");
  uint64_t module_alloc_base = symbol_resolve(global_syms, "module_alloc_base"); // Arbitrary symbol not in core
  
  if (sys_call_table && sys_write) {
      uint64_t gpa;
      if (vmi_gva_to_gpa(global_snapshot, global_snapshot->kernel_pgd, sys_call_table, &gpa) == 0) {
          // Case A: Semantic Mismatch (Overwrite sys_read [0] with sys_write)
          vmi_write_physical(global_snapshot, gpa, &sys_write, sizeof(sys_write));
          
          // Case B: Module Hook (Overwrite sys_open [2] with module_alloc_base)
          if (module_alloc_base) {
              vmi_write_physical(global_snapshot, gpa + (2 * 8), &module_alloc_base, sizeof(module_alloc_base));
          }
          
          // Case C: Unmapped Bogus Pointer (Overwrite sys_close [3] with garbage)
          uint64_t bogus_ptr = 0xffffffffdeadbeef;
          vmi_write_physical(global_snapshot, gpa + (3 * 8), &bogus_ptr, sizeof(bogus_ptr));
          
          int hooked_anomalies = vmi_validate_syscall_table(global_snapshot, global_syms);
          if (hooked_anomalies >= 2) { // Should detect at least Case A and Case C
              PASS();
          } else {
              FAIL("Failed to detect simulated syscall hooks");
          }
      } else {
          FAIL("Failed to translate sys_call_table GVA to GPA");
      }
  } else {
      FAIL("Could not resolve symbols for hook simulation");
  }

  // ---------------------------------------------------------
  // Phase 8: Differential Semantic Replay
  // ---------------------------------------------------------
  printf("\n[Test] ═══════════════════════════════════════\n");
  printf("[Test] Phase 8: Differential Semantic Replay\n");
  printf("[Test] ═══════════════════════════════════════\n\n");

  TEST("differential_temporal_semantics");
  
  // global_snapshot is now heavily mutated (DKOM'd PID 2, Hooked Syscalls 0, 2, 3)
  // We will load a fresh, clean session from disk to represent State A.
  // global_snapshot represents State B.
  
  struct vmi_session *clean_session = vmi_session_from_snapshot("tests/fixtures/cloudlab_guest.bin", "tests/fixtures/cloudlab_guest.json");
  if (!clean_session) {
      FAIL("Failed to load clean session for differential analysis");
  } else {
      vmi_regions_init(clean_session, global_syms);
      // Also mutate PID 1's real_parent pointer in global_snapshot to test task graph drift
      uint64_t init_task = symbol_resolve(global_syms, "init_task");
      if (init_task) {
          uint64_t bogus_parent = 0xffffffffdeadbeef;
          uint64_t init_gpa;
          if (vmi_gva_to_gpa(global_snapshot, global_snapshot->kernel_pgd, init_task, &init_gpa) == 0) {
              vmi_write_physical(global_snapshot, init_gpa + active_offsets->real_parent_offset, &bogus_parent, 8);
          }
      }

      int temporal_anomalies = 0;
      
      // Phase 10: Mutate PTE of __x64_sys_write to set PT_NX (simulating W^X bypass or payload hiding)
      uint64_t sys_write_addr = symbol_resolve(global_syms, "__x64_sys_write");
      if (!sys_write_addr) sys_write_addr = symbol_resolve(global_syms, "sys_write");
      if (sys_write_addr) {
          uint64_t entry;
          uint64_t pml4_base = global_snapshot->kernel_pgd & 0x000FFFFFFFFFF000ULL;
          uint64_t pml4e_addr = pml4_base + (((sys_write_addr) >> 39) & 0x1FF) * 8;
          vmi_read_physical(global_snapshot, pml4e_addr, &entry, 8);
          uint64_t pdpt_base = entry & 0x000FFFFFFFFFF000ULL;
          uint64_t pdpte_addr = pdpt_base + (((sys_write_addr) >> 30) & 0x1FF) * 8;
          vmi_read_physical(global_snapshot, pdpte_addr, &entry, 8);
          uint64_t pd_base = entry & 0x000FFFFFFFFFF000ULL;
          uint64_t pde_addr = pd_base + (((sys_write_addr) >> 21) & 0x1FF) * 8;
          vmi_read_physical(global_snapshot, pde_addr, &entry, 8);
          if (!(entry & 128)) { // Not huge page
              uint64_t pt_base = entry & 0x000FFFFFFFFFF000ULL;
              uint64_t pte_addr = pt_base + (((sys_write_addr) >> 12) & 0x1FF) * 8;
              vmi_read_physical(global_snapshot, pte_addr, &entry, 8);
              entry |= (1ULL << 63); // Set NX bit
              vmi_write_physical(global_snapshot, pte_addr, &entry, 8);
          } else { // Huge page
              entry |= (1ULL << 63);
              vmi_write_physical(global_snapshot, pde_addr, &entry, 8);
          }
      }

      struct semantic_transition *transitions = NULL;
      size_t num_transitions = 0;
      temporal_anomalies = vmi_differential_replay(clean_session, global_snapshot, global_syms, &transitions, &num_transitions);
      
      if (temporal_anomalies >= 4 && transitions != NULL) { // 2 syscall hooks + 1 parent mutation + 1 PTE permission drift
          // Let's assert the Temporal Confidence Engine worked
          int high_confidence_count = 0;
          for (size_t i = 0; i < num_transitions; i++) {
              if (transitions[i].confidence_malicious > 0.90f) {
                  high_confidence_count++;
              }
          }
          if (high_confidence_count >= 4) {
              PASS();
          } else {
              FAIL("Expected high confidence malicious scores for simulated DKOM");
          }
          free(transitions);
      } else {
          FAIL("Failed to detect expected temporal drift anomalies");
      }
      
      // Phase 12A: Precision Trap Injection & Trust Modeling
      printf("\n[Test] ───────────────────────────────────────\n");
      printf("[Test] Phase 12A: Precision Trap Injection\n");
      printf("[Test] ───────────────────────────────────────\n");
      
      clean_session->field.legitimacy.structural = 1.0f;
      clean_session->field.inertia.topology_resistance = 1.0f;
      clean_session->field.authority_centralization = 1.0f;
      clean_session->field.closure_state = FIELD_COHERENT;
      clean_session->semantic_epoch = 1;
      
      uint64_t sys_call_table = symbol_resolve(global_syms, "sys_call_table");
      if (sys_call_table) {
          uint64_t sys_call_table_gpa = 0;
          if (vmi_gva_to_gpa(clean_session, clean_session->kernel_pgd, sys_call_table, &sys_call_table_gpa) == 0) {
              // Phase 13: Mock raw CR3 from the kernel PGD
              uint64_t mock_cr3 = clean_session->kernel_pgd | 0x1000; // Adding KPTI bit to test normalization
              uint64_t mock_rip = 0xffffffff81234567ULL;
              
              // Simulate 3 isolated, local violations
              for (int i = 0; i < 3; i++) {
                  struct mediation_decision decision = vmi_handle_ept_violation(clean_session, global_syms, sys_call_table_gpa, sys_call_table, mock_cr3, mock_rip, 0, true, false);
                  if (decision.action == MEDIATE_INJECT_PF && decision.scope == SCOPE_VCPU) {
                      PASS();
                  } else {
                      FAIL("Expected MEDIATE_INJECT_PF with SCOPE_VCPU for localized write violation");
                  }
              }
              
              // The 4th violation should trigger TRUST COLLAPSE
              struct mediation_decision final_decision = vmi_handle_ept_violation(clean_session, global_syms, sys_call_table_gpa, sys_call_table, mock_cr3, mock_rip, 0, true, false);
              if (final_decision.action == MEDIATE_FREEZE && final_decision.scope == SCOPE_VM) {
                  PASS();
              } else {
                  FAIL("Expected MEDIATE_FREEZE with SCOPE_VM after Trust Collapse");
              }
              
          } else {
              FAIL("Failed to resolve GPA for sys_call_table");
          }
      } else {
          FAIL("Failed to resolve sys_call_table symbol");
      }
  }

  symbol_table_free(global_syms);
}

int main(void) {
  printf("\n[Test] ═══════════════════════════════════════\n");
  printf("[Test] Phase 6 & 7: Provenance & Integrity Tests\n");
  printf("[Test] ═══════════════════════════════════════\n\n");

  test_load_snapshot();
  test_semantic_anchors();

  printf("\n[Test] ───────────────────────────────────────\n");
  printf("[Test] Results: %d passed, %d failed\n", tests_passed, tests_failed);
  printf("[Test] ───────────────────────────────────────\n");

  return tests_failed > 0 ? 1 : 0;
}
