#include "sentinel_vmi.h"
#include "task_offsets.h"
#include <stdio.h>
#include <stdlib.h>

extern const struct task_offsets *active_offsets;

#define XA_CHUNK_SHIFT 6
#define XA_CHUNK_SIZE  (1 << XA_CHUNK_SHIFT)
#define XA_CHUNK_MASK  (XA_CHUNK_SIZE - 1)

static int is_xa_node(uint64_t entry) {
    return (entry & 3) == 2;
}

static int is_xa_value(uint64_t entry) {
    return (entry & 3) == 0 && entry != 0;
}

static uint64_t xa_to_node(uint64_t entry) {
    return entry & ~3ULL;
}

static uint64_t xa_to_value(uint64_t entry) {
    return entry;
}

static void add_radix_pid(struct vmi_graph_verifier *gv, uint32_t pid) {
    if (gv->radix_tree_count >= 8192) return;
    for (uint32_t i = 0; i < gv->radix_tree_count; i++) {
        if (gv->radix_tree_pids[i] == pid) return;
    }
    gv->radix_tree_pids[gv->radix_tree_count++] = pid;
}

static void add_list_pid(struct vmi_graph_verifier *gv, uint32_t pid) {
    if (gv->linked_list_count >= 8192) return;
    for (uint32_t i = 0; i < gv->linked_list_count; i++) {
        if (gv->linked_list_pids[i] == pid) return;
    }
    gv->linked_list_pids[gv->linked_list_count++] = pid;
}

static void process_pid_struct(struct vmi_session *s, struct vmi_graph_verifier *gv, uint64_t pid_addr) {
    // pid.tasks is an array of hlist_head at offset 16. PIDTYPE_PID is index 0.
    uint64_t hlist_first;
    if (vmi_read_virtual(s, s->kernel_pgd, pid_addr + 16, &hlist_first, sizeof(hlist_first)) < 0) return;
    
    uint64_t current_node = hlist_first;
    int safety = 0;
    while (current_node != 0 && safety < 128) {
        if (active_offsets->pid_links_offset == 0) break; // BTF fallback required
        
        uint64_t task_addr = current_node - active_offsets->pid_links_offset;
        
        uint32_t pid, tgid;
        if (vmi_read_virtual(s, s->kernel_pgd, task_addr + active_offsets->pid_offset, &pid, sizeof(pid)) == 0 &&
            vmi_read_virtual(s, s->kernel_pgd, task_addr + active_offsets->tgid_offset, &tgid, sizeof(tgid)) == 0) {
            if (pid == tgid) {
                add_radix_pid(gv, pid);
            }
        }
        
        // Read next hlist_node (offset 0)
        vmi_read_virtual(s, s->kernel_pgd, current_node, &current_node, sizeof(current_node));
        safety++;
    }
}

static void walk_xarray(struct vmi_session *s, struct vmi_graph_verifier *gv, uint64_t xa_head, int depth) {
    if (xa_head == 0 || depth > 10) return;
    
    if (is_xa_node(xa_head)) {
        uint64_t node_addr = xa_to_node(xa_head);
        uint64_t slots[64];
        if (vmi_read_virtual(s, s->kernel_pgd, node_addr + 40, slots, sizeof(slots)) < 0) return;
        
        for (int i = 0; i < 64; i++) {
            if (slots[i]) {
                walk_xarray(s, gv, slots[i], depth + 1);
            }
        }
    } else if (is_xa_value(xa_head)) {
        uint64_t pid_struct_addr = xa_to_value(xa_head);
        process_pid_struct(s, gv, pid_struct_addr);
    }
}

int provenance_run_cross_validation(struct vmi_session *s, struct symbol_table *syms) {
    if (!s || !syms || s->init_task_addr == 0) return -1;
    
    printf("[Provenance] ═══════════════════════════════════════\n");
    printf("[Provenance] Starting Semantic Provenance Engine\n");
    printf("[Provenance] ═══════════════════════════════════════\n");
    
    struct vmi_graph_verifier gv;
    gv.linked_list_pids = calloc(8192, sizeof(uint32_t));
    gv.linked_list_count = 0;
    gv.radix_tree_pids = calloc(8192, sizeof(uint32_t));
    gv.radix_tree_count = 0;
    
    // 1. Walk linked list
    printf("[Provenance] Reconstructing linked list graph...\n");
    uint64_t current = s->init_task_addr;
    int safety = 0;
    do {
        uint32_t pid;
        vmi_read_virtual(s, s->kernel_pgd, current + active_offsets->pid_offset, &pid, sizeof(pid));
        add_list_pid(&gv, pid);
        
        uint64_t list_next;
        vmi_read_virtual(s, s->kernel_pgd, current + active_offsets->tasks_offset, &list_next, sizeof(list_next));
        current = list_next - active_offsets->tasks_offset;
        safety++;
    } while (current != s->init_task_addr && safety < 8192);
    printf("[Provenance] Found %u tasks in doubly-linked list.\n", gv.linked_list_count);
    
    // 2. Walk Radix Tree
    printf("[Provenance] Reconstructing PID Radix Tree...\n");
    uint64_t init_pid_ns = symbol_resolve(syms, "init_pid_ns");
    if (init_pid_ns) {
        uint64_t xa_head;
        // idr offset 0 -> xarray offset 0 -> xa_head offset 8
        if (vmi_read_virtual(s, s->kernel_pgd, init_pid_ns + 8, &xa_head, sizeof(xa_head)) == 0) {
            walk_xarray(s, &gv, xa_head, 0);
        }
    }
    printf("[Provenance] Found %u tasks in PID Radix Tree.\n", gv.radix_tree_count);
    
    // 3. Cross Validate
    printf("[Provenance] Cross-validating graph invariants...\n");
    int dkom_found = 0;
    for (uint32_t i = 0; i < gv.radix_tree_count; i++) {
        uint32_t rpid = gv.radix_tree_pids[i];
        int found = 0;
        for (uint32_t j = 0; j < gv.linked_list_count; j++) {
            if (gv.linked_list_pids[j] == rpid) {
                found = 1;
                break;
            }
        }
        if (!found && rpid != 0) { // PID 0 is idle, often not in radix tree or special handled
            printf("[Provenance] ⚠ DKOM DETECTED: PID %u is in Radix Tree but hidden from linked list!\n", rpid);
            dkom_found++;
        }
    }
    
    if (dkom_found == 0) {
        printf("[Provenance] ✓ Graph invariants satisfied. No structural asymmetry detected.\n");
    }
    
    free(gv.linked_list_pids);
    free(gv.radix_tree_pids);
    
    return dkom_found;
}

int provenance_simulate_dkom(struct vmi_session *s, uint32_t target_pid) {
    if (!s || s->init_task_addr == 0) return -1;
    
    uint64_t current = s->init_task_addr;
    int safety = 0;
    do {
        uint32_t pid;
        vmi_read_virtual(s, s->kernel_pgd, current + active_offsets->pid_offset, &pid, sizeof(pid));
        
        if (pid == target_pid) {
            printf("[DKOM Sim] Found target PID %u at 0x%lx\n", pid, current);
            
            // Read tasks.prev and tasks.next
            uint64_t prev, next;
            vmi_read_virtual(s, s->kernel_pgd, current + active_offsets->tasks_offset, &next, sizeof(next));
            vmi_read_virtual(s, s->kernel_pgd, current + active_offsets->tasks_offset + 8, &prev, sizeof(prev));
            
            uint64_t prev_gpa, next_gpa;
            vmi_gva_to_gpa(s, s->kernel_pgd, prev, &prev_gpa);
            vmi_gva_to_gpa(s, s->kernel_pgd, next + 8, &next_gpa);
            
            vmi_write_physical(s, prev_gpa, &next, sizeof(next));
            vmi_write_physical(s, next_gpa, &prev, sizeof(prev));
            
            printf("[DKOM Sim] Successfully unlinked PID %u from tasks.next graph!\n", pid);
            return 0;
        }
        
        uint64_t list_next;
        vmi_read_virtual(s, s->kernel_pgd, current + active_offsets->tasks_offset, &list_next, sizeof(list_next));
        current = list_next - active_offsets->tasks_offset;
        safety++;
    } while (current != s->init_task_addr && safety < 8192);
    
    printf("[DKOM Sim] Target PID %u not found.\n", target_pid);
    return -1;
}
