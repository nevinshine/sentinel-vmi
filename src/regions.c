// src/regions.c — Sentinel VMI Region Topology Engine
//
// Centralizes spatial semantics by reconstructing the memory cartography
// of the kernel into an array of strictly bounded, typed memory regions.

#include "sentinel_vmi.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int cmp_region(const void *a, const void *b) {
    const struct memory_region *ra = (const struct memory_region *)a;
    const struct memory_region *rb = (const struct memory_region *)b;
    if (ra->start < rb->start) return -1;
    if (ra->start > rb->start) return 1;
    return 0;
}

static void add_region(struct vmi_session *s, uint64_t start, uint64_t end, enum region_type type, const char *name, bool r, bool w, bool x) {
    if (start >= end) return;
    
    if (s->nr_regions == 0) {
        s->regions = malloc(16 * sizeof(struct memory_region));
    } else if (s->nr_regions % 16 == 0) {
        s->regions = realloc(s->regions, (s->nr_regions + 16) * sizeof(struct memory_region));
    }
    
    struct memory_region *reg = &s->regions[s->nr_regions++];
    reg->region_id = s->nr_regions; // 1-indexed ID
    reg->start = start;
    reg->end = end;
    
    reg->declared.r = r;
    reg->declared.w = w;
    reg->declared.x = x;
    
    // Phase 11: Set stability contracts
    if (type == REGION_CORE_TEXT || type == REGION_CORE_RODATA) {
        reg->contract.allow_exec_transition = false;
        reg->contract.allow_permission_change = false;
        reg->contract.allow_symbol_drift = false;
        reg->contract.allow_edge_retarget = false;
    } else if (type == REGION_CORE_DATA) {
        reg->contract.allow_exec_transition = false; // Data should never become executable
        reg->contract.allow_permission_change = false;
        reg->contract.allow_symbol_drift = false;
        reg->contract.allow_edge_retarget = false;
    } else if (type == REGION_DYNAMIC_EXEC || type == REGION_MODULE_CANDIDATE) {
        reg->contract.allow_exec_transition = true;
        reg->contract.allow_permission_change = true;
        reg->contract.allow_symbol_drift = true;
        reg->contract.allow_edge_retarget = true;
    } else {
        // Safe default
        reg->contract.allow_exec_transition = false;
        reg->contract.allow_permission_change = false;
        reg->contract.allow_symbol_drift = true;
        reg->contract.allow_edge_retarget = true;
    }
    
    struct page_walk_result walk;
    if (vmi_mmu_translate(s, s->kernel_pgd, start, &walk) == 0) {
        reg->observed.r = walk.present; // Assume readable if present
        reg->observed.w = walk.writable;
        reg->observed.x = walk.executable;
    } else {
        // If unmapped at start, assume 0
        reg->observed.r = false;
        reg->observed.w = false;
        reg->observed.x = false;
    }
    
    reg->type = type;
    reg->name = name;
    
    printf("[Regions] Identified %-20s : 0x%016lx - 0x%016lx\n", name, start, end);
    if (reg->declared.x == false && reg->observed.x == true) {
        printf("    ↳ ⚠ MMU W^X VIOLATION: Region declared NX but observed Executable!\n");
    }
    if (reg->declared.w == false && reg->observed.w == true) {
        printf("    ↳ ⚠ MMU INTEGRITY VIOLATION: Region declared Read-Only but observed Writable!\n");
    }
}

int vmi_regions_init(struct vmi_session *s, struct symbol_table *syms) {
    if (!s || !syms) return -1;
    
    printf("[Regions] ═══════════════════════════════════════\n");
    printf("[Regions] Reconstructing Memory Topology\n");
    printf("[Regions] ═══════════════════════════════════════\n");
    
    uint64_t stext = symbol_resolve(syms, "_stext");
    uint64_t etext = symbol_resolve(syms, "_etext");
    add_region(s, stext, etext, REGION_CORE_TEXT, "CORE_TEXT", true, false, true);
    
    uint64_t srodata = symbol_resolve(syms, "__start_rodata");
    uint64_t erodata = symbol_resolve(syms, "__end_rodata");
    add_region(s, srodata, erodata, REGION_CORE_RODATA, "CORE_RODATA", true, false, false);
    
    uint64_t sdata = symbol_resolve(syms, "_sdata");
    uint64_t edata = symbol_resolve(syms, "_edata");
    add_region(s, sdata, edata, REGION_CORE_DATA, "CORE_DATA", true, true, false);
    
    uint64_t _end = symbol_resolve(syms, "_end");
    
    // Bootstrap heuristic for modules / dynamic exec
    uint64_t dyn_min = (uint64_t)-1;
    uint64_t dyn_max = 0;
    
    // We assume the symbol table is already sorted by address
    // (This was implemented in symbols.c in Phase 7)
    // We search for symbols of type 'T' or 't' outside the core kernel image.
    for (size_t i = 0; i < syms->count; i++) {
        uint64_t addr = syms->syms[i].addr;
        char type = syms->syms[i].type;
        
        if ((type == 'T' || type == 't') && (addr < stext || addr >= _end)) {
            if (addr < dyn_min) dyn_min = addr;
            if (addr > dyn_max) dyn_max = addr;
        }
    }
    
    // Pad the max boundary slightly to cover the last function
    if (dyn_max >= dyn_min && dyn_min != (uint64_t)-1) {
        add_region(s, dyn_min, dyn_max + 0x1000, REGION_DYNAMIC_EXEC, "DYNAMIC_EXEC", true, false, true);
    }
    
    // Sort regions by start address for O(log N) lookup
    qsort(s->regions, s->nr_regions, sizeof(struct memory_region), cmp_region);
    
    printf("[Regions] Topology cartography complete. %zu regions mapped.\n", s->nr_regions);
    return 0;
}

const struct memory_region *vmi_find_region(struct vmi_session *s, uint64_t addr) {
    if (!s || s->nr_regions == 0) return NULL;
    
    size_t low = 0;
    size_t high = s->nr_regions - 1;
    
    while (low <= high) {
        size_t mid = low + (high - low) / 2;
        const struct memory_region *r = &s->regions[mid];
        
        if (addr >= r->start && addr < r->end) {
            return r;
        }
        
        if (addr < r->start) {
            if (mid == 0) break;
            high = mid - 1;
        } else {
            low = mid + 1;
        }
    }
    
    return NULL;
}
