// src/symbols.c — Sentinel VMI Symbol Acquisition Layer
//
// Parses a guest-extracted /proc/kallsyms artifact into a fully 
// isolated, stateless symbol table mapping for deterministic 
// semantic traversal.

#include "sentinel_vmi.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>



// Helper for qsort
static int cmp_symbol(const void *a, const void *b) {
  const struct symbol *sa = (const struct symbol *)a;
  const struct symbol *sb = (const struct symbol *)b;
  if (sa->addr < sb->addr) return -1;
  if (sa->addr > sb->addr) return 1;
  return 0;
}

// ──────────────────────────────────────────────
// API: Load Symbol Table
// ──────────────────────────────────────────────
struct symbol_table *symbol_table_load(const char *path) {
  FILE *f = fopen(path, "r");
  if (!f) {
    fprintf(stderr, "[Symbols] Failed to open symbol file: %s\n", path);
    return NULL;
  }

  struct symbol_table *table = calloc(1, sizeof(struct symbol_table));
  if (!table) {
    fclose(f);
    return NULL;
  }

  table->capacity = 100000;
  table->syms = malloc(table->capacity * sizeof(struct symbol));
  table->count = 0;

  char line[256];
  while (fgets(line, sizeof(line), f)) {
    if (table->count >= table->capacity) {
      table->capacity *= 2;
      table->syms = realloc(table->syms, table->capacity * sizeof(struct symbol));
    }

    uint64_t addr;
    char type;
    char name[128];

    // Format: "ffffffff81000000 T startup_64"
    if (sscanf(line, "%lx %c %127s", &addr, &type, name) == 3) {
      table->syms[table->count].addr = addr;
      table->syms[table->count].type = type;
      table->syms[table->count].name = strdup(name);
      table->count++;
    }
  }

  fclose(f);
  
  // Sort symbols by address for efficient O(log N) reverse resolution
  qsort(table->syms, table->count, sizeof(struct symbol), cmp_symbol);
  
  printf("[Symbols] Loaded and sorted %zu symbols from %s\n", table->count, path);
  return table;
}

// ──────────────────────────────────────────────
// API: Free Symbol Table
// ──────────────────────────────────────────────
void symbol_table_free(struct symbol_table *table) {
  if (!table) return;
  for (size_t i = 0; i < table->count; i++) {
    free(table->syms[i].name);
  }
  free(table->syms);
  free(table);
}

// ──────────────────────────────────────────────
// API: Resolve Symbol
// ──────────────────────────────────────────────
uint64_t symbol_resolve(struct symbol_table *table, const char *sym_name) {
  if (!table || !sym_name) return 0;

  for (size_t i = 0; i < table->count; i++) {
    if (strcmp(table->syms[i].name, sym_name) == 0) {
      return table->syms[i].addr;
    }
  }

  return 0; // Not found
}

// ──────────────────────────────────────────────
// API: Reverse Resolve Symbol (Binary Search)
// ──────────────────────────────────────────────
const struct symbol *symbol_reverse_resolve(struct symbol_table *table, uint64_t target_addr, uint64_t *offset) {
  if (!table || table->count == 0) return NULL;

  size_t low = 0;
  size_t high = table->count - 1;
  const struct symbol *best_match = NULL;

  while (low <= high) {
    size_t mid = low + (high - low) / 2;
    if (table->syms[mid].addr <= target_addr) {
      best_match = &table->syms[mid];
      // Keep searching right for a closer match
      low = mid + 1;
    } else {
      // mid is > target_addr
      if (mid == 0) break;
      high = mid - 1;
    }
  }

  // Validate the ownership invariant: symbol.addr <= target_addr < next_symbol.addr
  if (best_match) {
    size_t best_idx = best_match - table->syms;
    if (best_idx + 1 < table->count) {
      if (target_addr >= table->syms[best_idx + 1].addr) {
        // This shouldn't happen with the binary search above, but just in case
        return NULL;
      }
    }
    
    // We enforce an arbitrary sanity bound (e.g., 16MB) to prevent matching 
    // a pointer to a symbol that is extremely far away
    if (target_addr - best_match->addr > 16 * 1024 * 1024) {
        return NULL;
    }
    
    if (offset) *offset = target_addr - best_match->addr;
    return best_match;
  }

  return NULL;
}
