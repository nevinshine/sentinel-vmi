#ifndef POLICY_H
#define POLICY_H

#include <stdint.h>

#define MAX_CAPABILITIES 8

/* Matches the payload structure emitted by LLVM SentinelPass */
typedef struct __attribute__((packed)) {
  uint64_t intent_hash;
  uint64_t start_pc_offset;
  uint64_t limit_pc_offset;
  uint8_t bloom_filter[32]; // 256-bit
} TelosPolicyEntry;

/* Phase 3: Multi-Capability Table */
typedef struct {
  TelosPolicyEntry policy;
  uint64_t abs_limit_pc; /* Absolute limit PC (resolved at boot) */
  uint8_t active;        /* 0 = available, 1 = granted */
  uint8_t revoked;       /* 1 = already expired */
} CapabilitySlot;

typedef struct {
  CapabilitySlot slots[MAX_CAPABILITIES];
  uint32_t count; /* Number of loaded policies */
} CapabilityTable;

#endif // POLICY_H
