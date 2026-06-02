#ifndef POLICY_H
#define POLICY_H

#include <stdint.h>

/* Matches the payload structure emitted by LLVM SentinelPass */
typedef struct __attribute__((packed)) {
    uint64_t intent_hash;
    uint64_t start_pc_offset;
    uint64_t limit_pc_offset;
    uint8_t  bloom_filter[32]; // 256-bit
} TelosPolicyEntry;

#endif // POLICY_H
