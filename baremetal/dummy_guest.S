.section .text
.global _start
_start:
    /* === Intent Scope 1: Network (0x42) === */
    /* Request network capability */
    li a0, 0x42
    ecall

    /* Valid network transmission */
    li t0, 0x87D00000
    li t1, 1
    sd t1, 0(t0)

tca_scope_end_net:
    /* Crossed limit PC for network scope — capability 0x42 revoked */

    /* === Intent Scope 2: Crypto (0x99) === */
    /* Request crypto capability */
    li a0, 0x99
    ecall

    /* Valid crypto transmission */
    li t0, 0x87D00000
    li t1, 3
    sd t1, 0(t0)

tca_scope_end_crypto:
    /* Crossed limit PC for crypto scope — capability 0x99 revoked */

    /* Attempt unauthorized transmission (both capabilities revoked) */
    li t1, 0xFF
    sd t1, 0(t0)

1:
    wfi
    j 1b

/* ================================================================
 * .telos_policy section: Two consecutive TelosPolicyEntry structs
 * Each entry: 56 bytes (8 + 8 + 8 + 32 bytes)
 * ================================================================ */
.section .telos_policy, "a"
.align 8

/* Entry 0: Network Intent (0x42) */
    .quad 0x42                          /* intent_hash */
    .quad 0x0                           /* start_pc_offset */
    .quad tca_scope_end_net - _start    /* limit_pc_offset */
    /* Bloom filter for 0x42:
       hash1 = 0x42 & 0xFF = 66 → word 1, bit 2
       hash2 = (0x42 >> 8) & 0xFF = 0 → word 0, bit 0 */
    .quad 0x1                           /* bloom word 0 */
    .quad 0x4                           /* bloom word 1 */
    .quad 0x0                           /* bloom word 2 */
    .quad 0x0                           /* bloom word 3 */

/* Entry 1: Crypto Intent (0x99) */
    .quad 0x99                          /* intent_hash */
    .quad 0x0                           /* start_pc_offset */
    .quad tca_scope_end_crypto - _start /* limit_pc_offset */
    /* Bloom filter for 0x99:
       hash1 = 0x99 & 0xFF = 153 → word 2, bit 25
       hash2 = (0x99 >> 8) & 0xFF = 0 → word 0, bit 0 */
    .quad 0x1                           /* bloom word 0 */
    .quad 0x0                           /* bloom word 1 */
    .quad 0x2000000                     /* bloom word 2: bit 25 */
    .quad 0x0                           /* bloom word 3 */
