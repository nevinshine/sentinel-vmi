.section .text
.global _start
_start:
    /* Request Intent 0x42 */
    li a0, 0x42
    ecall

    /* Valid Transmission */
    li t0, 0x87D00000
    li t1, 1
    sd t1, 0(t0)

tca_scope_end:
    /* We have now crossed the limit PC. The TCG should revoke the capability. */
    /* Second Transmission (should trap with [TCA SILICON FAULT]) */
    li t1, 2
    sd t1, 0(t0)

1:
    wfi
    j 1b

.section .telos_policy, "a"
.align 8
    .quad 0x42                /* intent_hash */
    .quad 0x0                 /* start_pc_offset */
    .quad tca_scope_end - _start /* limit_pc_offset */
    /* 32 bytes of Bloom filter:
       word0 = 1 (bit 0 set for hash2=0)
       word1 = 4 (bit 2 set for hash1=66)
       word2..3 = 0
    */
    .quad 0x1
    .quad 0x4
    .quad 0x0
    .quad 0x0
