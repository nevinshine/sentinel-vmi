.section .text
.global trap_entry
.align 4
trap_entry:
    /* Allocate stack space for 16 caller-saved registers + ra */
    addi sp, sp, -136
    sd ra, 0(sp)
    sd a0, 8(sp)
    sd a1, 16(sp)
    sd a2, 24(sp)
    sd a3, 32(sp)
    sd a4, 40(sp)
    sd a5, 48(sp)
    sd a6, 56(sp)
    sd a7, 64(sp)
    sd t0, 72(sp)
    sd t1, 80(sp)
    sd t2, 88(sp)
    sd t3, 96(sp)
    sd t4, 104(sp)
    sd t5, 112(sp)
    sd t6, 120(sp)

    /* a0 already contains the requested intent from the U-Mode ecall.
       We call handle_trap(a0) */
    call handle_trap

    /* Restore caller-saved registers */
    ld ra, 0(sp)
    ld a0, 8(sp)
    ld a1, 16(sp)
    ld a2, 24(sp)
    ld a3, 32(sp)
    ld a4, 40(sp)
    ld a5, 48(sp)
    ld a6, 56(sp)
    ld a7, 64(sp)
    ld t0, 72(sp)
    ld t1, 80(sp)
    ld t2, 88(sp)
    ld t3, 96(sp)
    ld t4, 104(sp)
    ld t5, 112(sp)
    ld t6, 120(sp)
    addi sp, sp, 136

    mret
