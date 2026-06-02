.section .text.boot
.global _start_boot
_start_boot:
    /* Setup stack to point to end of 128MB RAM block */
    li sp, 0x88000000

    /* Jump to C code */
    call _start

    /* Halt on return */
1:
    wfi
    j 1b

.section .data
.global guest_payload_start
.global guest_payload_end
.align 8
guest_payload_start:
    .incbin "guest_payload.elf"
guest_payload_end:
