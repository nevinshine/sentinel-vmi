/* TCA Hypervisor Linker Script */
ENTRY(_start_boot)

SECTIONS
{
    . = 0x80000000;

    .text : {
        _hypervisor_start = .;
        *(.text.boot)
        *(.text)
        *(.text.*)
    }

    .rodata : {
        *(.rodata)
        *(.rodata.*)
    }

    .data : ALIGN(8) {
        *(.data)
        *(.data.*)
    }

    .bss : ALIGN(8) {
        *(.bss)
        *(.bss.*)
    }

    . = ALIGN(4096);
    _hypervisor_end = .;

    /DISCARD/ : {
        *(.comment)
        *(.note.*)
        *(.eh_frame*)
        *(.riscv.attributes)
    }
}
