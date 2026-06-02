#include <stdint.h>
#include <stddef.h>
#include "elf_parser.h"

/* Minimal UART implementation for debug output */
#define UART_BASE 0x10000000
#define UART_THR  (volatile uint8_t*)(UART_BASE + 0x00)
#define UART_LSR  (volatile uint8_t*)(UART_BASE + 0x05)

static void uart_putc(char c) {
    while ((*UART_LSR & 0x20) == 0);
    *UART_THR = c;
}

static void uart_puts(const char *str) {
    while (*str) {
        uart_putc(*str++);
    }
}

static void print_hex(uint64_t val) {
    uart_puts("0x");
    for (int i = 15; i >= 0; i--) {
        int nibble = (val >> (i * 4)) & 0xF;
        uart_putc(nibble < 10 ? '0' + nibble : 'A' + nibble - 10);
    }
    uart_puts("\n");
}

/* Guest payload embedded via incbin in boot.S */
extern uint8_t guest_payload_start[];
extern uint8_t guest_payload_end[];

TelosPolicyEntry global_policy;
uint64_t global_abs_entry;
extern void trap_entry(void);

void handle_trap(uint64_t a0) {
    uint64_t mcause;
    uint64_t mepc;
    uint64_t mtval;
    __asm__ volatile("csrr %0, mcause" : "=r"(mcause));
    __asm__ volatile("csrr %0, mepc"   : "=r"(mepc));
    __asm__ volatile("csrr %0, mtval"  : "=r"(mtval));

    if (mcause == 8) { // U-Mode ecall
        uart_puts("\n[M-MODE HYPERVISOR] Intercepted U-Mode ecall.\n");
        uart_puts(" -> Authenticating intent request: "); print_hex(a0);
        
        if (a0 == global_policy.intent_hash) {
            uart_puts(" -> AUTHENTICATED. Provisioning TCA hardware datapath...\n");
            
            // 1. Provision Intent
            __asm__ volatile("csrw 0x800, %0" : : "r"(global_policy.intent_hash));
            
            // 2. Provision Bloom Filter
            uint64_t *bloom = (uint64_t*)global_policy.bloom_filter;
            __asm__ volatile("csrw 0x805, %0" : : "r"(bloom[0]));
            __asm__ volatile("csrw 0x806, %0" : : "r"(bloom[1]));
            __asm__ volatile("csrw 0x807, %0" : : "r"(bloom[2]));
            __asm__ volatile("csrw 0x808, %0" : : "r"(bloom[3]));
            
            // 3. Provision Spatial Limit
            uint64_t limit_pc = global_abs_entry + global_policy.limit_pc_offset;
            __asm__ volatile("csrw 0x809, %0" : : "r"(limit_pc));
            
            // Also configure dynamic bounds for testing (ADDR1 is TX Sink)
            uint64_t tca_addr1 = 0x87D00000;
            __asm__ volatile("csrw 0x804, %0" : : "r"(tca_addr1));
            uint64_t tca_cfg = (global_policy.intent_hash << 32) | 0x0A;
            __asm__ volatile("csrw 0x802, %0" : : "r"(tca_cfg));
            
            uart_puts(" -> Datapath mapped. Resuming U-Mode.\n");
            
            mepc += 4;
            __asm__ volatile("csrw mepc, %0" : : "r"(mepc));
            return;
        } else {
            uart_puts(" -> ACCESS DENIED. Intent does not match policy.\n");
            while(1);
        }
    }
    
    uart_puts("\n[M-MODE HYPERVISOR] UNHANDLED TRAP!\n");
    uart_puts("mcause: "); print_hex(mcause);
    uart_puts("mepc:   "); print_hex(mepc);
    uart_puts("mtval:  "); print_hex(mtval);
    while(1);
}

void _start() {
    uart_puts("\n======================================================\n");
    uart_puts("[M-MODE HYPERVISOR] Booting TCA Bare-Metal Orchestrator\n");
    uart_puts("======================================================\n");

    size_t payload_size = guest_payload_end - guest_payload_start;
    
    uart_puts("[VMI] Scanning Guest Payload (Size: ");
    print_hex(payload_size);
    uart_puts(")...\n");

    if (telos_policy_extract(guest_payload_start, payload_size, &global_policy)) {
        uart_puts("[VMI] SUCCESS: Extracted .telos_policy from Guest ELF!\n");
    } else {
        uart_puts("[VMI] ERROR: Failed to extract .telos_policy!\n");
        while(1);
    }

    uint64_t text_offset = 0;
    uint64_t text_size = 0;
    if (!elf64_find_section(guest_payload_start, payload_size, ".text", &text_offset, &text_size)) {
        uart_puts("[VMI] ERROR: Failed to get .text section offset!\n");
        while(1);
    }
    
    global_abs_entry = (uint64_t)guest_payload_start + text_offset;
    uart_puts("[VMI] Guest absolute entry point: "); print_hex(global_abs_entry);

    uart_puts("[VMI] Configuring Trap Handler and permissive PMP...\n");
    
    // Configure mtvec
    __asm__ volatile("csrw mtvec, %0" : : "r"(((uint64_t)trap_entry) & ~3ULL));
    
    // Configure permissive PMP
    uint64_t pmpaddr0 = -1ULL;
    uint64_t pmpcfg0  = 0x1F; // NAPOT | X | W | R
    __asm__ volatile("csrw pmpaddr0, %0" : : "r"(pmpaddr0));
    __asm__ volatile("csrw pmpcfg0, %0" : : "r"(pmpcfg0));

    uart_puts("[VMI] Dropping privileges and executing Guest in U-Mode...\n");

    // Set mstatus.MPP to 00 (U-Mode)
    uint64_t mstatus;
    __asm__ volatile("csrr %0, mstatus" : "=r"(mstatus));
    mstatus &= ~(3ULL << 11); // Clear MPP
    __asm__ volatile("csrw mstatus, %0" : : "r"(mstatus));

    // Set mepc to entry point
    __asm__ volatile("csrw mepc, %0" : : "r"(global_abs_entry));

    // Drop to U-Mode
    __asm__ volatile("mret");
    while(1);
}
