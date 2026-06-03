#include <stdint.h>
#include <stddef.h>
#include "elf_parser.h"
#include "crypto/ed25519.h"
#include "crypto/sha512.h"

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
}

static void print_hex_nl(uint64_t val) {
    print_hex(val);
    uart_puts("\n");
}

static void print_bytes(const uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        int hi = (buf[i] >> 4) & 0xF;
        int lo = buf[i] & 0xF;
        uart_putc(hi < 10 ? '0' + hi : 'a' + hi - 10);
        uart_putc(lo < 10 ? '0' + lo : 'a' + lo - 10);
    }
}

static void print_dec(uint32_t val) {
    char buf[12];
    int i = 0;
    if (val == 0) { uart_putc('0'); return; }
    while (val > 0) { buf[i++] = '0' + (val % 10); val /= 10; }
    while (i > 0) { uart_putc(buf[--i]); }
}

/* Guest payload embedded via incbin in boot.S */
extern uint8_t guest_payload_start[];
extern uint8_t guest_payload_end[];

/* Root of Trust key and signature embedded via incbin in boot.S */
extern uint8_t rot_public_key[32];
extern uint8_t guest_signature[64];

/* Linker-provided hypervisor memory boundaries */
extern uint8_t _hypervisor_start[];
extern uint8_t _hypervisor_end[];

/* Phase 3: Multi-Capability Table */
CapabilityTable cap_table;
uint64_t global_abs_entry;
extern void trap_entry(void);

/* ============================================================
 * Phase 1: Ed25519 Root of Trust Verification
 * ============================================================ */
static int verify_root_of_trust(const uint8_t *payload, size_t payload_size) {
    uart_puts("\n======================================================\n");
    uart_puts("[ROOT OF TRUST] Ed25519 Signature Verification\n");
    uart_puts("======================================================\n");

    uint64_t text_offset = 0;
    uint64_t text_size = 0;
    if (!elf64_find_section(payload, payload_size, ".text", &text_offset, &text_size)) {
        uart_puts("[ROOT OF TRUST] FATAL: No .text section found!\n");
        return 0;
    }

    uart_puts(" -> .text section: offset=");
    print_hex(text_offset);
    uart_puts(" size=");
    print_hex_nl(text_size);

    const uint8_t *text_data = payload + text_offset;

    uart_puts(" -> RoT Public Key: ");
    print_bytes(rot_public_key, 8);
    uart_puts("...\n");

    uart_puts(" -> Signature:      ");
    print_bytes(guest_signature, 8);
    uart_puts("...\n");

    uart_puts(" -> Verifying Ed25519(sig, .text, pubkey)...\n");

    int result = ed25519_verify(guest_signature, text_data, (size_t)text_size, rot_public_key);

    if (result) {
        uart_puts(" -> SIGNATURE VERIFIED. Root of Trust established.\n");
        uart_puts("======================================================\n\n");
        return 1;
    } else {
        uart_puts("\n!!! ROOT OF TRUST VIOLATION !!!\n");
        uart_puts("!!! Ed25519 signature does NOT match .text section !!!\n");
        uart_puts("!!! Binary integrity compromised — HALTING CPU !!!\n\n");
        return 0;
    }
}

/* ============================================================
 * Phase 2: Strict PMP Configuration (5 Regions)
 * ============================================================
 *
 * RISC-V PMP uses NAPOT (Naturally Aligned Power-of-Two) regions.
 * NAPOT encoding: pmpaddr = (base + (size/2 - 1)) >> 2
 * The region must be naturally aligned (base % size == 0).
 *
 * We round up to the next power of two for safety.
 */
static uint64_t next_power_of_two(uint64_t v) {
    v--;
    v |= v >> 1;
    v |= v >> 2;
    v |= v >> 4;
    v |= v >> 8;
    v |= v >> 16;
    v |= v >> 32;
    v++;
    return v;
}

static uint64_t napot_encode(uint64_t base, uint64_t size) {
    /* NAPOT: pmpaddr = (base | (size/2 - 1)) >> 2 */
    return (base | (size / 2 - 1)) >> 2;
}

static void configure_strict_pmp(void) {
    uart_puts("[PMP] Configuring 5-region strict isolation...\n");

    /* Region 0: Hypervisor Code/Data — M-mode only, Locked
     * L=1, A=NAPOT(3), R=1, W=1, X=1
     * When L=1, U-mode access is stripped regardless of RWX bits */
    uint64_t hyp_start = (uint64_t)_hypervisor_start;
    uint64_t hyp_end   = (uint64_t)_hypervisor_end;
    uint64_t hyp_size  = next_power_of_two(hyp_end - hyp_start);
    if (hyp_size < 4096) hyp_size = 4096;
    /* Align base down to power-of-two boundary */
    uint64_t hyp_base  = hyp_start & ~(hyp_size - 1);

    uart_puts(" -> PMP0 (Hypervisor Lock): ");
    print_hex(hyp_base); uart_puts(" - ");
    print_hex(hyp_base + hyp_size); uart_puts("\n");

    uint64_t pmpaddr0 = napot_encode(hyp_base, hyp_size);
    /* pmpcfg byte: L=1(bit7), A=NAPOT=11(bits4:3), R=1, W=1, X=1 = 0x9F */
    uint64_t cfg0 = 0x9F;

    /* Region 1: Guest Sandbox — U-mode RWX */
    uint64_t guest_start = (uint64_t)guest_payload_start;
    uint64_t guest_end   = (uint64_t)guest_payload_end;
    uint64_t guest_size  = next_power_of_two(guest_end - guest_start);
    if (guest_size < 4096) guest_size = 4096;
    uint64_t guest_base  = guest_start & ~(guest_size - 1);

    uart_puts(" -> PMP1 (Guest Sandbox):   ");
    print_hex(guest_base); uart_puts(" - ");
    print_hex(guest_base + guest_size); uart_puts("\n");

    uint64_t pmpaddr1 = napot_encode(guest_base, guest_size);
    /* A=NAPOT, R=1, W=1, X=1 = 0x1F */
    uint64_t cfg1 = 0x1F;

    /* Region 2: UART MMIO — U-mode RW (no execute) */
    uint64_t pmpaddr2 = napot_encode(0x10000000, 0x1000);
    /* A=NAPOT, R=1, W=1, X=0 = 0x1B */
    uint64_t cfg2 = 0x1B;
    uart_puts(" -> PMP2 (UART MMIO):       0x10000000 - 0x10001000\n");

    /* Region 3: TX Trigger MMIO — U-mode RW (no execute) */
    uint64_t pmpaddr3 = napot_encode(0x87D00000, 0x1000);
    uint64_t cfg3 = 0x1B;
    uart_puts(" -> PMP3 (TX Trigger MMIO): 0x87D00000 - 0x87D01000\n");

    /* Region 4: Deny-All Catch-all */
    uint64_t pmpaddr4 = -1ULL;
    /* A=NAPOT, R=0, W=0, X=0 = 0x18 */
    uint64_t cfg4 = 0x18;
    uart_puts(" -> PMP4 (Deny-All):        0x00000000 - 0xFFFFFFFF\n");

    /* Pack cfg bytes into pmpcfg0 (8 bytes, one byte per region) */
    uint64_t pmpcfg0 = cfg0 | (cfg1 << 8) | (cfg2 << 16) | (cfg3 << 24) | (cfg4 << 32);

    __asm__ volatile("csrw pmpaddr0, %0" : : "r"(pmpaddr0));
    __asm__ volatile("csrw pmpaddr1, %0" : : "r"(pmpaddr1));
    __asm__ volatile("csrw pmpaddr2, %0" : : "r"(pmpaddr2));
    __asm__ volatile("csrw pmpaddr3, %0" : : "r"(pmpaddr3));
    __asm__ volatile("csrw pmpaddr4, %0" : : "r"(pmpaddr4));
    __asm__ volatile("csrw pmpcfg0,  %0" : : "r"(pmpcfg0));

    uart_puts("[PMP] Strict 5-region isolation active.\n");
}

/* ============================================================
 * Phase 3: Multi-Capability Trap Handler
 * ============================================================ */
void handle_trap(uint64_t a0) {
    uint64_t mcause;
    uint64_t mepc;
    uint64_t mtval;
    __asm__ volatile("csrr %0, mcause" : "=r"(mcause));
    __asm__ volatile("csrr %0, mepc"   : "=r"(mepc));
    __asm__ volatile("csrr %0, mtval"  : "=r"(mtval));

    if (mcause == 8) { // U-Mode ecall
        uart_puts("\n[M-MODE HYPERVISOR] Intercepted U-Mode ecall.\n");
        uart_puts(" -> Requested intent: "); print_hex_nl(a0);

        /* Walk the capability table looking for a matching, inactive slot */
        for (uint32_t i = 0; i < cap_table.count; i++) {
            CapabilitySlot *slot = &cap_table.slots[i];

            if (slot->policy.intent_hash == a0 && !slot->active && !slot->revoked) {
                uart_puts(" -> MATCHED slot ");
                print_dec(i);
                uart_puts(". Provisioning TCA hardware datapath...\n");

                /* 1. Provision Intent */
                __asm__ volatile("csrw 0x800, %0" : : "r"(slot->policy.intent_hash));

                /* 2. Provision Bloom Filter */
                uint64_t *bloom = (uint64_t*)slot->policy.bloom_filter;
                __asm__ volatile("csrw 0x805, %0" : : "r"(bloom[0]));
                __asm__ volatile("csrw 0x806, %0" : : "r"(bloom[1]));
                __asm__ volatile("csrw 0x807, %0" : : "r"(bloom[2]));
                __asm__ volatile("csrw 0x808, %0" : : "r"(bloom[3]));

                /* 3. Provision Spatial Limit */
                __asm__ volatile("csrw 0x809, %0" : : "r"(slot->abs_limit_pc));

                /* 4. Configure dynamic bounds (ADDR1 = TX Sink) */
                uint64_t tca_addr1 = 0x87D00000;
                __asm__ volatile("csrw 0x804, %0" : : "r"(tca_addr1));
                uint64_t tca_cfg = (slot->policy.intent_hash << 32) | 0x0A;
                __asm__ volatile("csrw 0x802, %0" : : "r"(tca_cfg));

                /* 5. Mark slot as active */
                slot->active = 1;

                uart_puts(" -> Intent "); print_hex(a0);
                uart_puts(" GRANTED. Limit PC: "); print_hex_nl(slot->abs_limit_pc);

                mepc += 4;
                __asm__ volatile("csrw mepc, %0" : : "r"(mepc));
                return;
            }
        }

        uart_puts(" -> ACCESS DENIED. No matching capability in table.\n");
        uart_puts(" -> Requested: "); print_hex_nl(a0);
        while(1);
    }

    /* Handle store/load access faults from PMP or TCA */
    if (mcause == 0x07 || mcause == 0x05 || mcause == 0x0F || mcause == 0x0D) {
        uart_puts("\n[M-MODE HYPERVISOR] MEMORY ACCESS FAULT!\n");
        uart_puts("mcause: "); print_hex_nl(mcause);
        uart_puts("mepc:   "); print_hex_nl(mepc);
        uart_puts("mtval:  "); print_hex_nl(mtval);

        /* Check if this is a TCA revocation fault (post-revocation store) */
        if (mcause == 0x0F) {
            uart_puts(" -> TCA Silicon Fault: capability was revoked at temporal boundary.\n");
        } else if (mcause == 0x07 || mcause == 0x05) {
            uart_puts(" -> PMP Access Fault: strict isolation boundary enforced.\n");
        }
        while(1);
    }

    uart_puts("\n[M-MODE HYPERVISOR] UNHANDLED TRAP!\n");
    uart_puts("mcause: "); print_hex_nl(mcause);
    uart_puts("mepc:   "); print_hex_nl(mepc);
    uart_puts("mtval:  "); print_hex_nl(mtval);
    while(1);
}

/* ============================================================
 * Boot Sequence
 * ============================================================ */
void _start() {
    uart_puts("\n======================================================\n");
    uart_puts("[M-MODE HYPERVISOR] Booting TCA Bare-Metal Orchestrator\n");
    uart_puts("======================================================\n");

    size_t payload_size = guest_payload_end - guest_payload_start;
    uart_puts("[VMI] Guest Payload Size: ");
    print_hex_nl(payload_size);

    /* ---- Phase 1: Root of Trust ---- */
    if (!verify_root_of_trust(guest_payload_start, payload_size)) {
        while(1);
    }

    /* ---- Phase 3: Multi-Capability Extraction ---- */
    TelosPolicyEntry policies[MAX_CAPABILITIES];
    uint32_t policy_count = telos_policy_extract_all(
        guest_payload_start, payload_size, policies, MAX_CAPABILITIES);

    if (policy_count == 0) {
        uart_puts("[VMI] ERROR: Failed to extract .telos_policy!\n");
        while(1);
    }

    uart_puts("[VMI] Extracted "); print_dec(policy_count);
    uart_puts(" capability policies from Guest ELF:\n");

    /* Resolve entry point */
    uint64_t text_offset = 0;
    uint64_t text_size = 0;
    if (!elf64_find_section(guest_payload_start, payload_size, ".text", &text_offset, &text_size)) {
        uart_puts("[VMI] ERROR: Failed to get .text section offset!\n");
        while(1);
    }
    global_abs_entry = (uint64_t)guest_payload_start + text_offset;

    /* Populate capability table */
    cap_table.count = policy_count;
    for (uint32_t i = 0; i < policy_count; i++) {
        cap_table.slots[i].policy = policies[i];
        cap_table.slots[i].abs_limit_pc = global_abs_entry + policies[i].limit_pc_offset;
        cap_table.slots[i].active = 0;
        cap_table.slots[i].revoked = 0;

        uart_puts(" -> Slot "); print_dec(i);
        uart_puts(": intent="); print_hex(policies[i].intent_hash);
        uart_puts(" limit_pc="); print_hex_nl(cap_table.slots[i].abs_limit_pc);
    }

    uart_puts("[VMI] Guest absolute entry point: "); print_hex_nl(global_abs_entry);

    /* ---- Trap Handler ---- */
    uart_puts("[VMI] Configuring Trap Handler...\n");
    __asm__ volatile("csrw mtvec, %0" : : "r"(((uint64_t)trap_entry) & ~3ULL));

    /* ---- Phase 2: Strict PMP ---- */
    configure_strict_pmp();

    /* ---- Drop to U-Mode ---- */
    uart_puts("[VMI] Dropping privileges and executing Guest in U-Mode...\n\n");

    uint64_t mstatus;
    __asm__ volatile("csrr %0, mstatus" : "=r"(mstatus));
    mstatus &= ~(3ULL << 11);
    __asm__ volatile("csrw mstatus, %0" : : "r"(mstatus));
    __asm__ volatile("csrw mepc, %0" : : "r"(global_abs_entry));
    __asm__ volatile("mret");
    while(1);
}
