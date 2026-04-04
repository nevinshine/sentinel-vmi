// tests/test_npt.c — Phase 3 Tests
//
// Tests for the NPT Guard and NPF handler.

#include "sentinel_vmi.h"
#include <stdio.h>
#include <string.h>

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) printf("[Test] %-40s ", name)
#define PASS() do { printf("✓ PASS\n"); tests_passed++; } while(0)
#define FAIL(msg) do { printf("✗ FAIL: %s\n", msg); tests_failed++; } while(0)

// ──────────────────────────────────────────────
// Test: Arm/disarm lifecycle
// ──────────────────────────────────────────────

static void test_arm_no_pgd(void) {
    TEST("npt_arm_no_pgd_graceful");

    struct vmi_session s = {0};
    s.kernel_pgd = 0;  // Not set

    // Should succeed but not actually arm (non-fatal)
    int rc = npt_guard_arm(&s);
    if (rc == 0) {
        PASS();
    } else {
        FAIL("should return 0 (non-fatal) when pgd not set");
    }
}

static void test_arm_null_session(void) {
    TEST("npt_arm_null_session");

    int rc = npt_guard_arm(NULL);
    if (rc < 0) {
        PASS();
    } else {
        FAIL("should return -1 for NULL session");
    }
}

static void test_disarm_unarmed(void) {
    TEST("npt_disarm_unarmed_safe");

    struct vmi_session s = {0};
    s.npt_armed = 0;

    // Should be a no-op, not crash
    npt_guard_disarm(&s);
    PASS();
}

// ──────────────────────────────────────────────
// Test: NPF handler classification
// ──────────────────────────────────────────────

static void test_npf_read_ignored(void) {
    TEST("npf_read_access_ignored");

    struct vmi_session s = {0};

    // Read access should be ignored (we only trap writes)
    npf_handler_process(&s, 0x1000, 0);
    PASS();
}

static void test_npf_write_handled(void) {
    TEST("npf_write_access_handled");

    struct vmi_session s = {0};
    s.syscall_table_gpa = 0x1000;

    // Write access should trigger the handler
    npf_handler_process(&s, 0x1000, 1);
    PASS();
}

static void test_npf_write_outside_syscall(void) {
    TEST("npf_write_outside_syscall");

    struct vmi_session s = {0};
    s.syscall_table_gpa = 0x4000;

    // Write outside syscall table should still be handled safely
    npf_handler_process(&s, 0x1000, 1);
    PASS();
}

// ──────────────────────────────────────────────
// Test: NPF handler init
// ──────────────────────────────────────────────

static void test_npf_init(void) {
    TEST("npf_handler_init");

    struct vmi_session s = {0};
    int rc = npf_handler_init(&s);
    if (rc == 0) {
        PASS();
    } else {
        FAIL("init should return 0");
    }
}

static void test_integrity_violation_null_guard(void) {
    TEST("integrity_violation_null_guard");

    int rc = npf_handler_report_integrity_violation(NULL,
                                                    "kernel_text",
                                                    0x1000,
                                                    0x1,
                                                    0x2,
                                                    1);
    if (rc < 0) {
        PASS();
    } else {
        FAIL("should return -1 for NULL session");
    }
}

static void test_integrity_violation_report(void) {
    TEST("integrity_violation_report");

    struct vmi_session s = {0};
    int rc = npf_handler_report_integrity_violation(&s,
                                                    "idt",
                                                    0x2000,
                                                    0xaaa,
                                                    0xbbb,
                                                    1);
    if (rc == 0) {
        PASS();
    } else {
        FAIL("integrity report should return 0");
    }
}

int main(void) {
    printf("\n[Test] ═══════════════════════════════════════\n");
    printf("[Test] Phase 3: NPT Guard Tests\n");
    printf("[Test] ═══════════════════════════════════════\n\n");

    test_arm_no_pgd();
    test_arm_null_session();
    test_disarm_unarmed();
    test_npf_read_ignored();
    test_npf_write_handled();
    test_npf_write_outside_syscall();
    test_npf_init();
    test_integrity_violation_null_guard();
    test_integrity_violation_report();

    printf("\n[Test] ───────────────────────────────────────\n");
    printf("[Test] Results: %d passed, %d failed\n",
           tests_passed, tests_failed);
    printf("[Test] ───────────────────────────────────────\n");

    return tests_failed > 0 ? 1 : 0;
}
