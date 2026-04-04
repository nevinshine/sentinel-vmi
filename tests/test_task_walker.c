// tests/test_task_walker.c — Phase 2 Tests
//
// Tests for the task_struct parser and process list walker.

#include "sentinel_vmi.h"
#include "task_offsets.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) printf("[Test] %-40s ", name)
#define PASS() do { printf("✓ PASS\n"); tests_passed++; } while(0)
#define FAIL(msg) do { printf("✗ FAIL: %s\n", msg); tests_failed++; } while(0)

// ──────────────────────────────────────────────
// Test: Offset table integrity
// ──────────────────────────────────────────────

static void test_offset_table_6_6(void) {
    TEST("offset_table_6_6_valid");

    // Offsets must be non-zero and reasonable
    if (OFFSETS_6_6.tasks_offset > 0 &&
        OFFSETS_6_6.pid_offset > 0 &&
        OFFSETS_6_6.comm_offset > 0 &&
        OFFSETS_6_6.tasks_offset < 0x1000 &&
        OFFSETS_6_6.pid_offset < 0x1000) {
        PASS();
    } else {
        FAIL("offsets out of range");
    }
}

static void test_offset_table_6_1(void) {
    TEST("offset_table_6_1_valid");

    if (OFFSETS_6_1.tasks_offset > 0 &&
        OFFSETS_6_1.pid_offset > 0 &&
        OFFSETS_6_1.tasks_offset < 0x1000) {
        PASS();
    } else {
        FAIL("offsets out of range");
    }
}

// ──────────────────────────────────────────────
// Test: task_walker_dump with no init_task
// ──────────────────────────────────────────────

static void test_dump_no_init_task(void) {
    TEST("dump_no_init_task_graceful");

    struct vmi_session s = {0};
    s.init_task_addr = 0;  // Not set

    // Should print a message and return, not crash
    task_walker_dump(&s);
    PASS();
}

// ──────────────────────────────────────────────
// Test: find_pid with NULL session
// ──────────────────────────────────────────────

static void test_find_pid_null(void) {
    TEST("find_pid_null_guard");

    uint64_t addr;
    int rc = task_walker_find_pid(NULL, 1, &addr);
    if (rc < 0) {
        PASS();
    } else {
        FAIL("should return -1 for NULL");
    }
}

// ──────────────────────────────────────────────
// Test: Process struct zero-init
// ──────────────────────────────────────────────

static void test_vmi_process_size(void) {
    TEST("vmi_process_struct_size");

    struct vmi_process proc;
    memset(&proc, 0, sizeof(proc));

    if (sizeof(proc) > 0 && proc.pid == 0 && proc.uid == 0) {
        PASS();
    } else {
        FAIL("struct layout broken");
    }
}

int main(void) {
    printf("\n[Test] ═══════════════════════════════════════\n");
    printf("[Test] Phase 2: Task Walker Tests\n");
    printf("[Test] ═══════════════════════════════════════\n\n");

    test_offset_table_6_6();
    test_offset_table_6_1();
    test_dump_no_init_task();
    test_find_pid_null();
    test_vmi_process_size();

    printf("\n[Test] ───────────────────────────────────────\n");
    printf("[Test] Results: %d passed, %d failed\n",
           tests_passed, tests_failed);
    printf("[Test] ───────────────────────────────────────\n");

    return tests_failed > 0 ? 1 : 0;
}
