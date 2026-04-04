// tests/test_bridge.c — Phase 4 Tests
//
// Tests for the cross-layer bridge and alert pipeline.

#include "sentinel_vmi.h"
#include "vmi_alert_map.h"
#include <stdio.h>
#include <string.h>

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) printf("[Test] %-40s ", name)
#define PASS() do { printf("✓ PASS\n"); tests_passed++; } while(0)
#define FAIL(msg) do { printf("✗ FAIL: %s\n", msg); tests_failed++; } while(0)

// ──────────────────────────────────────────────
// Test: Alert map constants
// ──────────────────────────────────────────────

static void test_alert_constants(void) {
    TEST("alert_constants_defined");

    if (VMI_THREAT_CLEAN == 0 &&
        VMI_THREAT_SUSPICIOUS == 1 &&
        VMI_THREAT_MALICIOUS == 2 &&
        VMI_ALERT_MAP_SIZE > 0) {
        PASS();
    } else {
        FAIL("constants incorrect");
    }
}

static void test_alert_map_name(void) {
    TEST("alert_map_name_set");

    if (strcmp(VMI_ALERT_MAP_NAME, "vmi_alert_map") == 0) {
        PASS();
    } else {
        FAIL("map name mismatch");
    }
}

// ──────────────────────────────────────────────
// Test: Bridge lifecycle
// ──────────────────────────────────────────────

static void test_bridge_lifecycle(void) {
    TEST("bridge_init_teardown");

    int rc = bridge_init();
    if (rc != 0) {
        FAIL("bridge_init failed");
        return;
    }

    bridge_teardown();
    PASS();
}

// ──────────────────────────────────────────────
// Test: Signal and flush
// ──────────────────────────────────────────────

static void test_signal_malicious(void) {
    TEST("bridge_signal_malicious");

    bridge_init();
    bridge_signal_malicious(1337, "test_rootkit_write");
    bridge_flush_alerts();
    bridge_teardown();
    PASS();
}

static void test_signal_suspicious(void) {
    TEST("bridge_signal_suspicious");

    bridge_init();
    bridge_signal_suspicious(42, "test_priv_escalation");
    bridge_flush_alerts();
    bridge_teardown();
    PASS();
}

// ──────────────────────────────────────────────
// Test: Alert struct layout
// ──────────────────────────────────────────────

static void test_alert_struct_size(void) {
    TEST("vmi_alert_struct_size");

    struct vmi_alert alert;
    memset(&alert, 0, sizeof(alert));
    alert.pid = 123;
    alert.threat_level = VMI_THREAT_MALICIOUS;

    if (alert.pid == 123 && alert.threat_level == 2) {
        PASS();
    } else {
        FAIL("struct layout broken");
    }
}

int main(void) {
    printf("\n[Test] ═══════════════════════════════════════\n");
    printf("[Test] Phase 4: Cross-Layer Bridge Tests\n");
    printf("[Test] ═══════════════════════════════════════\n\n");

    test_alert_constants();
    test_alert_map_name();
    test_alert_struct_size();
    test_bridge_lifecycle();
    test_signal_malicious();
    test_signal_suspicious();

    printf("\n[Test] ───────────────────────────────────────\n");
    printf("[Test] Results: %d passed, %d failed\n",
           tests_passed, tests_failed);
    printf("[Test] ───────────────────────────────────────\n");

    return tests_failed > 0 ? 1 : 0;
}
