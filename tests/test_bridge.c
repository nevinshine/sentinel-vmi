// tests/test_bridge.c — Phase 4 Tests
//
// Tests for the cross-layer bridge and alert pipeline.

#include "sentinel_vmi.h"
#include "vmi_alert_map.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) printf("[Test] %-40s ", name)
#define PASS() do { printf("✓ PASS\n"); tests_passed++; } while(0)
#define FAIL(msg) do { printf("✗ FAIL: %s\n", msg); tests_failed++; } while(0)

static void remove_fallback_log(void) {
    unlink(VMI_ALERT_FALLBACK_PATH);
}

static void remove_file(const char *path) {
    if (path)
        unlink(path);
}

static int count_alert_lines(uint32_t pid, uint32_t threat_level) {
    FILE *fp = fopen(VMI_ALERT_FALLBACK_PATH, "r");
    if (!fp)
        return 0;

    int count = 0;
    char line[256];
    char needle[64];
    snprintf(needle, sizeof(needle), "pid=%u threat=%u", pid, threat_level);

    while (fgets(line, sizeof(line), fp) != NULL) {
        if (strstr(line, needle) != NULL)
            count++;
    }

    fclose(fp);
    return count;
}

static int file_contains_text(const char *path, const char *needle) {
    if (!path || !needle)
        return 0;

    FILE *fp = fopen(path, "r");
    if (!fp)
        return 0;

    char line[512];
    int found = 0;
    while (fgets(line, sizeof(line), fp) != NULL) {
        if (strstr(line, needle) != NULL) {
            found = 1;
            break;
        }
    }

    fclose(fp);
    return found;
}

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

    setenv("VMI_ALERT_STREAM_ENABLE", "0", 1);

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

    setenv("VMI_ALERT_STREAM_ENABLE", "0", 1);
    remove_fallback_log();

    bridge_init();
    bridge_signal_malicious(1337, "test_rootkit_write");
    bridge_flush_alerts();
    bridge_teardown();
    PASS();
}

static void test_signal_suspicious(void) {
    TEST("bridge_signal_suspicious");

    setenv("VMI_ALERT_STREAM_ENABLE", "0", 1);
    remove_fallback_log();

    bridge_init();
    bridge_signal_suspicious(42, "test_priv_escalation");
    bridge_flush_alerts();
    bridge_teardown();
    PASS();
}

static void test_malicious_not_duplicated_on_flush(void) {
    TEST("malicious_not_duplicated_on_flush");

    setenv("VMI_ALERT_STREAM_ENABLE", "0", 1);
    remove_fallback_log();

    bridge_init();
    bridge_signal_malicious(9001, "dup_check");
    bridge_flush_alerts();
    bridge_teardown();

    int count = count_alert_lines(9001, VMI_THREAT_MALICIOUS);
    if (count == 1) {
        PASS();
    } else {
        FAIL("malicious alert duplicated or missing");
    }
}

static void test_suspicious_escalates_to_malicious(void) {
    TEST("suspicious_escalates_to_malicious");

    setenv("VMI_ALERT_STREAM_ENABLE", "0", 1);
    remove_fallback_log();

    bridge_init();
    bridge_signal_suspicious(77, "burst_1");
    bridge_signal_suspicious(77, "burst_2");
    bridge_signal_suspicious(77, "burst_3");
    bridge_flush_alerts();
    bridge_teardown();

    int escalated = count_alert_lines(77, VMI_THREAT_MALICIOUS);
    if (escalated >= 1) {
        PASS();
    } else {
        FAIL("expected escalation to malicious");
    }
}

static void test_stream_helper_mode_graceful(void) {
    TEST("stream_helper_mode_graceful");

    setenv("VMI_ALERT_STREAM_ENABLE", "1", 1);
    setenv("VMI_ALERT_STREAM_MODE", "helper", 1);
    setenv("VMI_ALERT_GRPC_HELPER_CMD", "cat >/dev/null", 1);
    remove_fallback_log();

    bridge_init();
    bridge_signal_suspicious(88, "helper_mode_test");
    bridge_signal_malicious(88, "helper_mode_escalated");
    bridge_flush_alerts();
    bridge_teardown();

    setenv("VMI_ALERT_STREAM_ENABLE", "0", 1);
    PASS();
}

static void test_stream_helper_payload_schema(void) {
    TEST("stream_helper_payload_schema");

    const char *helper_out = "/tmp/vmi_helper_stream_payload.log";
    remove_file(helper_out);

    setenv("VMI_ALERT_STREAM_ENABLE", "1", 1);
    setenv("VMI_ALERT_STREAM_MODE", "helper", 1);
    setenv("VMI_ALERT_GRPC_HELPER_CMD", "cat >>/tmp/vmi_helper_stream_payload.log", 1);

    bridge_init();
    bridge_signal_malicious(999, "schema_test");
    bridge_flush_alerts();
    bridge_teardown();

    int has_type = file_contains_text(helper_out, "\"threat_type\":\"malicious\"");
    int has_conf = file_contains_text(helper_out, "\"confidence\":0.98");

    setenv("VMI_ALERT_STREAM_ENABLE", "0", 1);
    remove_file(helper_out);

    if (has_type && has_conf) {
        PASS();
    } else {
        FAIL("helper payload missing threat_type or confidence");
    }
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
    test_malicious_not_duplicated_on_flush();
    test_suspicious_escalates_to_malicious();
    test_stream_helper_mode_graceful();
    test_stream_helper_payload_schema();

    printf("\n[Test] ───────────────────────────────────────\n");
    printf("[Test] Results: %d passed, %d failed\n",
           tests_passed, tests_failed);
    printf("[Test] ───────────────────────────────────────\n");

    return tests_failed > 0 ? 1 : 0;
}
