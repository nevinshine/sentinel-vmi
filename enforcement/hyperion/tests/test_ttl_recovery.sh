#!/bin/bash
# Phase 7A.1: TTL Correctness (Crash Recovery)

set -e

echo "[*] Testing Hyperion TTL Recovery Mechanism"

# Clean up
pkill hyperiond || true
sudo rm -f /sys/fs/bpf/hyperion_blocked_flows || true
sudo rm -f ../decision_bus.jsonl

# Build everything
make build-release

# Load XDP on loopback so the map is pinned
echo "[*] Loading XDP on lo..."
sudo ./bin/flowctl load lo >/dev/null &
FLOWCTL_PID=$!
sleep 2

# Start hyperiond in the background
touch decision_bus.jsonl
sudo ./bin/hyperiond &
HYP_PID=$!

sleep 1

# 1. Insert flow with a 3-second TTL
echo '{"event_id": "test-ttl-1", "action": "deny", "ttl_seconds": 3, "network_targets": [{"dst_ip": "10.0.0.99", "dst_port": 80, "flow_risk": 0.99}], "risk_score": 0.99}' >> decision_bus.jsonl

sleep 1

# 2. Force-kill hyperiond (simulate crash)
echo "[*] Simulating daemon crash (kill -9)"
sudo kill -9 $HYP_PID

# 3. Wait for TTL expiration
echo "[*] Waiting 4 seconds for TTL to expire in the map..."
sleep 4

# 4. Restart hyperiond
echo "[*] Restarting daemon to trigger startup reconciliation..."
sudo ./bin/hyperiond &
NEW_PID=$!

sleep 2

# 5. Verify flow was swept
# We can use bpftool or flowctl to dump the map and ensure 10.0.0.99 is not there.
# For simplicity, if we check `bpftool map dump pinned /sys/fs/bpf/hyperion_blocked_flows`, it should be empty.
FLOW_COUNT=$(sudo bpftool map dump pinned /sys/fs/bpf/hyperion_blocked_flows | grep "key:" | wc -l || echo 0)

if [ "$FLOW_COUNT" -eq 0 ]; then
    echo "[+] SUCCESS: Map state was correctly reconciled. Expired entries were swept on boot."
else
    echo "[-] FAILURE: Expired entries still exist in the map!"
    sudo kill -9 $NEW_PID
    exit 1
fi

# Cleanup
sudo kill -9 $NEW_PID
sudo kill -9 $FLOWCTL_PID || true
echo "[*] TTL Recovery test complete."
