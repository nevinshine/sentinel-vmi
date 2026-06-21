#!/bin/bash
# Phase 7B.1: Saturation Boundaries (Map Occupancy vs Latency)

set -e

echo "[*] Compiling Instrumented Build for Saturation Benchmark..."
make build-instrumented

MAX_ENTRIES=16384 # As defined in bpf map

echo "[*] Starting Saturation Run"
echo "Flows | Occupancy | Memory"
echo "-----------------------------------"

# We use the flowctl utility to rapidly inject flows and measure insert latency.
# Note: Full lookup latency inside the kernel requires bpftrace or a custom XDP loader that reads perf events,
# which we have instrumented via BPF_CFLAGS in hyperion.bpf.c.

# Clean the map by detaching and re-attaching if needed, but for now we just delete.
sudo rm -f /sys/fs/bpf/hyperion_blocked_flows || true

# Setup dummy interface
sudo ip link add test1 type dummy || true
sudo ip link set test1 up

echo "[*] Loading XDP and spinning up daemon..."
sudo ./bin/flowctl load test1 >/dev/null &
FLOWCTL_PID=$!
sleep 2

touch decision_bus.jsonl
sudo ./bin/hyperiond > /tmp/hyperiond.log 2>&1 &
HYP_PID=$!
sleep 1

# Generate lots of flows
echo "[*] Injecting Flows..."

# We will inject flows up to 20,000 to trigger the 16384 map capacity limit.
# We track how long it takes.
for COUNT in 100 1000 10000 16000 20000; do
    
    # We write to decision_bus.jsonl in bulk to avoid bash loop overhead skewing the metrics
    > bulk_inject.jsonl
    for i in $(seq 1 $COUNT); do
        IP_END=$((i % 254))
        if [ "$IP_END" -eq 0 ]; then IP_END=1; fi
        PORT=$((i % 65000))
        if [ "$PORT" -eq 0 ]; then PORT=1; fi
        
        echo "{\"event_id\": \"bulk-$i\", \"action\": \"deny\", \"ttl_seconds\": 3600, \"network_targets\": [{\"dst_ip\": \"10.0.0.$IP_END\", \"dst_port\": $PORT, \"flow_risk\": 1.0}], \"risk_score\": 1.0}" >> bulk_inject.jsonl
    done
    
    START=$(date +%s%N)
    cat bulk_inject.jsonl >> decision_bus.jsonl
    
    # Wait for hyperiond to process them
    sleep 2
    
    END=$(date +%s%N)
    DUR_MS=$(((END - START) / 1000000))
    
    # Check actual map occupancy
    ENTRIES_USED=$(sudo bpftool map dump pinned /sys/fs/bpf/hyperion_blocked_flows | grep "\"key\":" | wc -l || echo 0)
    
    LOAD_FACTOR=$(echo "scale=2; ($ENTRIES_USED / $MAX_ENTRIES) * 100" | bc)
    
    echo "$COUNT | $LOAD_FACTOR% ($ENTRIES_USED/$MAX_ENTRIES) | ${DUR_MS}ms"
done

echo "[*] Tearing down daemon..."
sudo kill -9 $HYP_PID
sudo kill -9 $FLOWCTL_PID || true
sudo rm -f bulk_inject.jsonl decision_bus.jsonl
echo "[*] Saturation Benchmark Complete."
