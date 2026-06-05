#!/bin/bash
# Sentinel-VMI QEMU Trace Benchmark
# Measures the overhead of hypervisor introspection (VM-Exits) using a synthetic sysbench workload.

set -e

echo "======================================"
echo " Sentinel-VMI Introspection Benchmark"
echo "======================================"

# Ensure perf and sysbench are available
if ! command -v perf &> /dev/null || ! command -v sysbench &> /dev/null; then
    echo "Error: 'perf' and 'sysbench' are required for this benchmark."
    echo "Install with: sudo apt-get install linux-tools-common linux-tools-generic sysbench"
    exit 1
fi

echo "[1/2] Running baseline sysbench workload..."
time sysbench cpu --cpu-max-prime=20000 --threads=4 run > /dev/null

echo "[2/2] Tracing KVM VM-Exits during workload (requires KVM support)..."
if [ ! -c /dev/kvm ]; then
    echo "Warning: /dev/kvm not found. Nested virtualization might not be enabled."
    echo "The trace may not capture hardware-accelerated VM-Exits."
fi

# Run perf kvm stat in the background while sysbench runs
sudo perf kvm stat record -o kvm_stat.data -- sysbench cpu --cpu-max-prime=20000 --threads=4 run > /dev/null

echo "VM-Exit Statistics:"
sudo perf kvm stat report -i kvm_stat.data

echo "Cleaning up..."
sudo rm -f kvm_stat.data

echo "Benchmark complete."
