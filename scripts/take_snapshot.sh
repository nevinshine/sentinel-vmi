#!/usr/bin/env bash
# scripts/take_snapshot.sh
# Extracts an atomic memory snapshot and structural metadata from a QEMU guest via QMP.

set -euo pipefail

QMP_SOCK="${1:-/tmp/qmp.sock}"
OUT_DIR="${2:-../tests/fixtures}"
BIN_FILE="$OUT_DIR/cloudlab_guest.bin"
JSON_FILE="$OUT_DIR/cloudlab_guest.json"
SYMS_FILE="$OUT_DIR/cloudlab_guest.kallsyms"

mkdir -p "$OUT_DIR"

echo "[*] Connecting to QMP at $QMP_SOCK..."

qmp_cmd() {
    local cmd="$1"
    (echo '{"execute": "qmp_capabilities"}'; echo "$cmd") | socat - UNIX-CONNECT:"$QMP_SOCK" | grep -v 'QMP' || true
}

# 1. Extract symbols before stopping the VM
echo "[*] Extracting /proc/kallsyms via SSH (port 2222)..."
sshpass -p ubuntu ssh -o StrictHostKeyChecking=no -p 2222 ubuntu@127.0.0.1 'sudo cat /proc/kallsyms' > "$SYMS_FILE" 2>/dev/null
if [ ! -s "$SYMS_FILE" ]; then
    echo "[!] Failed to extract kallsyms. Is the VM booted and SSH reachable?"
    exit 1
fi
echo "[+] Extracted $(wc -l < "$SYMS_FILE") symbols."

# 2. Force the guest into kernel mode so CR3 maps kernel memory
echo "[*] Forcing guest into kernel mode..."
sshpass -p ubuntu ssh -o StrictHostKeyChecking=no -p 2222 ubuntu@127.0.0.1 'while true; do cat /proc/version > /dev/null; done' > /dev/null 2>&1 &
LOOP_PID=$!
sleep 1

# 3. Ensure atomic state by stopping the VM
echo "[*] Pausing VM for atomic capture..."
qmp_cmd '{"execute": "stop"}' > /dev/null

kill $LOOP_PID 2>/dev/null || true

STATUS=$(qmp_cmd '{"execute": "query-status"}' | tail -n 1 | jq -r '.return.status')
if [ "$STATUS" != "paused" ]; then
    echo "[!] Failed to pause VM! Status is $STATUS"
    exit 1
fi
echo "[+] VM is paused."

# 4. Dump physical memory as RAW binary (256MB)
echo "[*] Dumping guest memory to $BIN_FILE (RAW format)..."
rm -f "$BIN_FILE"
BIN_FILE_ABS=$(readlink -f "$BIN_FILE" || echo "$PWD/$BIN_FILE")
PMEM_OUT=$(qmp_cmd "{\"execute\": \"human-monitor-command\", \"arguments\": {\"command-line\": \"pmemsave 0 268435456 \\\"$BIN_FILE_ABS\\\"\"}}")
if [ ! -f "$BIN_FILE" ]; then
    echo "[!] pmemsave failed! Output: $PMEM_OUT"
    exit 1
fi

# 4. Extract vCPU registers
echo "[*] Extracting vCPU registers..."
REGS=$(qmp_cmd '{"execute": "human-monitor-command", "arguments": {"command-line": "info registers"}}')

# Extract RIP, RSP, CR3 using grep
RIP=$(echo "$REGS" | grep -oP 'RIP=\K[0-9a-f]+' | head -1)
RSP=$(echo "$REGS" | grep -oP 'RSP=\K[0-9a-f]+' | head -1)
CR3=$(echo "$REGS" | grep -oP 'CR3=\K[0-9a-f]+' | head -1)

echo "[+] RIP=0x$RIP, RSP=0x$RSP, CR3=0x$CR3"

# 5. Resume the VM
echo "[*] Resuming VM..."
qmp_cmd '{"execute": "cont"}' > /dev/null

# 6. Compute checksums
echo "[*] Computing SHA256 checksums..."
BIN_SHA256=$(sha256sum "$BIN_FILE" | awk '{print $1}')
SYMS_SHA256=$(sha256sum "$SYMS_FILE" | awk '{print $1}')

# 7. Generate JSON Metadata Triplet
echo "[*] Generating metadata $JSON_FILE..."
cat <<EOF > "$JSON_FILE"
{
  "paging": {
    "mode": "x86_64_4level",
    "page_shift": 12
  },
  "vcpu": {
    "rip": "0x$RIP",
    "rsp": "0x$RSP",
    "cr3": "0x$CR3"
  },
  "kernel": {
    "release": "6.8.0-generic",
    "build_id": "abcdef123456",
    "kaslr_slide": "0x0",
    "phys_base": "0x0"
  },
  "snapshot_sha256": "$BIN_SHA256",
  "kallsyms_sha256": "$SYMS_SHA256"
}
EOF

echo "[+] Snapshot capture complete!"
