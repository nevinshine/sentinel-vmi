# Sentinel VMI

Ring -1 hypervisor introspection for the Sentinel Stack.

Operates below the Linux kernel using AMD-V hardware extensions.
Assumes the guest OS is compromised. Enforces security from outside
the trust boundary entirely.

## Position in the Sentinel Stack

```
Ring -1  → Sentinel VMI     ← THIS PROJECT
Ring 0   → Sentinel-CC
Ring 0   → Telos Runtime
Wire     → Hyperion XDP
L7       → Pipelock
```

## Core Capability

Marks sys_call_table read-only at the hypervisor level via
Nested Page Tables. Any rootkit attempting to modify it triggers
an #NPF fault trapped in Ring -1. The malicious PID is identified
via task_struct walking and signaled to Hyperion XDP for
wire-speed packet drops.

## Phases

| Phase | Goal | Status |
|-------|------|--------|
| 1 | Raw guest memory introspection | Implemented baseline (QMP handshake + live memslot discovery) |
| 2 | task_struct parsing and process list | Rebuilding |
| 3 | NPT Guard — sys_call_table protection | Rebuilding |
| 4 | Cross-layer bridge to Hyperion/Telos | Rebuilding |

## Requirements

- AMD processor with AMD-V/SVM support
- Linux kernel with kvmi-v7 patches
- KVM with CONFIG_KVM_INTROSPECTION=y
- libkvmi, libbpf

## Critical Rule

ALL kernel experiments run inside a nested KVM VM.
NEVER on the host machine.

## Building

```bash
# Build custom kernel (inside VM only)
./scripts/build_kernel.sh

# Build VMI daemon
make

# Run tests
./scripts/run_tests.sh
```

## Cross-Layer Signals

Writes malicious PIDs to `vmi_alert_map` (pinned BPF map).
Hyperion XDP reads this map for wire-speed XDP_DROP.
Telos Runtime reads this map for taint elevation.
