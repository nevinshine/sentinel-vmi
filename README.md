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
| 2 | task_struct parsing and process intelligence | Implemented with BTF-first fallback and anomaly detectors |
| 3 | NPT Guard and kernel integrity enforcement | Hardened baseline implemented (multi-region integrity + revalidation) |
| 4 | Cross-layer bridge to Hyperion/Telos | In progress (policy orchestration + resilient stream transport) |
| 5 | Advanced introspection (network/fs/module/hypervisor hardening) | Planned |
| 6 | Telos Ring -1 integration and formal verification | Future |

## Planning Documents

- [Complete feature specification](docs/complete-feature-spec.md)
- [Rebuild roadmap](docs/rebuild-roadmap.md)

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

## Phase 3 Optional Guard Regions

Phase 3 now supports optional integrity monitoring regions in addition to sys_call_table.
Set guest virtual addresses as environment variables before launch; each region is translated and guarded at runtime.

- VMI_IDT_GVA with optional VMI_IDT_SIZE
- VMI_GDT_GVA with optional VMI_GDT_SIZE
- VMI_LSTAR_GVA with optional VMI_LSTAR_SIZE
- VMI_KERNEL_TEXT_GVA with optional VMI_KERNEL_TEXT_SIZE

Optional testing override:

- VMI_ALLOW_LEGIT_KERNEL_PATCH=1 allows sys_call_table and kernel_text writes to be treated as legitimate in staging tests only.

## Phase 4 Producer Policy

Bridge producer behavior now applies a local orchestration policy before writing alerts:

- Duplicate suppression for repeated identical alerts in a short window
- Suspicious burst escalation: repeated suspicious events for one PID are promoted to malicious
- Immediate dispatch for malicious alerts, batched flush for suspicious alerts

Optional downstream stream controls:

- VMI_ALERT_STREAM_ENABLE=1 enables downstream stream publishing
- VMI_ALERT_STREAM_MODE=tcp|helper (default: tcp)
- VMI_ALERT_STREAM_HOST=127.0.0.1 (default for tcp mode)
- VMI_ALERT_STREAM_PORT=8421 (default for tcp mode)
- VMI_ALERT_GRPC_HELPER_CMD="<command>" (required for helper mode; bridge writes JSONL alerts to helper stdin)

gRPC compatibility note:

- Use helper mode with a local sidecar command that forwards JSONL alerts to your gRPC endpoint.
