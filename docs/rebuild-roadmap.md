# Sentinel VMI Rebuild Roadmap

## Execution Rule
- Run all kernel experiments only in nested KVM VMs.
- Push at the end of every session.

## Current Snapshot
- Phase 1 baseline is implemented and passing unit tests.
- Phases 2 to 4 are partially rebuilt and test-covered with placeholder or best-effort components.
- CI is green and Node 24 compatible.

## Weekly Priority Plan

### Week 1: Phase 1 completion
Done:
- Session setup with QEMU process discovery
- Best-effort QMP capability handshake
- Live memslot discovery from QEMU maps
- Remote-process backed memory I/O path
- Retry logic for transient memory I/O failures

Next:
- Integrate real libkvmi handshake path when kvmi-v7 userspace API is available
- Add session heartbeat and reconnect state machine
- Add optional page cache layer with bounded memory and invalidation on writes
- Add multi-VM session manager (one control loop, N sessions)

### Week 2: Phase 2 hardening
- BTF-first offset loader
- Runtime kernel version matching and fallback offset profile selection
- Expanded process extraction fields (ppid, capabilities, namespaces, files)
- Process ancestry graph and suspicious pattern rules

### Week 3: Phase 3 enforcement maturity
- Harden NPT policy engine for protected-page lifecycle
- Expand rootkit signature coverage (IDT/GDT/LSTAR/inline hooks/DKOM)
- Kernel text integrity baseline + periodic revalidation

### Week 4: Phase 4 orchestration
- Finalize vmi_alert_map schema and producer behavior
- Add resilient gRPC stream for downstream consumers
- Implement threat-level orchestration policy

## Deliverable Matrix (Now vs Target)

### Memory
- Raw GPA read/write: baseline done
- GVA to GPA translation: done
- Huge page translation: done
- Read retry logic: done
- Cache layer: pending

### Semantic
- Static offsets: done
- BTF dynamic offsets: pending
- Basic process list walk: done
- Advanced process intelligence: pending

### NPT Guard
- Baseline guard and detection loop: done
- Comprehensive signature engine: pending
- Integrity baseline framework: pending

### Cross-layer
- Bridge and map signaling baseline: done
- gRPC policy stream: pending
- Full stack orchestration rules: pending

## Short-Term Acceptance Criteria
- Week 1 complete when libkvmi handshake, heartbeat/reconnect, and optional cache pass unit and integration tests.
- Week 2 complete when BTF offset resolution works across at least two kernel versions.
- Week 3 complete when NPT guard catches expected tamper scenarios in nested KVM tests.
- Week 4 complete when bridge events trigger deterministic downstream policy behavior.
