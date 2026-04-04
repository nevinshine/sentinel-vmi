# Sentinel VMI Complete Feature Specification

## Core Identity
Sentinel VMI is a Ring -1 hypervisor introspection system built for enforcement, not just observation.
It runs below the guest Linux kernel via AMD-V virtualization features, assumes the guest is compromised,
and acts from outside the trust boundary.

## Design Principle
- Detection is necessary but insufficient.
- Hardware-backed prevention is primary.
- Cross-layer response is immediate when prevention is bypassed.

## Phase 1: Raw Memory Introspection
### Session and Control
- kvmi-v7 handshake and session establishment
- VM pause/resume without guest cooperation
- Multi-VM session support
- Session heartbeat and auto-reconnect
- Clean teardown of all kernel and userspace resources

### Memory Access
- Raw GPA reads and writes
- Chunked large-region reads
- Retry logic for transient failures
- Memory caching for hot pages

### Translation
- GVA to GPA page-table walking (PML4 to PT)
- Huge page support (2MB and 1GB)
- KASLR-aware operation (no fixed kernel addresses)
- CR3-driven translation from guest context
- GPA to host mapping via KVM/QEMU memory metadata

## Phase 2: Semantic Gap Bridging
### Symbol and Offset Resolution
- BTF-first offset discovery
- Kernel version detection from guest state
- Automatic recalculation across versions
- Static offset fallback when BTF is unavailable

### task_struct and Process Intelligence
- init_task anchor resolution
- Full tasks linked-list traversal
- PID/TGID/PPID extraction
- comm/mm/cred/files/nsproxy extraction
- start_time and flags extraction

### Detection Logic
- Privilege escalation detection for uid/euid and capability changes
- Process ancestry reconstruction and anomaly detection
- Fork bomb and suspicious parent-child pattern detection
- Memory map analysis from vm_area_struct
- Hidden executable region and W^X violation detection

## Phase 3: NPT Guard
### Core Protection
- Resolve sys_call_table physical backing
- Mark page read-only in NPT/EPT equivalent path
- Verify protection applied and active

### Fault Handling
- Ring -1 fault trap handling with low latency
- Classification of legitimate vs malicious writes
- Re-protect after temporary legitimate writes

### Signature and Integrity Coverage
- sys_call_table hook detection
- IDT/GDT/LSTAR tamper checks
- Inline kernel hook detection
- DKOM detection and critical structure consistency checks
- Baseline hash verification for critical kernel sections

## Phase 4: Cross-Layer Bridge
### Alert Data Plane
- Pinned BPF map vmi_alert_map as shared low-latency interface
- Key: PID
- Value: structured threat metadata

### Signal Targets
- Hyperion XDP for immediate packet dropping
- Telos Runtime taint elevation
- Sentinel-CC policy revocation
- Sentinel Runtime seccomp kill policy

### Control Plane
- gRPC alert stream with reconnect resilience
- Optional bidirectional policy updates
- Orchestration by threat level (suspicious vs malicious)

## Phase 5: Advanced Introspection
- Network socket structure traversal and hidden socket detection
- Filesystem integrity and hidden file detection
- Kernel module list integrity and hidden module detection
- Hypervisor self-protection hardening

## Phase 6: Telos Integration (Future)
- Ring -1 compilation target in Telos Language
- Single-source intent compiled across Ring 3/0/-1 paths
- Formal verification pipeline with fail-closed guarantees

## What Makes Sentinel VMI Different
Traditional VMI stacks primarily observe and report.
Sentinel VMI is designed to enforce at the hardware boundary and coordinate immediate stack-wide lockdown when needed.
