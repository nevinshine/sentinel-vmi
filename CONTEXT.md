# Sentinel VMI — Full Engineering Context

## What This Is
Sentinel VMI is the Ring -1 hypervisor introspection layer of the 
unified Sentinel Stack. It operates below the Linux kernel using 
AMD-V hardware virtualization extensions. It assumes the guest OS 
is already compromised and enforces security from outside the 
trust boundary entirely.

## Position in the Unified Stack
```
Ring -1  → Sentinel VMI        (THIS PROJECT)
Ring 0   → Sentinel-CC         (compiler policy enforcement)
Ring 0   → Telos Runtime       (intent-based eBPF/LSM)
Ring 0   → Sentinel Runtime    (HIDS/seccomp)
Wire     → Hyperion XDP        (NIC-level packet drops)
L7       → Pipelock            (MCP semantic detection)
```

## Core Threat Model
- Adversary has Ring 0 access (kernel is compromised)
- Traditional eBPF/LSM tools are untrustworthy at this point
- VMI operates from Ring -1 — below the compromised OS
- Hardware enforces what software cannot

## Hardware Requirements
- AMD processor with AMD-V (SVM) support
- Nested Page Table (NPT) support
- KVM with kvmi-v7 patchset applied
- Custom compiled kernel with CONFIG_KVM_INTROSPECTION=y

## The Four Phases

### Phase 1 — Raw Memory Introspection
Goal: Read guest physical memory from Ring -1 without 
trusting the guest OS at all.

Components:
- KVM file descriptor management
- kvmi API setup and handshake
- Raw guest physical memory dump via kvmi_read_physical()
- Page table walker for guest virtual → physical translation

Key technical challenge:
- Guest physical address ≠ host physical address
- Must use KVM memslots to translate
- No guest cooperation assumed

### Phase 2 — Semantic Gap Bridging
Goal: Parse meaningful kernel data structures from raw bytes.

Components:
- BTF-first offset loader with kernel-profile fallback
- Process list walker (init_task → all processes)
- Expanded extraction: PID/TGID/PPID, comm, mm, files, namespaces, start time, flags
- Credential parsing (uid/gid/euid/egid/capabilities)
- Behavioral analytics: privilege transitions, orphan tasks, fork-bomb patterns, suspicious ancestry

Key technical challenge:
- task_struct layout changes between kernel versions
- Offsets must be discovered dynamically or from BTF
- Linked list traversal across physical memory pages

### Phase 3 — NPT Guard (The Core Innovation)
Goal: Protect sys_call_table from rootkit modification using 
AMD-V Nested Page Tables.

Components:
- Nested Page Table manipulation via KVM ioctl
- sys_call_table physical address resolution
- NPT entry modification: mark page read-only at hypervisor level
- #NPF (Nested Page Fault) trap handler
- Fault analysis: is this a legitimate kernel write or rootkit?
- Multi-region integrity baseline and periodic hash revalidation
- Optional IDT/GDT/LSTAR/kernel_text guard regions via runtime configuration

Key technical challenge:
- NPT operates on physical addresses not virtual
- Must handle legitimate kernel self-modification
- #NPF must be handled fast — blocks guest execution

What it proves:
- Even a fully compromised kernel CANNOT modify sys_call_table
- The hardware enforces the write protection
- No kernel-level bypass exists

### Phase 4 — Cross-Layer Bridge
Goal: Connect Ring -1 detection to the rest of the Sentinel Stack.

Components:
- Malicious PID detection (from Phase 2 + 3 combined)
- Pinned eBPF map: vmi_alert_map (PID → threat_level)
- Map write from host userspace into guest's eBPF namespace
- Signal to Hyperion XDP: wire-speed drops for malicious PIDs
- Signal to Telos Runtime: elevate taint to TAINT_CRITICAL
- Producer orchestration policy (dedup + suspicious burst escalation)
- Resilient downstream alert stream transport with reconnect backoff
- Helper-based gRPC compatibility hook for sidecar forwarding

Signal flow:
```
VMI detects rootkit write to sys_call_table
  → identifies malicious PID via task_struct walk
  → writes PID to vmi_alert_map
  → Hyperion XDP reads map → XDP_DROP all packets
  → Telos Runtime reads map → Network Slam
  → Zero bytes leave the machine
```

## Key Dependencies
- Linux kernel 6.x with kvmi-v7 patches applied
- KVM (CONFIG_KVM, CONFIG_KVM_AMD)
- kvmi userspace library (libkvmi)
- libbpf for cross-layer eBPF map access
- Custom Fedora kernel compiled from source

## The Hardest Problem
Nevin identified VMI as the hardest project in the entire stack.
Harder than the libc BFS filtering in Sentinel-CC.
Harder than the LLVM dual-target compiler.

Reason: the feedback loop is a kernel panic and hard reboot.
No error messages. No debugger. Just silence and a reset button.

Rule: ALL VMI kernel experiments run inside a nested KVM VM.
NEVER on the host machine. Learned this the hard way.

## Testing Strategy
- Nested KVM VM as sacrificial environment
- GitHub Actions for automated kernel build verification
- Host machine stays clean at all times
- kvmi-v7 patches applied only inside the VM kernel

## Cross-Layer Signals (What Other Projects Expect)

Hyperion XDP expects:
  Map name: vmi_alert_map
  Type: BPF_MAP_TYPE_HASH
  Key: uint32_t (PID)
  Value: uint32_t (threat_level: 1=suspicious, 2=malicious)

Telos Runtime expects:
  gRPC endpoint: localhost:8421/vmi/alert
  Payload: {pid: u32, threat_type: string, confidence: f32}
  Bridge helper stream emits JSONL with these fields plus threat_level, timestamp_ns, and reason.

Sentinel-CC expects:
  Nothing directly — VMI detection triggers runtime response

## File Structure
sentinel-vmi/
├── src/
│   ├── main.c              # Entry point, VMI session management
│   ├── kvmi_setup.c        # KVM introspection API setup
│   ├── memory.c            # Guest physical memory access
│   ├── task_walker.c       # task_struct parsing and process list
│   ├── npt_guard.c         # Nested Page Table manipulation
│   ├── npf_handler.c       # #NPF fault trap and analysis
│   └── bridge.c            # Cross-layer eBPF map signaling
├── include/
│   ├── sentinel_vmi.h      # Shared definitions
│   ├── task_offsets.h      # task_struct field offsets by kernel version
│   └── vmi_alert_map.h     # Shared map definition with Hyperion/Telos
├── kernel/
│   └── patches/
│       └── kvmi-v7/        # KVM introspection kernel patches
├── tests/
│   ├── test_memory.c       # Phase 1 tests
│   ├── test_task_walker.c  # Phase 2 tests
│   ├── test_npt.c          # Phase 3 tests
│   └── test_bridge.c       # Phase 4 tests
├── scripts/
│   ├── build_kernel.sh     # Custom kernel build script
│   ├── setup_vm.sh         # Nested KVM VM setup
│   └── run_tests.sh        # Full test suite
├── .github/
│   └── workflows/
│       └── vmi-build.yml   # GitHub Actions kernel build CI
├── docs/
│   ├── threat-model.md     # VMI-specific threat model
│   ├── architecture.md     # Phase-by-phase architecture
│   └── setup.md            # How to build the custom kernel
├── Makefile
└── README.md

## Current Status
Phase 1: Baseline implemented and test-validated.
Phase 2: Implemented with BTF-first semantic extraction fallback and anomaly analytics.
Phase 3: Hardened baseline implemented with multi-region integrity guard and anomaly classification.
Phase 4: In-progress with policy orchestration and resilient transport (TCP + helper gRPC compatibility).
Phase 5: Planned after Phase 4 completion.
Phase 6: Future language/runtime integration milestone.

The architecture is proven. This repository tracks the rebuild in increments.

See planning docs for the canonical roadmap:
- docs/complete-feature-spec.md
- docs/rebuild-roadmap.md

## The One Rule
Push to GitHub after every session.
git add . && git commit -m "..." && git push
Never lose this again.
