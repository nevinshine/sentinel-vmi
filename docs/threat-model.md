# Sentinel VMI — Threat Model

## 1. System Overview

Sentinel VMI is a **Ring -1 hypervisor introspection daemon** that runs on a
KVM host and observes the internals of a guest VM without the guest's
cooperation or knowledge. It uses:

- **KVMI** (KVM Introspection API) to intercept VMENTER/VMEXIT events
- **NPF / EPT trapping** to detect and classify unauthorized writes to
  guest kernel memory
- **Direct physical memory reads** to walk guest `task_struct` chains and
  reconstruct the live process list
- An **eBPF map bridge** (Phase 4) to forward introspection events to
  companion daemons (Hyperion, Telos)

The daemon runs as a **privileged host process** with access to `/dev/kvm`
and the guest physical address space. It is the last line of defense: it
assumes the guest OS is fully compromised.

```
┌─────────────────────────────────────────────────────┐
│  Host kernel (Ring 0 / Ring -1 for KVM hypervisor)  │
│  ┌────────────────────────────────────────────────┐ │
│  │  sentinel-vmi daemon  (this codebase)          │ │
│  │  ┌──────────┐  ┌────────────┐  ┌───────────┐  │ │
│  │  │kvmi_setup│  │ npt_guard  │  │task_walker│  │ │
│  │  └────┬─────┘  └─────┬──────┘  └─────┬─────┘  │ │
│  └───────┼──────────────┼───────────────┼─────────┘ │
│          │  KVMI ioctl  │  EPT/NPF trap │ mem read  │
│  ┌───────▼──────────────▼───────────────▼─────────┐ │
│  │               KVM hypervisor                   │ │
│  └────────────────────┬────────────────────────────┘ │
└───────────────────────┼─────────────────────────────┘
                        │  VMENTER / VMEXIT
┌───────────────────────▼─────────────────────────────┐
│         Guest VM  (untrusted — assumed compromised)  │
│  Guest kernel, processes, memory                     │
└──────────────────────────────────────────────────────┘
```

---

## 2. Assets to Protect

| Asset | Sensitivity | Notes |
|-------|-------------|-------|
| Host kernel integrity | Critical | If compromised, the introspection guarantee is void |
| Guest physical memory contents | High | May contain credentials, keys, PII |
| Introspection event stream | High | Tampering could mask attacks or produce false alerts |
| Host process memory of sentinel-vmi | High | Holds parsed task lists, alert state, EPT mappings |
| `/dev/kvm` and KVMI file descriptors | High | Granting access allows arbitrary guest memory reads |
| eBPF maps shared with companion daemons | Medium | Poisoned maps could mislead Telos/Hyperion policy |
| Build artifacts and CI pipeline | Medium | Tampered binary could silently ignore intrusions |

---

## 3. Trust Boundaries and Assumptions

### Trusted

- Host kernel (Ring 0) — assumed not compromised at daemon startup
- KVM hypervisor — assumed correct per the Linux kernel security model
- The operator who launched `sentinel-vmi` — assumed authorized

### Untrusted

- **Everything inside the guest VM**, including guest kernel, kernel
  modules, and all guest processes
- Guest-controlled data structures read via `vmi_read_physical_mem()` —
  treated as attacker-supplied input
- VMCS/EPT fields when interpreting NPF fault addresses presented by the
  guest MMU
- BTF auto-detection path (`bpftool btf dump`) — output parsed from a
  host tool but structured data is ultimately derived from the kernel;
  bounds-check everything parsed

### Assumptions

- The host is hardened independently (SELinux/AppArmor, updated kernel,
  locked-down `/dev/kvm` permissions)
- Nested virtualization (guest-within-guest) is not in scope for the
  current implementation; behavior under nested virt is undefined
- The KVMI patch set (kvmi-v7) is applied correctly to the host kernel

---

## 4. Adversary Capabilities

### Capability A — Compromised Guest Kernel (primary threat)

The attacker controls ring 0 inside the guest. They can:
- Manipulate all guest page tables and memory mappings
- Forge `task_struct` contents, list pointers, and credential fields
- Trigger arbitrary NPF/EPT faults by modifying guest memory access patterns
- Attempt to hide processes by unlinking them from the scheduler queues
- Use timing side channels to infer host-side introspection activity

### Capability B — Malicious Guest Operator (secondary threat)

A legitimate but hostile operator with QEMU/libvirt access can:
- Pause/resume the VM to disrupt event ordering
- Load malicious kernel modules before introspection starts
- Corrupt the KVMI session through the management socket
- Attempt to exhaust host resources (memory, CPU) to degrade introspection

### Capability C — Supply-Chain Attacker (tertiary threat)

An attacker who can modify the source code or CI pipeline can:
- Introduce a backdoor in `sentinel-vmi` itself
- Tamper with the KVMI patch set or build toolchain
- Inject malicious entries into shared eBPF maps

### Out-of-Scope Adversaries

- Ring -1 / Ring -2 hypervisor attacks (SMM, BIOS firmware)
- Hardware side channels (Spectre/Meltdown variants)
- Physical access to the host machine

---

## 5. Primary Attack Surfaces

| Surface | Entry point | Risk |
|---------|-------------|------|
| Guest physical memory reads | `vmi_read_physical_mem()` → parsed structs | High — attacker controls content |
| NPF fault GPA values | `npf_handler` → `fault_gpa` | Medium — validate against known regions |
| KVMI event payloads | `kvmi_setup` socket | Medium — kernel-filtered, but validate sizes |
| BTF auto-offset parsing | `popen("bpftool btf …")` output | Medium — parse defensively |
| eBPF map bridge writes | `bridge.c` → BPF map updates | Low-Medium — only written by trusted host code |
| Command-line arguments | `main.c` argument parsing | Low — trusted operator input |
| Signal handlers | `SIGTERM`/`SIGINT` handling | Low — volatile flag only |

---

## 6. Security Invariants

These must hold at all times for the introspection guarantee to be meaningful:

1. **Guest data is untrusted input.** Every field read from guest physical
   memory via `vmi_read_physical_mem()` must be validated before use as
   an array index, pointer, or length.

2. **No guest-writable code paths on the host.** The guest must never be
   able to trigger arbitrary code execution in `sentinel-vmi` or the host
   kernel through KVMI events or NPF faults.

3. **Alert integrity.** Once an alert is raised (malicious classification),
   it must not be retractable by subsequent guest actions. The
   `malicious_gfns` set is append-only until an explicit flush by the host
   operator.

4. **Fail-closed on parse errors.** If a guest memory region cannot be
   parsed (invalid offsets, unreadable GPA), the task or region is
   classified as suspicious rather than ignored.

5. **Daemon privilege is not delegable.** `sentinel-vmi` must not load
   untrusted code (plugins, scripts) at runtime. The eBPF map bridge only
   signals companion daemons; it does not execute guest-provided eBPF.

---

## 7. Non-Goals

- **Preventing all guest evasion.** A sufficiently sophisticated guest
  rootkit can hide from any VMI system; the goal is to raise the cost, not
  guarantee detection.
- **Kernel exploit prevention.** This daemon observes but does not enforce
  policy at the syscall level — that is Sentinel CC's role.
- **Real-time blocking of guest actions.** Phase 1–3 are observation-only;
  blocking requires EPT write-protection enforcement (Phase 3+) and is a
  secondary capability.
- **Nested-virtualization transparency.** Behavior under nested KVM is
  undefined and untested.

---

## 8. Mitigations and Residual Risks

### Implemented Mitigations

| Threat | Mitigation |
|--------|-----------|
| Buffer overflow on guest memory parse | Bounds checks in `memory.c`; `TASK_COMM_LEN` limits |
| Stack corruption | `-fstack-protector-strong` in build |
| Format-string injection | `-Wformat -Werror=format-security` |
| Code injection via `printf`/`sprintf` | `-D_FORTIFY_SOURCE=3` |
| Process hiding (unlinked tasks) | NPT guard cross-references task list vs. page allocations |
| Privilege escalation in daemon | Run as dedicated user; no `setuid`; capabilities dropped after init |
| ASLR bypass | `-fPIE -pie` + ASLR on host |
| GOT/PLT hijacking | `-Wl,-z,relro,-z,now` (full RELRO) |
| Sensitive data leakage via alerts | Alert payloads contain GPA + classification only, not raw guest memory |

### Residual Risks

| Risk | Likelihood | Impact | Notes |
|------|-----------|--------|-------|
| Guest manipulates `task_struct` offsets to cause OOB read | Medium | High | Mitigated by offset validation; not fully eliminated |
| Timing side-channel leaks host-side introspection state to guest | Low | Medium | Inherent to VMI; hardening requires constant-time page walks |
| BTF parsing produces incorrect offsets under adversarial kernel | Low | Medium | Fallback to static offsets if BTF parse fails |
| Shared eBPF map poisoned by compromised companion daemon | Low | Medium | Map access should be restricted to `sentinel-vmi` and known daemons |
| KVMI patch regression introduces memory safety bug | Low | Critical | Mitigated by CI build + static analysis; kernel patch must be reviewed |

---

## 9. Revision History

| Date | Author | Notes |
|------|--------|-------|
| 2026-04-10 | Initial | First published threat model |
