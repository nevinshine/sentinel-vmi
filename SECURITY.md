# Security Policy

## Supported Versions

| Version / Branch | Supported          |
|------------------|--------------------|
| `main`           | ✅ Yes             |
| Older branches   | ❌ No              |

Only the `main` branch receives security fixes. Users running forks or
pinned snapshots should update to the latest commit on `main`.

---

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Please report security issues privately via one of the following channels:

1. **GitHub Private Vulnerability Reporting** (preferred)
   Use the **"Report a vulnerability"** button on the
   [Security tab](../../security/advisories/new) of this repository.
   GitHub will create a private advisory visible only to maintainers.

2. **Email fallback**
   If GitHub's private reporting is unavailable, e-mail the maintainer
   directly. Use the address listed in the repository's `AUTHORS` file or
   the GitHub profile of `@nevinshine`.
   Please encrypt the report with the maintainer's public GPG key if one
   is published there.

Include the following in your report:

- Affected component(s) and file(s)
- Steps to reproduce or a minimal proof-of-concept
- Potential impact and attack scenario
- Your assessment of severity (CVSS score if possible)
- Any suggested mitigations

---

## Response & Triage SLA

| Stage                       | Target timeline          |
|-----------------------------|--------------------------|
| Acknowledgement             | ≤ 5 business days        |
| Initial triage / severity   | ≤ 10 business days       |
| Patch for Critical / High   | ≤ 30 days from triage    |
| Patch for Medium            | ≤ 60 days from triage    |
| Patch for Low / Info        | Next planned release      |

These are best-effort targets for an open-source project. Complex
vulnerabilities affecting the hypervisor introspection layer may require
additional time.

---

## Coordinated Disclosure Policy

1. The reporter and maintainer agree on a **disclosure date** (default:
   90 days after triage, sooner if a fix is ready).
2. The maintainer prepares a fix on a private branch, then requests a
   CVE via GitHub's advisory workflow.
3. A patched release is published on the agreed date.
4. The reporter is credited in the release notes and advisory unless they
   prefer anonymity.
5. If the 90-day window passes without a fix, the reporter may disclose
   at their discretion with advance notice to the maintainer.

---

## Scope

### In-scope

- Memory-safety vulnerabilities in C source (`src/`, `include/`)
- Guest-to-host escape paths reachable through the VMI introspection
  interface (KVMI, NPF handler, task walker)
- Integer overflows, buffer overflows, or use-after-free in any code
  that processes guest-controlled data
- Privilege escalation in the daemon process
- Sensitive information disclosure (guest memory contents, host kernel
  structures) through unintended channels
- Supply-chain issues in build dependencies or CI workflow

### Out-of-scope

- Vulnerabilities in the host Linux kernel itself (report to
  [kernel.org security list](https://www.kernel.org/doc/html/latest/process/security-bugs.html))
- Attacks that require full control of the hypervisor host already
  (i.e., the attacker is already at ring -1 / ring 0 on the host)
- Social-engineering attacks against contributors
- Physical / hardware side-channel attacks (e.g., Spectre/Meltdown)
  unless they are specifically exploitable via the introspection API
- Denial-of-service through resource exhaustion by a privileged guest
  operator (out-of-scope by design — operators control their guests)

---

## Disclosure Hall of Fame

Responsible reporters will be acknowledged here once the advisory is
published (with permission).

*No disclosures yet.*
