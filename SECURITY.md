# Security Policy

Light WAF is a security product, so we treat vulnerabilities in it — including ways to get an
attack past it — as security issues, not ordinary bugs.

## Reporting a vulnerability

**Please do not open a public issue, discussion or pull request for a security problem.**

Report it privately through GitHub's private vulnerability reporting:
**[Report a vulnerability](https://github.com/0x00spor3/Light-WAF/security/advisories/new)**
(repository → *Security* tab → *Report a vulnerability*).

Please include:

- the affected component (crate, binary, chart) and version or commit;
- the configuration needed to reproduce it (paranoia level, mode, enabled modules);
- a minimal reproduction — for a detection bypass, the exact request (e.g. a `curl` command)
  and the verdict you got versus the one you expected;
- the impact as you understand it.

## What to expect

- **Acknowledgement** within 7 days.
- An initial **assessment** (accepted / not a vulnerability / needs more information) within
  14 days.
- For accepted reports, we develop the fix in a private advisory, agree on a disclosure date
  with you, and publish the advisory together with the fixed release. Reporters are credited in
  the advisory unless they prefer otherwise.

This is a community-maintained project; the timelines above are targets, not a contractual SLA.

## Scope

In scope — please report privately:

- **Detection bypasses**: a request that carries a working attack in a category the WAF claims to
  cover, yet is allowed at a paranoia level where it should be blocked (evasion through encoding,
  normalization or parsing differences between the WAF and common backends).
- Vulnerabilities in the **proxy** itself: memory-safety issues, crashes or panics reachable from
  a request, request smuggling / desync through the proxy, resource exhaustion that a single
  client can trigger, TLS issues.
- Vulnerabilities in the **control plane, node agent and operator**: authentication or
  authorization bypass, RBAC escalation, session or token flaws, audit-log tampering that verifies
  as valid, injection, SSRF, exposure of secrets or captured request data.
- Supply-chain issues in what this repository builds: signature-verification bypass for WASM
  plugins, insecure defaults in the container images or Helm charts.

Out of scope:

- False positives (legitimate traffic blocked) — please open a normal issue.
- Attacks in categories the WAF does not claim to cover, or bypasses only at a paranoia level
  documented as not covering that case.
- Findings that require an already-compromised host, config file or Kubernetes cluster admin.
- Vulnerabilities in third-party dependencies with no demonstrated impact on Light WAF — report
  those upstream. Known CVEs in base images are tracked by the image scan in CI (`.trivyignore`
  documents every accepted exception and its expiry).

## Supported versions

| Version | Supported |
|---|---|
| 1.0.x | ✅ |
| < 1.0 | ❌ — the 0.x core releases are superseded by 1.0 |

Security fixes are released as patch versions of the latest minor line.
