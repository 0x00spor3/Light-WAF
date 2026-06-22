# BOUNDARY.md — Open / Enterprise Boundary

> **Guiding rule.** The *core* is the **security datapath**: it must be fully useful
> and self-sufficient in **single-node**, and it must be **inspectable** (in security,
> trust requires open code). The **enterprise** tier sells **scale, governance, and
> team operability** — never baseline detection capability.
>
> **Mnemonic.** *"Understanding and inspecting a protocol" is core.
> "Managing it at scale / with governance" is enterprise.*

This document is normative: no feature may remain ambiguous. Every entry is labeled
`OPEN`, `ENTERPRISE`, or `SPLIT` (with the cut line made explicit). Retroactively
changing an already-released boundary is forbidden (see §Boundary stability policy).

---

## 1. OPEN SOURCE (community) — Apache-2.0 license

The complete datapath and everything needed to protect a single node.

### 1.1 Datapath and orchestration
- Listener and standalone **reverse proxy**.
- **Phased pipeline** (`on_connection` → `on_request_line` → `on_headers` → `on_body` → `on_response`).
- `WafModule` module contract and the `Decision` type (Allow / Block / Monitor / Score / Scores / Reject).
- `RequestContext` and score accumulation.

### 1.2 Normalization and canonicalization
- `canonicalize_value` (conditional percent-decode, NFKC, pipeline-wide overlong-collapse).
- Derived `decode-then-match-then-discard` channel (base64, HTML-entity, tag/control-strip, VBScript-concat).
- Multipart coverage (`name` / `filename` / `value`), JSON leaf canonicalization, cookie normalization.

### 1.3 Detection modules (all of them)
- SQLi, XSS, Path Traversal, RCE/Cmd-Injection, LFI/RFI, SSRF, Header Injection,
  Request Smuggling, SSI/XXE.
- **gRPC and GraphQL inspection** → see §3.1 (these are datapath, they stay OPEN).

### 1.4 Scoring and tuning
- Cumulative CRS-style anomaly scoring, configurable severities (config **C2**).
- **Paranoia levels** 1–4.
- Equivalence fast-path (`RegexSet` prefilter).

### 1.5 State and rate limiting (single-node)
- **In-process L7 rate limiting** (token bucket).
- **`StateStore`** trait + **in-memory** implementation (`waf-state`). *(This is the extension point onto which enterprise multi-node plugs in.)*

### 1.6 Single-node operability
- External TOML config, semantic validation, per-scenario fail-open/closed (`[resilience]`).
- Hot reload via **SIGHUP** (validate-then-swap).
- **Trusted-proxy IP resolution** (`trusted_proxies`, `client_ip_header`, `trusted_hops`).
- Structured **JSON logging**; **baseline OpenTelemetry/Prometheus** export.

### 1.7 Quality and validation
- `waf-corpus` (versioned malicious/benign corpus) and test suites.
- Extensibility: **WASM plugin runtime (Proxy-Wasm)**.
- **Parser** for importing OWASP CRS / ModSecurity rules.

---

## 2. ENTERPRISE (paid) — source-available license (BSL 1.1 / Elastic 2.0)

Scale, governance, compliance, and team operability.

### 2.1 Distributed multi-node state
- **Distributed `StateStore`** implementation (Redis/shared store): cluster-wide rate-limit and IP-reputation.

### 2.2 Control plane
- Web dashboard, rule management, blocked-request drill-down, alerting.
- **Pre-built dashboards + long-term retention** of metrics/telemetry.

### 2.3 Governance and compliance
- **RBAC**, SSO/SAML/OIDC, signed audit logs (SOC2 / PCI-DSS).
- Automated compliance reports, long-term retention.

### 2.4 Threat intelligence and curated content
- **Premium reputation/signature feed** by subscription.
- **Curated premium CRS/ModSecurity rules** (the *parser* stays OPEN, §1.7).
- WASM plugin **marketplace/signing** (the *runtime* stays OPEN, §1.7).

### 2.5 Integration and support
- Enterprise SIEM connectors, SLA support, guided hardening.

---

## 3. Explicitly decided cases

### 3.1 gRPC and GraphQL → `OPEN`
These are **datapath parsing/inspection surfaces**, like multipart or JSON: they are
*detection* capabilities, not *scale*. Keeping them out of the core would yield a WAF
unable to inspect modern traffic (a "gutted core") and would push into closed-source
exactly the part that requires inspectable trust. They flow through `canonicalize_value`,
the prefilter, and the scoring in §1.4 like any other inspected field.
> *Associated enterprise value:* premium GraphQL signatures (curated depth/complexity
> abuse), managed schema-enforcement, dashboard drill-down → §2.

### 3.2 HTTPS / TLS → `SPLIT`
- **Basic TLS termination** (accepting `https://`, cert from file) → `OPEN`, for
  single-node self-sufficiency. *(Note: `ARCHITECTURE.md` currently classifies this as
  a non-goal, delegated to the front proxy; if/when implemented, it is core.)*
- **Certificate management at scale** (automatic ACME/Let's Encrypt, rotation,
  centralized multi-node certs, **mTLS with managed PKI**) → `ENTERPRISE`
  (governance/scale).

### 3.3 Gray zone (cut-line summary)

| Feature | OPEN | ENTERPRISE |
|---|---|---|
| WASM plugins (Proxy-Wasm) | runtime | marketplace / signing |
| OpenTelemetry / Prometheus | baseline export | pre-built dashboards + retention |
| OWASP CRS / ModSecurity rules | parser | curated premium rules |
| TLS | basic termination | ACME / mTLS PKI / multi-node |

---

## 4. Boundary architectural pattern

For every enterprise feature, the core defines the **trait** (extension point);
the enterprise provides the **at-scale implementation**.

```rust
// in waf-core (OPEN)
pub trait StateStore: Send + Sync {
    fn get_bucket(&self, key: &str) -> Option<Bucket>;
    fn update_bucket(&self, key: &str, b: Bucket);
    fn sweep_idle(&self);
}
// in-memory impl -> OPEN        (waf-state)
// Redis impl      -> ENTERPRISE (waf-state-redis)
```

The same scheme is replicated for reputation/feed and the other extension points.

---

## 5. Boundary stability policy

The `WafModule` and `StateStore` traits are **public ABI**: SemVer, frozen
before the first public release.

A feature labeled `OPEN` **cannot** be moved to `ENTERPRISE` retroactively after a
release. The only permitted move is `ENTERPRISE → OPEN`.

Every new feature must be added to this file **before merge**, with an unambiguous label.

---

## 6. Licensing & contribution governance

> Engineering policy, not legal advice — the CLA text and trademark filings must be
> validated with counsel. The *decisions* below are fixed; the wording is not.

### 6.1 Core license = **Apache-2.0** (decided)
- **Chosen over MIT** for the explicit **patent grant + retaliation clause** (§3) —
  material for a security product — and the explicit **trademark exclusion** (§6),
  which opens the code without opening the name (see §6.3).
- **NOT AGPL / SSPL / BSL on the core.** Cloud-hostility lives in the **enterprise tier**
  (§2, BSL/Elastic), never in the datapath. A copyleft/source-available core would tax
  community adoption (enterprise legal teams routinely ban AGPL) and contradict the
  guiding rule (*inspectable, widely-adopted datapath*). The moat is the enterprise tier,
  not the core license — do not pay the adoption tax twice.

### 6.2 Contributor agreement — **REQUIRED before the first external contribution**
- Open-core depends on the ability to **dual-license** (sell commercial exceptions) and
  to relicense. Without inbound rights, a **single** external contributor can permanently
  block relicensing of the touched code.
- **Decision:** a **CLA** granting the project the right to license contributions under
  *both* the open license **and** the enterprise license; **DCO** (`Signed-off-by`) is the
  hard minimum. Must be wired into CI (bot check) **before** the first external PR is merged.
- **Document:** the agreement lives in [`CLA.md`](CLA.md) (Individual CLA, modeled on the
  Apache ICLA + the dual-licensing grant). A Corporate CLA is required when a company
  contributes on behalf of its employees (§4 of `CLA.md`).

### 6.3 Trademark = the real moat of a permissive core
- The permissive license opens the **code**, not the **name**. Register the project/product
  **name + logo**.
- **Policy:** *"fork it, but you cannot call it X, nor offer a service as X."* This is what
  a permissive open-core relies on for brand defense (Apache-2.0 §6 leaves it intact by design).

### 6.4 Per-crate hygiene (makes the §4 boundary physical, not just documentary)
- **SPDX header** in every source file; root `LICENSE` = Apache-2.0; a `NOTICE` file for
  third-party attribution (Apache-2.0 §4).
- **Enterprise crates** (`waf-state-redis`, control-plane, …) live in a **separate
  path/repo**, each carrying its own **BSL** `LICENSE` — so the cut line of §4 is enforced
  by file layout, not only by this document.
