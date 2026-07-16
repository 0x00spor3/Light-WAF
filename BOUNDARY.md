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
- **`StateStore`** trait + **in-memory** implementation (`InMemoryStateStore`, in `waf-core`). *(This is the extension point onto which enterprise multi-node plugs in.)*

### 1.6 Single-node operability
- External TOML config, semantic validation, per-scenario fail-open/closed (`[resilience]`).
- Hot reload via **SIGHUP** (validate-then-swap).
- **Trusted-proxy IP resolution** (`trusted_proxies`, `client_ip_header`, `trusted_hops`).
- Structured **JSON logging**; **baseline OpenTelemetry/Prometheus** export.

### 1.7 Quality and validation
- `waf-corpus` (versioned malicious/benign corpus) and test suites.
- Extensibility: **WASM plugin runtime (Proxy-Wasm)**. **IMPLEMENTED (B3)**: a `wasmi`-based
  runtime (`waf-wasm` crate) loads a `.wasm` Proxy-Wasm filter as a `WafModule` (`[modules.wasm]`,
  default off; implemented host-function subset + dynamic stubs for the rest, fuel/memory DoS
  caps, instance pool, fail-closed — see `ARCHITECTURE.md` §9). The *runtime* is OPEN;
  *marketplace/signing* stays enterprise (§2.4).
- **Parser** for importing OWASP CRS / ModSecurity rules. **IMPLEMENTED (B2)**: a `seclang`
  parser + subset evaluator runs imported `SecRule` files as a `WafModule` (`[modules.crs]`,
  default off; supported subset + boot skip-report — see `ARCHITECTURE.md` §9). The *parser/engine*
  is OPEN; the *curated rule content* stays enterprise (§2.4).

---

## 2. ENTERPRISE (paid) — source-available license (BSL 1.1 / Elastic 2.0)

Scale, governance, compliance, and team operability.

### 2.1 Distributed multi-node state
- **Distributed `StateStore`** implementation (Redis/shared store): cluster-wide rate-limit and IP-reputation.

### 2.2 Control plane
- Web dashboard, rule management, blocked-request drill-down, alerting.
- **Pre-built dashboards + long-term retention** of metrics/telemetry.
- A **separate service** consuming the OPEN telemetry (JSON decision-log + Prometheus `/metrics`),
  **never on the data port** and off the request path — it does not affect datapath performance.
  v1 (`waf-controlplane`, enterprise) is read-only observability: ingestion + retention + drill-down
  + read API.

*(RULE-MANAGEMENT WRITE PATH IMPLEMENTED 2026-07-07, gated behind §2.3 governance: the control plane
versions **one managed SecRule `.conf`** and a per-node agent (`waf-node-agent`) pushes it. **Zero-core** —
the WAF loads the file via `[modules.crs].files` and hot-reloads it on SIGHUP (validate-then-swap); the
agent only writes the file + triggers that existing reload, never linking the datapath. Publish/rollback
require `ManageRules` (operator+) and are audited; the agent **pre-validates** with the OPEN seclang parser
(fail-safe level 1) before the WAF's own validate-then-swap (level 2). A **Rules** dashboard view covers
publish / rollback / per-node convergence. Follow-on: server-side dry-run, canary/staged rollout, version
diff, multiple named rulesets, ruleset signing.)*

*(API ATTACK-SURFACE INVENTORY IMPLEMENTED 2026-07-15, §4-B pt3 discovery: the control plane builds an inventory
of the endpoints seen in persisted enforcement decisions (`GET /api/inventory` + `/api/inventory/drift`, "API
Inventory" dashboard view). It aggregates `decision_events` **on demand** — which hold **denied requests only**, so
this is the observed attack surface, not all-traffic — templating per-id paths (`/users/{}`) and classifying them
against the app's OpenAPI spec: `documented` (a declared endpoint drawing blocks) vs `shadow` (an undeclared
endpoint being hit). Read-only, off-datapath, and **core-free** — the control plane does not link `waf-core`, so
the path→route matcher is a standalone `serde_json`-only re-implementation of the datapath router, not an import of
the premium module. Zombie [declared-but-unused] detection and all-traffic discovery need an all-traffic ingest =
follow-on; a learning-mode OpenAPI-draft-from-traffic is a follow-on too.)*

### 2.3 Governance and compliance
- **RBAC**, SSO (**OIDC native**; **SAML via an IdP broker**, see below), signed audit logs (SOC2 / PCI-DSS).
- Automated compliance reports, long-term retention.

*(COMPLIANCE REPORTS IMPLEMENTED 2026-07-07: a period-scoped, **signed** SOC2/PCI evidence bundle assembled
from data the system already holds — access control, the tamper-evident audit log (a whole-chain
verification is attested inside), and WAF telemetry — each section annotated with the controls it supports.
Read-only, zero-core/zero-datapath, admin-only (`ViewAudit`), only with governance on (reuses the audit
signer). `GET /api/compliance/report?from=&to=` + `POST /api/compliance/verify` + a **Compliance** dashboard
view (print-to-PDF). The bundle is itself Ed25519-signed (order-independent content hash), so a generated
report is self-verifiable evidence. Caveat: denied volumes are period-accurate, allowed/total are cumulative
counters. Follow-on: native PDF, an immutable report archive, a dedicated auditor role.)*

*(v1 IMPLEMENTED 2026-07-06: `waf-governance` — a control-plane library, zero-core/zero-datapath, on the
same Postgres. Three fixed RBAC roles (viewer/operator/admin) + a pure permission matrix; **local auth**
with argon2id passwords + server-side sessions (HttpOnly + SameSite=Strict cookie); a **tamper-evident
signed audit log** (SHA-256 hash chain + Ed25519 via `ring`, with a `/api/audit/verify` endpoint). With
governance on, `/api` takes a session (human, RBAC) or the bearer (a machine/admin principal); off by
default = the plain bearer, backward-compat.)*

*(v2 IMPLEMENTED 2026-07-06: **SSO via OIDC** (Authorization Code + PKCE, id_token verified against the
IdP's JWKS; role mapped from a configurable claim; federated user provisioning) — verified live against
Keycloak — plus **auth hardening**: named revocable role-bound service tokens, session listing/revocation
(auto-revoke on disable / password change), self-service password change + admin reset, and login
brute-force throttling. **Follow-on:** automated compliance reports, cluster-wide throttle, MFA.
This unblocked the §2.2 rule-management write path (RBAC `ManageRules` + audit), now IMPLEMENTED.)*

*(SAML — FROZEN DECISION 2026-07-07: **not natively supported by design; covered via an IdP broker.**
Native SAML requires XML-DSig verification (C14N canonicalization + XML-Signature-Wrapping) — the bug
class that has broken mature SAML libraries across every ecosystem for years; a hand-rolled validator
would be false security (the §4-B/apollo-compiler discipline in reverse: there we chose the mature
library because the control was critical — here a mature *pure-Rust* library does not exist, so we stay
out of the territory), and the one mature option (`samael` → `xmlsec`/`libxml2`, a real CVE history)
would betray the pure-Rust/no-C posture in the trust crate itself. Every relevant enterprise IdP (Okta,
Entra ID, Ping, OneLogin, Keycloak, Google Workspace) speaks OIDC natively; the residual "SAML-only" case
is covered by an **IdP broker** (Keycloak/Dex) — the customer's SAML IdP federated behind it, the control
plane speaking only OIDC (runbook §J). **Native = demand-driven follow-on**: reconsidered ONLY on real
paying-customer demand blocked by the broker path, and ONLY toward `samael` — never a pure-Rust hand-roll.)*

### 2.4 Threat intelligence and curated content
- **Premium reputation/signature feed** by subscription. *(Reputation feed IMPLEMENTED
  2026-07-02: `waf-threatintel` populates the `rep:<ip>` keyspace via the `ReputationWriter`
  write seam on the shared Redis store — file/HTTP sources, single-writer, TTL-based snapshot;
  the datapath read stays enterprise-only, out of the frozen core ABI.)*
- **Curated premium CRS/ModSecurity rules** (the *parser* stays OPEN, §1.7). *(IMPLEMENTED
  2026-07-02: `waf-crs-curated` ships the tuned premium `SecRule` CONTENT (CVE/app/evasion
  signatures), embedded and injected as a `WafModule` via the OPEN CRS engine, gated by
  `[enterprise.crs_curated]`. Premium-additive — it never re-implements the OPEN baseline; a compat
  gate proves it loads cleanly under the shipped parser subset.)*
- **Managed GraphQL/gRPC schema-enforcement** (validating against the app's real `.graphql` schema /
  `.proto` descriptor = schema management/governance, §3.1). *(IMPLEMENTED 2026-07-03: `waf-modules-premium`
  validates each GraphQL operation against the app's SDL via `apollo-compiler`, and each unary gRPC message
  against the app's compiled `FileDescriptorSet` via `prost-reflect` — both `structural()` `Phase::Body`
  `WafModule`s, gated by `[enterprise.schema_enforcement]` / `[enterprise.grpc_schema_enforcement]`, default
  off. Premium-additive `Decision::Scores` under the reserved `schema-graphql-*` / `schema-grpc-*` id namespaces;
  extraction mirrors the OPEN Phase-11 / gRPC modules and the OPEN structural caps run first, bounding the
  validator's input. gRPC v1 is unary; protobuf unknown-field flagging is opt-in [forward-compat]; streaming /
  grpc-web / `.proto`-source input are follow-ons.)*
- **Managed OpenAPI positive-security** (validating each REST/JSON request against the app's real OpenAPI spec =
  contract governance, §3.1). *(IMPLEMENTED 2026-07-15: `waf-modules-premium` `api_schema.rs` routes each request
  under a guarded path prefix against the spec (JSON; 3.0+3.1 via `oas3`) and validates parameters + JSON body via
  `jsonschema` — a `structural()` `Phase::Body` `WafModule`, gated by `[enterprise.api_schema]`, default off.
  Premium-additive `Decision::Scores` under the reserved `schema-api-*` id namespace; an unknown route/method scores
  Critical, a contract violation [param/body shape] scores the lower `violation_severity`. Extraction mirrors the
  OPEN normalization [routes on the decoded/traversal-resolved path] and value-level injection stays in the OPEN §6
  channel [contract, not content]. `jsonschema` runs with no HTTP retriever [a WAF never fetches remote schemas];
  3.0 schemas are normalized to standard JSON Schema at load [`nullable`]. v1 is JSON-only; BOLA/BFLA and
  response-side data classification are follow-ons.)*
- **Premium native signature modules** (§4-A): high-curation `WafModule`s for logic a single regex
  can't express — deliberately NOT the OPEN `scanner` (UA-tool matching) or curated content (§6).
  *(Client-integrity / bot detection IMPLEMENTED 2026-07-03: `waf-modules-premium` scores a
  browser-impersonation request — a modern-browser UA with no `sec-fetch-*` headers — as an additive
  `Decision::Scores` under the reserved `bot-*` id namespace, `Phase::Headers` `structural()`,
  `[enterprise.bot_detection]`, default off. Behavioral/rate-based scanner detection and TLS/JA
  fingerprinting are follow-ons.)*
- WASM plugin **marketplace/signing** (the *runtime* stays OPEN, §1.7). *(Signing IMPLEMENTED
  2026-07-03: `waf-marketplace` verifies a detached **minisign/ed25519** signature over the `.wasm`
  against configured `trusted_keys` before delegating to the OPEN `WasmModule::from_bytes`, gated by
  `[enterprise.wasm]`, default off.* **Posture divergence, operator-visible**: the OPEN loader SKIPS a
  broken UNSIGNED plugin (a missing plugin only degrades coverage); a SIGNED plugin whose signature does
  not verify is **boot-fatal / fail-closed**, because it is indistinguishable from tampering. *Coexistence
  limit: leaving only the signed path is a convention, not enforcement — an attacker who can write the
  config could add an unsigned plugin under the OPEN `[modules.wasm]`; the `[enterprise.wasm].exclusive`
  flag turns that into a boot-time refusal. Full marketplace / PKI / cosign are follow-ons.)*

### 2.5 Integration and support
- Enterprise SIEM connectors, SLA support, guided hardening.

*(SIEM CONNECTORS IMPLEMENTED 2026-07-07: a background forwarder in the control plane PUSHes the stored
events — denied WAF verdicts + the signed audit log + fired alerts — to configured SIEM sinks, normalized
into a versioned, ECS-like NDJSON event (ECS field names where obvious + a `waf.*` domain namespace).
Read-only, zero-core/zero-datapath (it reads the control-plane stores; the WAF is unaware). Delivery is
at-least-once: a `(destination, stream)` cursor advances only on a whole-batch 2xx ack, so a sink being
down loses nothing (the SIEM dedups on the stable `event.id`); backpressure is bounded by Postgres
(retention), and the lag is exposed by `GET /api/siem/status`. The formatter is an abstraction from day one
(`SiemFormatter`) so CEF/LEEF/syslog and vendor adapters are future variants over the same event. Config
`[controlplane.siem]`, default off. Follow-on: those extra formats, a native `siem_forwarder_lag` metric,
a dead-letter queue, export filters, OTLP.)*

---

## 3. Explicitly decided cases

### 3.1 gRPC and GraphQL → `OPEN`
These are **datapath parsing/inspection surfaces**, like multipart or JSON: they are
*detection* capabilities, not *scale*. Keeping them out of the core would yield a WAF
unable to inspect modern traffic (a "gutted core") and would push into closed-source
exactly the part that requires inspectable trust. Argument/variable injection flows
through `canonicalize_value` + the derived channel + scoring (§1.4) like any other
inspected field; the **structural** GraphQL protections run as a structural module
(see below), outside the content prefilter.
> **GraphQL — IMPLEMENTED (Phase 11), `OPEN`.** The core ships the **structural caps** — query
> depth (paren-aware), alias/field/directive counts, batch size, and an introspection policy —
> as a `structural()` `Phase::Body` module (`[modules.graphql]`, default off).
>
> **gRPC — IMPLEMENTED (gRPC phase, over Phase-12 HTTP/2), `OPEN`.** The core de-frames the gRPC
> body and extracts the protobuf fields into the §6 derived channel (so a SQLi/XSS in a field is
> caught by the content modules), plus a `structural()` `grpc` module with message-size / field-count
> / nesting-depth caps and a compressed-payload policy (`[modules.grpc]`, default off). Content
> extraction is best-effort (schema-less wire format); the structural caps are the guaranteed signal.
> Forwarding is h2c end-to-end with trailer relay (unary; streaming + h2-over-TLS backend deferred).
>
> *Associated enterprise value* (for both): premium GraphQL/gRPC signatures (curated depth/complexity
> abuse), **managed schema-enforcement** (validating against the app's real schema/`.proto` = schema
> management/governance), dashboard drill-down → §2.

### 3.2 HTTPS / TLS → `SPLIT`
- **Basic TLS termination** (accepting `https://`, cert from file) → `OPEN`, for
  single-node self-sufficiency. **IMPLEMENTED (Phase 12)**: rustls cert-from-file on the
  listener, ALPN-negotiated h1/h2 via the `auto` builder, behind the `TlsCertSource` seam
  (`waf-proxy::tls`); config `[tls]`, default off. See `ARCHITECTURE.md` §9.
- **Certificate management at scale** (automatic ACME/Let's Encrypt, rotation,
  centralized multi-node certs, **mTLS with managed PKI**) → `ENTERPRISE`
  (governance/scale). These plug in as enterprise implementations of the **same**
  `TlsCertSource` trait — the §4 pattern (the core ships only `FileCertSource`).
  **IMPLEMENTED (enterprise `waf-tls-managed`, core 0.2):** the trait gained two
  *additive defaulted* hooks — `resolver()` (a dynamic `ResolvesServerCert` for
  **hitless** ACME rotation; default `None` → the OPEN single-cert path) and
  `client_verifier()` (mTLS / managed-PKI client auth; default `None` → no client
  auth). The enterprise crate provides ACME (TLS-ALPN-01, hitless) + an mTLS verifier;
  the OPEN `FileCertSource` is unchanged (both hooks default `None`). See §5.

### 3.3 Gray zone (cut-line summary)

| Feature | OPEN | ENTERPRISE |
|---|---|---|
| WASM plugins (Proxy-Wasm) | runtime ✅ (B3) | marketplace / signing |
| OpenTelemetry / Prometheus | baseline export | pre-built dashboards + retention |
| OWASP CRS / ModSecurity rules | parser ✅ (B2) | curated premium rules |
| TLS | basic termination | ACME / mTLS PKI / multi-node |

---

## 4. Boundary architectural pattern

For every enterprise feature, the core defines the **trait** (extension point);
the enterprise provides the **at-scale implementation**.

```rust
// in waf-core (OPEN) — A0 decision (2026-06-24): a single ATOMIC operation, not a
// get/update pair. Refill-then-consume must be indivisible across callers, else two
// nodes read the same bucket level and both allow (cluster-wide over-allow / TOCTOU).
// In-memory enforces it under one lock; a Redis impl uses one server-side script.
// Time and memory-bounding are the store's concern (in-memory owns a clock + a
// tracked-key cap; Redis uses server time + TTL), so they stay out of the ABI.
pub struct BucketParams { pub capacity: f64, pub refill_per_sec: f64 }
pub struct Acquired { pub allowed: bool, pub tokens_remaining: f64 }

pub trait StateStore: Send + Sync {
    fn try_acquire(&self, key: &str, cost: f64, params: BucketParams) -> Acquired;
}
// in-memory impl -> OPEN        (InMemoryStateStore)
// Redis impl      -> ENTERPRISE (waf-state-redis)
```

Future cluster-wide state (e.g. IP-reputation, §2.1) is added as a new trait method
with a default impl (non-breaking), not a separate get/update KV.

The impl is **injected without forking** through the stable embedding builder
(A2, 2026-06-24) — every seam has a default, so an empty builder equals `Proxy::bind`:

```rust
// enterprise crate, depending on the published core as a LIBRARY:
let proxy = Proxy::builder(&config)
    .state_store(Arc::new(RedisStore::connect(&url)?)) // ENTERPRISE impl of StateStore
    .cert_source(Arc::new(AcmeCertSource::new(..)))     // ENTERPRISE impl of TlsCertSource
    .module_factory(move || Ok(build_premium_modules())) // extra WafModule set (survives reload)
    .build()
    .await?;
```

`.modules(..)`/`.add_module(..)` inject a *static* extra set built once — they are
convenient for tests but are **dropped on a config reload**. `.module_factory(F)` (core 0.3)
takes a `Fn() -> Result<Vec<Box<dyn WafModule>>>` that the core re-runs on every reload (and
at bind), so injected modules **survive a SIGHUP** and are re-`init`'d — this is the seam an
embedder uses for premium modules. It is fallible as a UNIT: a failed rebuild aborts that
reload and keeps the last-good modules (never an unprotected window), exactly like a rejected
config.

---

## 5. Boundary stability policy

The `WafModule`, `StateStore` and `TlsCertSource` traits are **public ABI**: SemVer,
frozen before the first public release.

**Additive trait evolution (allowed).** A new method with a default body is non-breaking
for existing impls (like `WafModule::structural()`). `TlsCertSource` used this in **core
0.2**: it gained `resolver()` and `client_verifier()` (both defaulting to `None`), enabling
enterprise ACME/mTLS (§3.2) without touching `FileCertSource` or any external impl. This is
the only sanctioned way to extend a frozen ABI trait — additive, defaulted, minor-version.

**Additive builder evolution (allowed).** A new `ProxyBuilder` method with a default (the
seam is `None` when unset) is likewise non-breaking. **Core 0.3** added `.module_factory(F)`
this way: injected modules are rebuilt on every config reload instead of being dropped, so
they survive a SIGHUP. `WafModule` itself is unchanged; this is a builder seam, not a trait
change — additive, minor-version. The `ModuleFactory` type alias becomes part of the frozen
public surface.

**Config evolution (A4, 2026-06-24).** `Config` is `#[non_exhaustive]`: adding a future
top-level section (as `tls` was added) is **non-breaking** — external code cannot use a
`Config { .. }` literal, it builds from `Config::default()`/TOML and mutates, so a new
field is absorbed. This protects the whole config tree transitively, *except* the
sub-configs ALSO taken by-value by a public fn (`TlsConfig` → `acceptor_from_*`,
`NetworkConfig` → `ClientIpResolver::from_config`, `LimitsConfig` → `Normalizer::new`),
which are marked `#[non_exhaustive]` individually. The remaining sub-configs stay
literal-constructible (reached only through `config.field`). Marking a struct
`#[non_exhaustive]` later is itself breaking, so this set is part of the freeze.

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
