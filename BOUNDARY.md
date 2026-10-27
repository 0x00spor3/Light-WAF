# BOUNDARY.md — Core and Components

> **Guiding rule.** The **core** is the **security datapath**: it must be fully useful and
> self-sufficient on a **single node**, small enough to audit, and free of operational
> dependencies (no Redis, no Postgres, no control plane). The **components** add **scale,
> governance and team operability** on top of it — never baseline detection capability.
>
> **Mnemonic.** *"Understanding and inspecting a protocol" is core.
> "Running it at scale / with governance" is a component.*

Everything in this repository — core and components — is open source under **Apache-2.0**.
The boundary below is **architectural**, not commercial: it decides what a minimal
single-node deployment contains, which crates may depend on which, and where a new feature
belongs. It is normative: no feature may remain ambiguous. Every entry is labeled `CORE`,
`COMPONENT`, or `SPLIT` (with the cut line made explicit).

> **Terminology.** Older documents and code comments call the core `OPEN` and the
> components the `ENTERPRISE` tier, from when the components were released under a separate
> license. `OPEN` = `CORE`; "enterprise" survives in crate and binary names (`waf-enterprise`,
> `[enterprise]` config table) and simply means *the component layer*.

**The two crate sets.**

| Layer | Crates | Binary |
|---|---|---|
| Core | `waf-core`, `waf-normalizer`, `waf-pipeline`, `waf-detection`, `waf-proxy`, `waf-wasm`, `waf-corpus` | `waf-proxy` (single node, no external services) |
| Components | `waf-state-redis`, `waf-tls-managed`, `waf-threatintel`, `waf-crs-curated`, `waf-modules-premium`, `waf-marketplace`, `waf-capture`, `waf-enterprise` · `waf-controlplane`, `waf-governance`, `waf-node-agent`, `waf-operator` | `waf-enterprise` (data plane with every component wired in) · `waf-controlplane` · `waf-node-agent` · `waf-operator` |

**Dependency rule.** Components depend on the core's **public API only**; the core never
depends on a component. A component never forks or patches the core — it plugs in through
the seams of §4. This is what keeps the core auditable and lets it ship and version on its
own.

---

## 1. CORE — the datapath

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
  Request Smuggling, SSI/XXE, LDAP, NoSQL, Mail, SSTI, scanner fingerprinting.
- **gRPC and GraphQL inspection** → see §3.1 (these are datapath, they stay in the core).

### 1.4 Scoring and tuning
- Cumulative CRS-style anomaly scoring, configurable severities (config **C2**).
- **Paranoia levels** 1–4.
- Equivalence fast-path (`RegexSet` prefilter).

### 1.5 State and rate limiting (single-node)
- **In-process L7 rate limiting** (token bucket).
- **`StateStore`** trait + **in-memory** implementation (`InMemoryStateStore`, in `waf-core`).
  *(This is the extension point the distributed store plugs into, §2.1.)*

### 1.6 Single-node operability
- External TOML config, semantic validation, per-scenario fail-open/closed (`[resilience]`).
- Hot reload via **SIGHUP** (validate-then-swap).
- **Trusted-proxy IP resolution** (`trusted_proxies`, `client_ip_header`, `trusted_hops`).
- Structured **JSON logging**; **Prometheus** `/metrics` export.

### 1.7 Quality, validation and extensibility
- `waf-corpus` (versioned malicious/benign corpus) and test suites.
- **WASM plugin runtime (Proxy-Wasm)**: a `wasmi`-based runtime (`waf-wasm`) loads a `.wasm`
  Proxy-Wasm filter as a `WafModule` (`[modules.wasm]`, default off; implemented host-function
  subset + dynamic stubs for the rest, fuel/memory DoS caps, instance pool, fail-closed — see
  `ARCHITECTURE.md` §9). The *runtime* is core; *signature verification* is a component (§2.4).
- **OWASP CRS / ModSecurity parser**: a `seclang` parser + subset evaluator runs imported
  `SecRule` files as a `WafModule` (`[modules.crs]`, default off; supported subset + boot
  skip-report — see `ARCHITECTURE.md` §9). The *parser/engine* is core; the *curated rule
  content* is a component (§2.4).

---

## 2. COMPONENTS — scale, governance, operability

Built on the core's seams; each is opt-in and default-off.

### 2.1 Distributed multi-node state
- **Distributed `StateStore`** implementation (`waf-state-redis`): cluster-wide rate limiting and
  IP reputation over a shared Redis.

### 2.2 Control plane
- Web dashboard, rule management, blocked-request drill-down, alerting, retention.
- A **separate service** (`waf-controlplane`) consuming the core's telemetry (JSON decision log +
  Prometheus `/metrics`), **never on the data port** and off the request path — it does not
  affect datapath performance. It does not link `waf-core`: it depends on the telemetry
  *contract*, not on the datapath crate.

*Rule management (write path):* the control plane versions **one managed SecRule `.conf`** and a
per-node agent (`waf-node-agent`) pushes it. The WAF loads the file via `[modules.crs].files` and
hot-reloads it on SIGHUP (validate-then-swap); the agent only writes the file and triggers that
existing reload, never linking the datapath. Publish/rollback require `ManageRules` (operator+)
and are audited; the agent **pre-validates** with the core's seclang parser (fail-safe level 1)
before the WAF's own validate-then-swap (level 2). Follow-ons: server-side dry-run,
canary/staged rollout, version diff, multiple named rulesets, ruleset signing.

*API attack-surface inventory:* the control plane builds an inventory of the endpoints seen in
persisted enforcement decisions (`GET /api/inventory` + `/api/inventory/drift`). It aggregates
`decision_events` **on demand** — denied requests only, so this is the observed attack surface,
not all traffic — templating per-id paths (`/users/{}`) and classifying them against the app's
OpenAPI spec: `documented` vs `shadow`. Read-only and off-datapath; the path→route matcher is a
standalone `serde_json`-only re-implementation of the datapath router. Zombie-endpoint detection,
all-traffic discovery and an OpenAPI-draft-from-traffic learning mode are follow-ons.

### 2.3 Governance and compliance
- **RBAC**, SSO (**OIDC native**; **SAML via an IdP broker**, see below), signed audit log.
- Compliance evidence reports (SOC 2 / PCI DSS).

*Governance (`waf-governance`):* a control-plane library on the same Postgres. Three fixed RBAC
roles (viewer/operator/admin) + a pure permission matrix; **local auth** with argon2id passwords
+ server-side sessions (HttpOnly + SameSite=Strict cookie); a **tamper-evident signed audit log**
(SHA-256 hash chain + Ed25519 via `ring`, with `/api/audit/verify`). With governance on, `/api`
takes a session (human, RBAC) or a bearer token (a machine principal); off by default = the plain
bearer. **SSO via OIDC** (Authorization Code + PKCE, id_token verified against the IdP's JWKS,
role mapped from a configurable claim) plus auth hardening: named revocable service tokens,
session listing/revocation, password change/reset, login brute-force throttling. Follow-ons:
cluster-wide throttle, MFA.

*Compliance reports:* a period-scoped, **signed** SOC 2 / PCI evidence bundle assembled from data
the system already holds — access control, the audit log (with a whole-chain verification
attested inside), and WAF telemetry — each section annotated with the controls it supports.
`GET /api/compliance/report?from=&to=` + `POST /api/compliance/verify`; admin-only (`ViewAudit`).
The bundle is Ed25519-signed, so a generated report is self-verifiable evidence. Caveat: denied
volumes are period-accurate, allowed/total are cumulative counters.

*SAML — decided:* **not natively supported, by design; covered via an IdP broker.** Native SAML
requires XML-DSig verification (C14N + XML-Signature-Wrapping), the bug class that has broken
mature SAML libraries across every ecosystem; a hand-rolled validator would be false security,
and the one mature option (`samael` → `xmlsec`/`libxml2`) would bring a C dependency with a CVE
history into the trust crate. Every relevant IdP (Okta, Entra ID, Ping, OneLogin, Keycloak,
Google Workspace) speaks OIDC; a SAML-only IdP is federated behind a broker (Keycloak/Dex) and the
control plane speaks only OIDC. Native SAML would be reconsidered only on concrete demand the
broker path cannot serve, and only via `samael` — never a hand-rolled implementation.

### 2.4 Threat intelligence, curated content, advanced detection
- **Reputation feed** (`waf-threatintel`): populates the `rep:<ip>` keyspace via the
  `ReputationWriter` seam on the shared Redis store — file/HTTP sources, single writer, TTL-based
  snapshot; read on the datapath by a reputation `WafModule`.
- **Curated CRS/ModSecurity content** (`waf-crs-curated`; the *parser* is core, §1.7): tuned
  `SecRule` content (CVE/app/evasion signatures), embedded and injected as a `WafModule` via the
  core's CRS engine, gated by `[enterprise.crs_curated]`. Additive — it never re-implements the
  core baseline; a compat gate proves it loads cleanly under the shipped parser subset.
- **GraphQL / gRPC schema enforcement** (`waf-modules-premium`): validates each GraphQL operation
  against the app's SDL (`apollo-compiler`) and each unary gRPC message against the app's
  `FileDescriptorSet` (`prost-reflect`) — `structural()` `Phase::Body` modules, gated by
  `[enterprise.schema_enforcement]` / `[enterprise.grpc_schema_enforcement]`. Additive
  `Decision::Scores` under the reserved `schema-graphql-*` / `schema-grpc-*` namespaces;
  extraction mirrors the core modules and the core's structural caps run first, bounding the
  validator's input. Follow-ons: gRPC streaming, grpc-web, `.proto`-source input.
- **OpenAPI positive security** (`waf-modules-premium`, `api_schema.rs`): routes each request
  under a guarded path prefix against the app's OpenAPI spec (JSON; 3.0 + 3.1 via `oas3`) and
  validates parameters + JSON body via `jsonschema`, gated by `[enterprise.api_schema]`. An
  unknown route/method scores Critical, a contract violation scores the lower
  `violation_severity`; value-level injection stays in the core's channel (contract, not
  content). `jsonschema` runs with no HTTP retriever — a WAF never fetches remote schemas.
  Follow-ons: BOLA/BFLA, response-side data classification.
- **Client integrity / bot detection** (`waf-modules-premium`): scores a browser-impersonation
  request — a modern-browser UA with no `sec-fetch-*` headers — as additive `Decision::Scores`
  under the reserved `bot-*` namespace, gated by `[enterprise.bot_detection]`. Deliberately not
  the core `scanner` module (UA-tool matching). Follow-ons: behavioral scanner detection,
  TLS/JA fingerprinting.
- **Signed WASM plugins** (`waf-marketplace`; the *runtime* is core, §1.7): verifies a detached
  **minisign/ed25519** signature over the `.wasm` against configured `trusted_keys` before
  delegating to the core's `WasmModule::from_bytes`, gated by `[enterprise.wasm]`.
  **Posture divergence, operator-visible:** the core loader *skips* a broken unsigned plugin (a
  missing plugin only degrades coverage); a signed plugin whose signature does not verify is
  **boot-fatal / fail-closed**, because it is indistinguishable from tampering. Keeping only the
  signed path is a convention unless `[enterprise.wasm].exclusive` is set, which refuses unsigned
  `[modules.wasm]` plugins at boot. Follow-ons: plugin registry, PKI, cosign.

### 2.5 Integration
- **SIEM forwarding** (control plane): a background forwarder PUSHes the stored events — denied
  verdicts, the signed audit log, fired alerts — to configured sinks as a versioned, ECS-like
  NDJSON event (ECS field names where obvious + a `waf.*` namespace). Delivery is at-least-once:
  a `(destination, stream)` cursor advances only on a whole-batch 2xx, so a sink being down loses
  nothing (the SIEM dedups on the stable `event.id`); the lag is exposed by
  `GET /api/siem/status`. The formatter is an abstraction (`SiemFormatter`) so CEF/LEEF/syslog
  are future variants. Config `[controlplane.siem]`, default off.
- **Request capture** (`waf-capture`): buffers full denied requests off-datapath and ships them
  to the control plane for the event drill-down; opt-in, with redaction, retention and RBAC.
- **Kubernetes**: Helm charts for the data plane and the control plane, and an operator
  (`waf-operator`) that reconciles a `WafProxy` custom resource into a data-plane Deployment.

---

## 3. Explicitly decided cases

### 3.1 gRPC and GraphQL → `CORE`
These are **datapath parsing/inspection surfaces**, like multipart or JSON: they are
*detection* capabilities, not *scale*. Leaving them out of the core would yield a WAF unable to
inspect modern traffic. Argument/variable injection flows through `canonicalize_value` + the
derived channel + scoring (§1.4) like any other inspected field; the **structural** protections
run as structural modules, outside the content prefilter.

> **GraphQL — core.** Structural caps — query depth (paren-aware), alias/field/directive counts,
> batch size, and an introspection policy — as a `structural()` `Phase::Body` module
> (`[modules.graphql]`, default off).
>
> **gRPC — core** (over HTTP/2). The core de-frames the gRPC body and extracts the protobuf
> fields into the derived channel (so a SQLi/XSS in a field is caught by the content modules),
> plus a `structural()` `grpc` module with message-size / field-count / nesting-depth caps and a
> compressed-payload policy (`[modules.grpc]`, default off). Content extraction is best-effort
> (schema-less wire format); the structural caps are the guaranteed signal. Forwarding is h2c
> end-to-end with trailer relay (unary; streaming and h2-over-TLS backends deferred).
>
> *Component side* (both): **schema enforcement** against the app's real schema / `.proto`
> (schema governance, §2.4) and the dashboard drill-down (§2.2).

### 3.2 HTTPS / TLS → `SPLIT`
- **Basic TLS termination** (accepting `https://`, cert from file) → `CORE`, for single-node
  self-sufficiency: rustls cert-from-file on the listener, ALPN-negotiated h1/h2, behind the
  `TlsCertSource` seam (`waf-proxy::tls`); config `[tls]`, default off.
- **Certificate management at scale** (automatic ACME, rotation, multi-node certs, **mTLS**) →
  `COMPONENT` (`waf-tls-managed`). It implements the **same** `TlsCertSource` trait — the §4
  pattern (the core ships only `FileCertSource`). The trait has two *additive defaulted* hooks:
  `resolver()` (a dynamic `ResolvesServerCert` for **hitless** ACME rotation; default `None` →
  the single-cert path) and `client_verifier()` (mTLS client auth; default `None` → no client
  auth). The component provides ACME (TLS-ALPN-01 and DNS-01, hitless, multi-node via a shared
  encrypted cert store) and an mTLS verifier.

### 3.3 Cut-line summary

| Feature | CORE | COMPONENT |
|---|---|---|
| WASM plugins (Proxy-Wasm) | runtime | signature verification |
| Metrics | Prometheus `/metrics` export | dashboards, retention, alerting |
| OWASP CRS / ModSecurity rules | parser + engine | curated rule content, managed ruleset rollout |
| TLS | termination, cert from file | ACME, mTLS, multi-node certs |
| Rate limiting / reputation | in-memory, single node | cluster-wide over Redis |
| GraphQL / gRPC / REST | structural caps + content inspection | schema / OpenAPI enforcement |

---

## 4. Architectural pattern: seams

For every component feature, the core defines the **trait** (extension point); the component
provides the **at-scale implementation**.

```rust
// in waf-core — a single ATOMIC operation, not a get/update pair. Refill-then-consume must be
// indivisible across callers, else two nodes read the same bucket level and both allow
// (cluster-wide over-allow / TOCTOU). In-memory enforces it under one lock; the Redis impl
// uses one server-side script. Time and memory-bounding are the store's concern (in-memory
// owns a clock + a tracked-key cap; Redis uses server time + TTL), so they stay out of the ABI.
pub struct BucketParams { pub capacity: f64, pub refill_per_sec: f64 }
pub struct Acquired { pub allowed: bool, pub tokens_remaining: f64 }

pub trait StateStore: Send + Sync {
    fn try_acquire(&self, key: &str, cost: f64, params: BucketParams) -> Acquired;
}
// in-memory impl -> CORE      (InMemoryStateStore)
// Redis impl     -> COMPONENT (waf-state-redis)
```

Future cluster-wide state is added as a new trait method with a default impl (non-breaking),
not a separate get/update KV.

The impl is **injected without forking** through the embedding builder — every seam has a
default, so an empty builder equals `Proxy::bind`:

```rust
// a component binary, using the core as a library:
let proxy = Proxy::builder(&config)
    .state_store(Arc::new(RedisStore::connect(&url)?))    // COMPONENT impl of StateStore
    .cert_source(Arc::new(AcmeCertSource::new(..)))        // COMPONENT impl of TlsCertSource
    .module_factory(move || Ok(build_extra_modules()))     // extra WafModule set (survives reload)
    .build()
    .await?;
```

`.modules(..)`/`.add_module(..)` inject a *static* extra set built once — convenient for tests,
but **dropped on a config reload**. `.module_factory(F)` takes a
`Fn() -> Result<Vec<Box<dyn WafModule>>>` that the core re-runs on every reload (and at bind), so
injected modules **survive a SIGHUP** and are re-`init`'d — this is the seam a component binary
uses for its modules. It is fallible as a unit: a failed rebuild aborts that reload and keeps the
last-good modules (never an unprotected window), exactly like a rejected config.

**Where a new feature goes.** If it is needed to *inspect* traffic correctly on one node, it
belongs in the core. If it needs shared infrastructure (Redis, Postgres, a control plane, an
external service) or exists to operate many nodes or many people, it is a component — and if the
core lacks the seam it needs, add the seam to the core first (additively, §5), then build the
component on it.

---

## 5. Stability policy

The `WafModule`, `StateStore` and `TlsCertSource` traits and the `ProxyBuilder` are **public
ABI** under SemVer (1.0 onward: a breaking change requires a new major version).

**Additive trait evolution (allowed).** A new method with a default body is non-breaking for
existing impls (like `WafModule::structural()`). `TlsCertSource` grew `resolver()` and
`client_verifier()` (both defaulting to `None`) this way, enabling ACME/mTLS (§3.2) without
touching `FileCertSource` or any external impl. This is the only sanctioned way to extend a
frozen ABI trait — additive, defaulted, minor version.

**Additive builder evolution (allowed).** A new `ProxyBuilder` method with a default (the seam is
`None` when unset) is likewise non-breaking. `.module_factory(F)` was added this way; the
`ModuleFactory` type alias is part of the frozen public surface.

**Config evolution.** `Config` is `#[non_exhaustive]`: adding a top-level section (as `tls` was
added) is non-breaking — external code cannot use a `Config { .. }` literal, it builds from
`Config::default()`/TOML and mutates, so a new field is absorbed. This protects the whole config
tree transitively, *except* the sub-configs also taken by value by a public fn (`TlsConfig` →
`acceptor_from_*`, `NetworkConfig` → `ClientIpResolver::from_config`, `LimitsConfig` →
`Normalizer::new`), which are marked `#[non_exhaustive]` individually. Marking a struct
`#[non_exhaustive]` later is itself breaking, so this set is part of the freeze.

**Boundary moves.** A capability in the core is **never moved out** to a component — that would
silently remove it from minimal single-node deployments. Moving a capability from a component
into the core is allowed.

Every new feature must be placed in this file **before merge**, with an unambiguous label.

---

## 6. Licensing and contributions

- **License.** The whole repository is **Apache-2.0** — chosen over MIT for the explicit
  **patent grant + retaliation clause** (§3), which matters for a security product. The
  component crates were originally released under the Business Source License 1.1 and were
  relicensed to Apache-2.0 by the sole copyright holder in 2026 (see `NOTICE`).
- **Contributions.** Inbound = outbound: contributions are accepted under Apache-2.0, with a
  **Developer Certificate of Origin** sign-off on every commit (`git commit -s`). See
  [`CONTRIBUTING.md`](CONTRIBUTING.md).
- **Per-file hygiene.** An SPDX header in every source file (`add-spdx.sh`), a root `LICENSE`, and
  a `NOTICE` file for attribution (Apache-2.0 §4).
- **Name.** Apache-2.0 §6 grants no rights to the project name or logo: forks are welcome, but
  must not present themselves as Light WAF.
