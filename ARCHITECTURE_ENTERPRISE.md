# ARCHITECTURE_ENTERPRISE.md — Light WAF components

> Architecture of the **components** (scale, governance, operability) — Apache-2.0 like the rest
> of the repository. It assumes familiarity with the core (`ARCHITECTURE.md`) and with the
> boundary (`BOUNDARY.md`).
>
> **Guiding rule, inherited from `BOUNDARY.md`.** The core is the **security datapath**
> (single node, auditable). The components add **scale, governance and team operability** —
> NEVER baseline detection capability. *"Understanding and inspecting a protocol" is core;
> "running it at scale / with governance" is a component.*
>
> *Terminology:* in this document "enterprise" names the component layer (it started as a
> separately licensed tier; it is now Apache-2.0 like the core) and `OPEN` names the core. See
> `BOUNDARY.md`.

---

## 1. Goals and non-goals

### Goals
- **Multi-node scale**: shared state (rate limit + IP reputation) cluster-wide, consistent and
  not exploitable (no over-allow, no TOCTOU).
- **Governance & compliance**: RBAC, SSO, signed audit log, SOC 2 / PCI DSS reports.
- **Team operability**: a control plane (dashboard, drill-down, alerting) and long-term
  retention of metrics/telemetry.
- **Threat intelligence**: reputation feeds and curated CRS rules.
- **Integration**: SIEM connectors, signed WASM plugins, certificate management at scale (ACME,
  rotation, mTLS).

### Non-goals (boundary constraints, NOT negotiable)
- **No baseline detection** lives here: SQLi/XSS/PT/RCE/LFI-RFI/SSRF/header injection/
  smuggling/SSI/XXE, GraphQL and gRPC inspection, scoring, fast path, normalization → they stay
  in the **core** (`BOUNDARY.md` §1.3, §3.1). Moving them out would leave a "gutted core".
- **No fork of the core**: components **depend** on the core's public API and **implement its
  traits** (`BOUNDARY.md` §4, §5); they never reach into its internals.
- **No moving capabilities out of the core** (`BOUNDARY.md` §5): moving a capability from a
  component into the core is allowed, never the reverse.

---

## 2. Architectural principle: extension, not fork

The components are a **set of separate crates** (in the same workspace as the core, but with no
access to its internals — `BOUNDARY.md`) that **depend** on the core as a library and hook into
its **three stable seams** (frozen ABI, SemVer — `BOUNDARY.md` §5):

```rust
// a component binary, using the core as a library:
let proxy = Proxy::builder(&config)
    .state_store(Arc::new(RedisStore::connect(&url)?))  // §3 — distributed StateStore
    .cert_source(Arc::new(AcmeCertSource::new(..)))      // §5 — TlsCertSource at scale
    .module_factory(move || Ok(extra_modules()))         // §4 — extra WafModules (survive reload)
    .build()
    .await?;
```

Every seam has a **core default**: a builder with no overrides is identical to `Proxy::bind`. A
component **replaces** an implementation; it does not rewrite the datapath. Standing constraint:
every new cluster-wide capability is a **new trait method with a default impl** (additive,
non-breaking — `BOUNDARY.md` §4), never a parallel trait that bypasses the pipeline.

### Crate map

| Component crate | Seam / area | Depends on |
|---|---|---|
| `waf-state-redis`     | distributed `StateStore` (§3), shared cert store (§5) | `waf-core::state` |
| `waf-tls-managed`     | `TlsCertSource` ACME/mTLS (§5) | `waf-proxy::tls` |
| `waf-schema-enforcement` | extra `WafModule`s: schema enforcement, OpenAPI, bot detection (§4) | `waf-core` (module contract) |
| `waf-threatintel`     | reputation feed + reputation module (§3, §6) | `waf-core`, `waf-state-redis` |
| `waf-crs-curated`     | curated CRS content (§6) | the core CRS engine (`waf-detection`) |
| `waf-wasm-signing`     | signed WASM plugins (§4) | the core `waf-wasm` runtime |
| `waf-capture`         | request capture (§13) | `waf-core` |
| `waf-enterprise`      | the data-plane binary wiring all of the above | all of the above |
| `waf-controlplane`    | dashboard/API/alerting/SIEM (§7, §9) | core telemetry contract + Postgres |
| `waf-governance`      | RBAC/SSO/signed audit (§8) | used by `waf-controlplane` |
| `waf-node-agent`      | per-node ruleset agent (§7) | `waf-controlplane` API |
| `waf-operator`        | Kubernetes operator (§12) | — |

---

## 3. Distributed multi-node state (Redis `StateStore`) — `BOUNDARY.md` §2.1

> **STATUS: §3 FULLY IMPLEMENTED (2026-06-30).** Distributed rate limiting (`waf-state-redis`,
> proven with 2 nodes on the wire) **+** cluster-wide IP reputation (`waf-threatintel` +
> `waf-state-redis`). The **§6 feed** that *populates* reputation in Redis (a write capability,
> deliberately separate) is IMPLEMENTED too (2026-07-02) — see §6.

The core `StateStore` seam (`waf-core::state`) has **a single atomic operation**:

```rust
pub trait StateStore: Send + Sync {
    fn try_acquire(&self, key: &str, cost: f64, params: BucketParams) -> Acquired;
}
```

### Cornerstone invariant: refill-then-consume atomicity
The contract is **not** get/update: refill-then-consume must be **indivisible** across nodes,
otherwise two nodes read the same bucket level and both allow → **cluster-wide over-allow /
TOCTOU**. The core's in-memory store guarantees it under a lock; **Redis guarantees it with a
server-side script** (Lua / `EVALSHA`) that runs refill + consume + writeback in **one** atomic
round trip.

- **Distributed token bucket**: key = `ctx.client_ip` (derived by the core's trusted-proxy
  resolver), value = `{tokens, last_refill_ts}`. The **clock is Redis's** (`TIME`), so refill
  does not depend on clock skew between WAF nodes. The **memory cap** is the Redis TTL (idle keys
  expire) → out of the ABI, as with the in-memory store.
- **Degradation (fail-open vs fail-closed)**: Redis unreachable is a critical operational
  scenario. `RedisStore` exposes a policy `[state.redis].on_backend_error`:
  - `local_fallback` (recommended default) → falls back to the node's **local in-memory** token
    bucket (per-node, not cluster-wide, rate limiting) + `warn!` + the
    `waf_state_backend_errors_total` metric. Consistent with the core's *additive control*
    philosophy: a failure of the state infrastructure must not zero out throttling.
  - `fail_closed` → `Reject{503}` (for deployments where cluster-wide exactness is a compliance
    requirement).
- **Not reset by a reload** (inherits core §9): the buckets live in Redis, beyond the node's
  process lifetime → a reload/restart of a node does not reset the throttle.

### Cluster-wide IP reputation (component-only capability — NOT on the core trait)

> **Design correction (2026-06-30).** An earlier draft proposed a `reputation()` method
> **defaulted on the core `StateStore`**. That is wrong and was rejected: the core datapath
> consumes `try_acquire` (rate limiting) and **never calls** `reputation()`. A method the core
> does not invoke **does not belong in the core ABI** — it would be boundary contamination
> disguised as "additive", at the cost of a core release and a method frozen forever, for **zero
> benefit**: since the component builds the store anyway and injects it into the module, the
> module already holds the component type → a method on the core trait adds no capability.

**IMPLEMENTED (`waf-threatintel` + `waf-state-redis`).** Reputation lives **entirely in the
components**, using only the existing core seams (module injection + `.state_store()`) — **no
change to the core**:

```rust
// component crate (e.g. waf-state-redis): trait + data, NOT in waf-core
pub trait ReputationStore: Send + Sync {
    fn reputation(&self, ip: IpAddr) -> Reputation;   // IpAddr, not &str (canonical key in ONE place)
}
pub enum Reputation { Unknown, Suspicious, Malicious }
```

- **One `RedisStore`, two capabilities**: `RedisStore` implements **both** `StateStore`
  (`try_acquire`) **and** `ReputationStore` (`reputation`), sharing the **same pool** (a keyspace
  separate from the buckets, populated by the §6 feed). `Arc<RedisStore>` coerces to both traits.
  The lookup is read-only → **no atomicity/Lua** (it is not refill-then-consume).
- **Canonical key in ONE place**: `IpAddr::to_string()` is already the canonical RFC 5952 form
  (compressed IPv6, no brackets/zone id). A single helper `rep_key(ip)` serves both lookup and
  population → no mismatch between IP forms.
- **fail → `Unknown`** (fail to no opinion): Redis down ⇒ `reputation()` returns `Unknown` and
  the pipeline **inspects anyway**. A feed being down must neither block nor unblock. It is the
  analogue of the store's `local_fallback`, for a capability that is additive by nature.
- **Consumption**: a `WafModule` (`waf-threatintel`) in `Phase::Connection` reads
  `ctx.client_ip` → `reputation(ip)` → `Decision::Scores` with a **severity** (Malicious/Suspicious
  → severity, `Unknown` → `Allow`); the pipeline maps severity → points (§4: no hardcoded
  scores). It contributes to the **same** cumulative anomaly score as the core, with no new
  decision logic.
- **No double counting** (design note for §6): if the feed ever also drives signature modules,
  the **same IP must not contribute twice** to the cumulative score → a dedicated `rule_id`
  namespace + dedup. Not an issue for the MVP (reputation module only), but a constraint to keep
  as §6 grows.
- **Population**: in production = the **§6 feed** (`ReputationWriter::apply_snapshot`,
  IMPLEMENTED — see §6). The crate does NOT expose a product-level `set_reputation` (the feed owns
  the writes); tests seed raw `rep:<ip>` keys via `redis-cli` using the documented key format.

---

## 4. Additional detection modules (`WafModule`) — `BOUNDARY.md` §2.4

> **Hard boundary**: only **curated** signatures and modules that consume component
> state/intelligence live here — NEVER move baseline capability out of the core.

> **Reload (applies to every module in this section).** `waf-enterprise` builds all injected
> modules inside one core `.module_factory(..)` closure, which the core runs at bind **and on
> every reload**: the modules survive a SIGHUP and are re-`init`'d, so a changed GraphQL SDL, gRPC
> descriptor, OpenAPI spec or plugin is picked up by a reload. The factory is fallible as a unit:
> if any module fails to rebuild (an invalid schema, a plugin that no longer verifies), the reload
> is aborted and the last-good modules stay active.

- **Curated modules** (`waf-schema-enforcement`): high-curation rules packaged as additional
  `WafModule`s, injected **after** the built-ins. Same `inspect -> Decision` contract, same scoring
  as the core: **no hardcoded scores**, every rule only declares a severity.
  - **Client integrity / bot detection** (`bot.rs`) — **IMPLEMENTED (2026-07-03)**: **native
    cross-header** heuristics that a regex cannot express — deliberately **outside** the core
    `scanner` module (UA-tool matching = baseline) and outside `waf-crs-curated` (signature
    content). v1 = **browser impersonation (S1)**: a UA claiming a **modern** browser (Chromium/
    Firefox with a 3-digit major; Safari excluded — historically inconsistent Sec-Fetch) **without
    ANY `sec-fetch-*` header** → a bot posing as a browser (`curl`/`requests` send no Fetch
    Metadata; a non-browser client does not claim to be a browser → no trigger). `Phase::Headers`,
    `structural()=true`, additive `Decision::Scores` (`bot-browser-impersonation`, tunable
    `Critical`). Config `[enterprise.bot_detection]` (default off, no files/Redis, infallible
    construction). FP source = old/edge browsers or proxies that strip headers → governed by the
    severity. `rule_id` namespace `bot-*` (structural registry).
  - Declared **follow-ons**: **behavioral scanner detection** (per-IP counters in the §3 store),
    **TLS/JA fingerprinting** (ClientHello), corroborating signals (`sec-ch-ua`/`accept-language`),
    header order/casing.
- **GraphQL schema enforcement** (`waf-schema-enforcement`) — **IMPLEMENTED (2026-07-03)**: validates
  every GraphQL operation against the app's **real schema** (`.graphql` SDL) — this is **schema
  management = governance** → a component. A structural module (`Phase::Body`,
  `structural() = true`) that also runs on fast-path skips, like the core's structural caps.
  - **Validator = `apollo-compiler`** (the Apollo Router engine): zero gap — a hand-rolled
    validator would be false security for a security control. **Bounded parser DoS**: the core's
    Phase-11 structural caps (depth/size/batch → `Reject{400}`) run FIRST, so the validator only
    sees already-bounded operations.
  - **Extraction mirrors the core GraphQL module**: `application/graphql` raw body by
    Content-Type (any path), JSON `query` leaf + batch `<i>.query` and GET `?query=` **only on the
    configured `paths`**; it reuses `waf_normalizer::graphql::unwrap_query_envelope` so it never
    diverges from the core.
  - **Contribution = additive `Decision::Scores`** (never a hard `Reject`): two `rule_id`s with
    distinct severities — `schema-graphql-parse-error` (non-GraphQL body, lower) vs
    `schema-graphql-unknown-field` (valid query outside the schema, `Critical`). Dedup per kind (a
    batch of N violations = one signal). Introspection is **not** flagged here (the core module's
    job). `rule_id` namespace `schema-*` reserved and structurally enforced (`rules` registry),
    disjoint from the core ids (no double counting).
  - **FP boundary**: the only real FP source is **schema drift** (the app updated before the WAF's
    SDL copy) — governed by the configurable severity, not by loosening validation (a conforming
    client never sends out-of-schema queries; the real backend rejects them anyway).
  - **Config** `[enterprise.schema_enforcement]` (default off; `schema_path` required when enabled
    → **boot-fatal** if missing/invalid = fail-closed on the config, never on traffic). No Redis.
- **gRPC schema enforcement** (`waf-schema-enforcement`, same crate) — **IMPLEMENTED (2026-07-03)**:
  validates every **unary** gRPC message against the app's **real descriptor**
  (`FileDescriptorSet` `.bin` from `protoc`/`buf`). The `:path` (`/pkg.Service/Method`) selects the
  input message type; the message is decoded via **`prost-reflect`** (`DynamicMessage`). A
  structural module (`Phase::Body`, `structural()`), recognized via
  `Content-Type: application/grpc*` (no `paths` list — in gRPC the path IS the method).
  - **Three additive `Decision::Scores` signals** under `schema-grpc-*`: `unknown-method` (`:path`
    not in the descriptor) → `Critical`; `decode-error` (bytes that do not decode) → `Warning`;
    `unknown-field` (a top-level field outside the descriptor) → **opt-in
    `flag_unknown_fields`, default off**. Dedup per kind across the batch of frames.
  - **Differences from GraphQL** (on record): (1) the core's `GrpcExtract` does not expose the raw
    bytes → the module **de-frames by itself** (`[flag:1][len:4][msg]`, mirroring the core framing)
    and **skips compressed frames** (opaque → never a decode-error FP); (2) protobuf **tolerates
    unknown fields by design** (forward compatibility) → unknown-field is opt-in so that a client
    using a newer `.proto` than the WAF's copy does not cause FPs. Unknown-field detection = manual
    tag walk, **v1 scope = top level** (nested = follow-on).
  - **Config** `[enterprise.grpc_schema_enforcement]` (default off; `descriptor_path` required when
    enabled → **boot-fatal** on a missing/invalid descriptor).
  - **Unary only** in v1 (streaming, grpc-web, response validation, `.proto` input via protox =
    follow-ons).
- **OpenAPI positive security** (`waf-schema-enforcement`, `api_schema.rs`) — **IMPLEMENTED
  (2026-07-15)**: validates every REST/JSON request under a guarded prefix against the app's **real
  OpenAPI spec** (JSON file; v1 JSON-only) — this is **contract management = positive security**,
  not baseline detection. `Phase::Body`, `structural()`, additive `Decision::Scores`, zero core
  changes. `rule_id` namespace `schema-api-*` (structural registry).
  - **Extraction mirrors the core**: routing/gating on `ctx.normalized.path` (decoded +
    traversal-resolved → **evasion-resistant**), query/headers from `normalized` (lowercased),
    the JSON body from the raw `ctx.body`.
  - **Path router** (static > templated `/users/{id}`, most specific first) →
    `unknown-route`/`method-not-allowed` (Critical, `unknown_route_severity`); a known operation →
    parameter validation (path/query/header with string→scalar coercion) + `requestBody` via
    **`jsonschema`** (a mature crate, no hand-roll) → `unknown-param`/`missing-required`/
    `type-violation`/`unknown-property`/`content-type`/`body-parse-error` (Warning,
    `violation_severity`); dedup per kind.
  - **Boundary**: value-level injection (SQLi/XSS in a parameter's *value*) stays in the core's
    §6 channel; the core's structural DoS/body caps run FIRST. **Libraries** (A0): `oas3` (parses
    3.0 + 3.1), `jsonschema` with `default-features=false` (NO HTTP retriever — a WAF never fetches
    remote schemas); **3.0 → JSON Schema normalization at load** (3.0's `nullable` would otherwise
    be a false positive). `from_config`/`CompiledSpec::compile` are **boot-fatal** on a
    missing/invalid/non-compilable spec; per-operation precompilation. Config
    `[enterprise.api_schema]` (default off).
  - **Naturally monitor-first** (additive → it does not block on its own below the threshold;
    avoids the FP wall of ModSecurity's positive model). Follow-ons: behavioral BOLA/BFLA,
    response-side sensitive data, pure-Rust YAML, spec delivery via §7.
- **IP-reputation module** (consumes §3): `Phase::Connection`, reads the `ReputationStore`.

### Signed WASM plugins (`BOUNDARY.md` §1.7, §2.4)
The Proxy-Wasm **runtime** (`waf-wasm`, `wasmi`) is **core** and already loads **unsigned**
`.wasm` files from `[modules.wasm]` (skip on error). The component (`waf-wasm-signing`) adds the
**trust gate** — **IMPLEMENTED (2026-07-03)**:
- **Signing**: `verify_signature` checks a **detached minisign (ed25519) signature** of the
  `.wasm` against the configured `trusted_keys`; `load_verified_plugin` verifies and ONLY if the
  signature is valid delegates to `WasmModule::from_bytes` (core API, **zero core changes**) — the
  same buffer is verified and loaded (no TOCTOU).
- **Fail-closed posture (a deliberate divergence from the core)**: a signed plugin that does
  **not** verify (signature missing/invalid/untrusted key) is **boot-fatal**, never skipped.
  Reason: on the core path a missing plugin degrades coverage; here a signature that does not
  verify is **indistinguishable from tampering** → it is refused.
- **Config** `[enterprise.wasm]` (default off): `trusted_keys` +
  `plugins[{wasm_path, sig_path, config?}]` + section-global runtime limits. **`exclusive = true`**
  = refuse at boot a config whose core `[modules.wasm]` is populated (enforces the lockdown:
  without the flag, an unsigned `.wasm` in the core block would bypass the gate — a declared v1
  limit).
- A full **plugin registry** (distribution/versioning/updates, PKI/cert chain + revocation,
  cosign/OCI) = **follow-on**.

---

## 5. Certificate management at scale (`TlsCertSource`) — `BOUNDARY.md` §3.2

The core ships **only** `FileCertSource` (PEM, cert from file) behind the
`waf-proxy::tls::TlsCertSource` seam. The component provides implementations **of the same
trait** (zero fork).

**IMPLEMENTED (`waf-tls-managed`, core 0.2).** The trait gained two **additive, defaulted**
methods (`BOUNDARY.md` §5): `resolver() -> Option<Arc<dyn ResolvesServerCert>>` and
`client_verifier() -> Option<Arc<dyn ClientCertVerifier>>` (both default `None` → the core's
single-cert path via `load()` is unchanged). `build_server_config` branches: resolver `Some` ⇒
`with_cert_resolver` (and does not call `load()`); verifier `Some` ⇒ `with_client_cert_verifier`.

- **ACME (TLS-ALPN-01, HITLESS)** via `resolver()`: `ManagedTlsCertSource` exposes
  `rustls-acme`'s `ResolvesServerCert`; issuance + **background renewal** rotate the live cert
  **without rebuilding the acceptor**. The core adds `acme-tls/1` to the ALPN list when a resolver
  is present, so the challenge negotiates on the same `:443`.
- **ACME DNS-01** (wildcards, or a CA that cannot reach `:443`) via `instant-acme`, with
  Cloudflare and Route53 providers.
- **mTLS** via `client_verifier()`: a `WebPkiClientVerifier` from a configured CA bundle
  (`[tls.mtls].ca_path`). Roots are loaded at boot (rotation = restart).
- **Multi-node certificates**: a `SharedCertStore` on the shared Redis (single-writer lock, the
  private key encrypted at rest with AES-256-GCM, `WAF_CERT_STORE_KEY`), DNS-01 only, opt-in via
  `[tls.acme].cluster`: one node issues and renews, every node serves the same certificate.

Config: `[tls.acme]` / `[tls.mtls]` are re-parsed by the component binary (the core `Config`
ignores them). Constraints inherited from the core (§9 "TLS termination"): `[tls].enabled`/`alpn`
still come from config (the **source only governs where the cert comes from**); **no silent
downgrade** (fail-closed); a per-connection handshake error stays non-fatal.

> **Rotation vs acceptor immutability (RESOLVED).** The core's acceptor stays immutable after
> bind, and rotation does NOT violate that: `resolver()` is a `ResolvesServerCert` consulted
> **per handshake**, so the cert rotates inside the source without touching the acceptor or going
> through a config reload. The "TLS only when enabled" contract is unchanged.

---

## 6. Threat intelligence and curated content — `BOUNDARY.md` §2.4

- **Reputation feed** (`waf-threatintel`) — **IMPLEMENTED (2026-07-02)**: the *writer* that
  populates the `rep:<ip>` keyspace read by the reputation module (§3). Symmetric with the read
  side: a write seam `ReputationWriter::apply_snapshot` on `RedisStore` (same `rep_key` + value
  encoding in ONE place — read and write cannot diverge), sources behind the `ReputationFeed`
  trait (v1: `FileFeed` + `HttpListFeed`, one IP per line, **per-source verdict**; commercial
  threat-intel subscription APIs = follow-on behind the same trait), and a background driver
  `start_reputation_feed`.
  - **Single writer** (`DistributedLock`, key `feed_lock:` on the same pool): only ONE node per
    cycle fetches and writes → N nodes do not repeat the same fetch (subscriptions may be
    metered). Per-cycle lock, no heartbeat; if the leader dies, another node takes over on the next
    cycle.
  - **TTL-based snapshot** (no atomic swap): every `rep:<ip>` is written with `entry_ttl` (default
    3× the refresh interval). A de-listed IP ages out on its own; a feed that is down lets
    everything expire → `Unknown` (fail to no opinion, consistent with the read side). **Exact IPs
    only** in v1 (the read is `GET rep:<ip>`; CIDRs are skipped with a warning, follow-on).
  - Config `[enterprise.reputation.feed]` (default off; requires `redis_url`). A node can be a
    **pure feed writer** (populating for the others) even without the local reputation module.
  - Refresh/hot update is built into the loop (periodic re-fetch); no SIGHUP needed.
- **Curated CRS/ModSecurity rules** (`waf-crs-curated`) — **IMPLEMENTED (2026-07-02)**: the
  **`seclang` parser/engine** is core (`BOUNDARY.md` §1.7, B2); only the **curated content**
  lives here (maintained and tuned `SecRule` files). **It counts towards the same cumulative
  anomaly score** → with curated CRS enabled, threshold tuning is the operator's call (double
  counting with the native modules accepted, B2 guardrail #4).
  - **Additive content, not baseline**: high-curation CVE/app/evasion signatures. **28 rules**
    (27 in v1, plus id 9000004 for Log4Shell lookup obfuscation — `${${lower:j}ndi:…}`,
    `${::-j}`, `${env:X:-j}` — added after pentest #2, finding E-1): (a) generic categories (cloud-metadata SSRF, PHP-wrapper LFI, webshells, `.git`/`.env`
    exposure, dangerous HTTP methods, deserialization markers, recon UAs); (b) a **named-CVE pack**
    from CISA KEV (`rules/cve.conf`, ids 9100000+): Joomla JCE, Mirasvit/Magento object injection,
    UniFi/Cisco SD-WAN/FortiWeb/TeamCity/PAN-OS traversal, Next.js middleware bypass, SharePoint
    ToolShell, PHP-CGI argument injection, MOVEit, GoAnywhere, Kentico, PaperCut, Oracle EBS,
    Log4Shell/Spring4Shell. It does **not** re-implement baseline SQLi/XSS/PT/RCE/LFI-RFI (they stay
    in the core's native modules). Only constructs from the engine's **v1 subset** (`@rx`/`@pm`;
    `@detectSQLi`/`@detectXSS` stay out → SQLi/XSS go to the native modules). FP-prone CVEs (Serv-U
    deflate, generic `/_layouts/`) are **explicitly discarded** with a note in the `.conf`.
  - **Packaging = embed + module injection**: the crate embeds the `.conf` files
    (`include_str!`) and exposes `curated_source()` + `EXPECTED_LOADED`; the component binary builds
    `CrsModule::from_source` and injects it, gated by `[enterprise.crs_curated]` (default off, no
    Redis). The core's `[modules.crs].files` channel stays for the OPERATOR's own rules.
  - **Compatibility gate** (the engineering value of this crate): the crate's test loads the
    content through the core engine and asserts `loaded_count() == EXPECTED_LOADED` **exactly** +
    `skipped()` **empty** + a per-rule bite test → the content is *guaranteed compatible* with the
    shipped subset, with no silent loss (the lesson of the B2 setvar bug).

---

## 7. Control plane — `BOUNDARY.md` §2.2

> **v1 IMPLEMENTED (2026-07-05)** — crate `waf-controlplane`. **Read-only observability**:
> ingest + retention + drill-down + dashboard API. Rule management (write path → SIGHUP push) was
> **deferred until after §8** (RBAC/audit). An **axum** + **Postgres** service, **DECOUPLED from
> `waf-core`** (its own DTOs over the decision-log JSON contract → it does not link the datapath).
> v1 auth = a static bearer token (RBAC/SSO = §8). Runbook `scripts/controlplane/`. End-to-end bite
> test with a real WAF node.
>
> **v2 ALERTING IMPLEMENTED (2026-07-05)** — rules in config (`[[controlplane.alerts]]`) evaluated
> by a background **evaluator**: when the count (per `client_ip`/`rule_id` group) of denied
> `decision_events` in a window exceeds the threshold (outside the cooldown) → an `alerts` row + a
> generic **webhook** (POST JSON) + `GET /api/alerts`. Fired-record model + DB-based cooldown.
> Zero datapath (it only reads the control plane's store). Proven end to end with a webhook
> receiver. Migration `0003_alerts`.
>
> **WEB DASHBOARD IMPLEMENTED (2026-07-06)** — a **React + Vite + TypeScript** SPA (+ **Recharts**)
> in `crates/waf-controlplane/ui/`, consuming the read API (same origin, **no CORS**). Views
> **Overview** (volume cards + bar chart, events-over-time area chart with a range selector,
> per-node p50/95/99 latency, cluster status) · **Events** (filters → table → **drill-down**
> `/events/:id` with the per-module breakdown) · **Alerts** (fired alerts + rules). Supporting
> endpoints: `GET /api/decisions/series` (bucket whitelist {60,300,3600} + window capped at 7 days,
> aggregation in SQL) and `GET /api/version` (UI↔API drift check). **Two serving modes**:
> `[controlplane].ui_dir` = development override (`ServeDir`); a production **single binary** via
> `rust-embed` behind the **`embed-ui`** feature (`ui/dist` embedded in the binary; a plain
> `cargo build` does NOT need the frontend). UI assets are **public**, only `/api` sits behind auth.
> v1 kept the token in `sessionStorage` (a declared XSS trade-off), since replaced by HttpOnly
> session cookies with governance (§8). Supply chain: committed lockfile + `npm audit` in CI +
> minimal direct dependencies (no UI kit). Zero datapath (the UI is just another API consumer).
> **Playwright E2E (2026-07-07)**: a committed suite (`ui/tests/e2e/`) that drives the SPA in a real
> browser against the **real backend** (two `embed-ui` binaries, token and session mode, +
> Postgres); it covers both auth modes, RBAC, every view and the main flows (publish a rule,
> compliance generate/verify, audit verify). `npm run e2e`, runbook §M; runs in CI
> (`.github/workflows/e2e.yml`).
>
> **WRITE PATH (RULE MANAGEMENT v3) IMPLEMENTED (2026-07-07)** — the last piece of §7, unblocked by
> §8. The control plane versions **ONE managed SecRule `.conf` file** and **pushes** it to the
> nodes, which hot-reload it. **Zero core changes** (verified): the WAF loads the file via
> `[modules.crs].files` and on **SIGHUP** `reload_from` reloads it with **validate-then-swap**
> (invalid rules → keep last-good). **Backend** (migration `0004_rules`): an immutable
> `rule_versions` table + a `rule_current` singleton (rollback = re-point) + `node_rule_status`
> (convergence). API: **manage** (`ManageRules`, operator+, audited as `rule.publish`/
> `rule.rollback`) `POST/GET /api/rules/versions` · `GET /versions/{id}` · `POST /rollback`;
> **agent** (`ReadObservability`) `GET /api/rules/current` · `POST /api/rules/status` ·
> `GET /api/rules/nodes`. The `MaybePrincipal` extractor serves the same routes with governance ON
> (RBAC) and OFF (static bearer = `api-token`). **Per-node agent** = the `waf-node-agent` crate (a
> binary that links the core `waf-detection` **only to pre-validate**, NOT on the datapath): it
> polls `current` → **pre-validates** (seclang parser) → if valid: **atomic write** (temp + rename) +
> `reload_command` (SIGHUP by default, configurable → portable) + reports `applied`; if invalid:
> reports `rejected`, the **WAF is untouched**. **Two fail-safe levels** (the agent pre-validates +
> the WAF's validate-then-swap). **UI**: a **Rules** view (publish editor · versions with
> current/rollback badges · node convergence), navigation role-gated to operator+. Proven end to
> end (REAL proxy: publish → the agent validates and writes → in-process `reload_from` = SIGHUP →
> the request goes 200 → **403** + convergence; reject path: an invalid v2 leaves the WAF intact) +
> a browser smoke test. Runbook §I. **Follow-ons**: server-side dry run, canary/staged rollout,
> version diff, multiple named rulesets, ruleset signing, live convergence over WebSocket, reload on
> Windows.

A service separate from the datapath (never on the data port). It consumes the core's **baseline
telemetry** (structured JSON logging + Prometheus metrics) and persists it long term.

**Isolation / performance posture (the control plane does NOT tax the datapath).** It is off the
request path by construction: the core `waf` binary does not even depend on `waf-controlplane`.
Two flows, both at ~zero cost on the hot path:
- **Metrics = PULL**: a scraper does `GET /metrics` on the WAF's **dedicated/loopback** listener
  (every 15 s by default). `render()` only reads atomic counters (`relaxed`, no lock shared with
  `handle()`). The scrape runs on a background task and steals no serving time.
- **Decision log = out-of-process PUSH**: the WAF writes its JSON logs as it always did; an
  **external log shipper** forwards them to `POST /ingest/events`. The WAF does not know about the
  control plane. Correlating `→ request` + `request blocked` and parsing the NDJSON happen IN the
  control plane.
- **The only WAF-side change (core 0.4)**: `score_contributions` is serialized in the decision
  log **only for a denied request** (Block/Reject) → benign traffic pays **zero**.
By contrast, the Redis `StateStore` (§3) is on the datapath (per request); the control plane is
purely observational, downstream. Empirical check in runbook §D (benchmark with/without scraping).

**v1 architecture (phases):** Phase 0 enriched the core decision log in 0.4
(`score_contributions`). Phase 1 Postgres store (`decision_events` + `metric_rollups` +
`latency_buckets`). Phase 2 ingest (scraper `/metrics` → rollups; `POST /ingest/events` NDJSON →
parse + correlation → `decision_events`). Phase 3 read API (`/api/cluster/status` ·
`/decisions/volume` · `/latency` [p50/95/99] · `/events` search · `/events/{request_id}`
drill-down; bearer middleware). Phase 4 end-to-end bite test (real WAF node → drill-down) +
runbook. **v2 = alerting** (config rules + evaluator + webhook + `GET /api/alerts`, migration
`0003_alerts`; **DONE**). **UI = web dashboard DONE** (React/Vite SPA + `ui_dir`/`embed-ui`
serving). **Rule-management write path (v3) = DONE** (crate `waf-node-agent`, migration
`0004_rules`, Rules view; see the callout above). **Follow-ons**: metric/latency-based alerting
+ firing/resolved state, native Slack/email connectors, OpenAPI for the control-plane API,
server-side dry run + canary rollout for the write path, external Prometheus/Grafana integration.

### 7.1 Two data flows (metrics are NOT the only source)

The control plane has **two separate inputs**, with two models and two stores — it does NOT derive
everything from metrics:

| Flow | Model | Source | Feeds |
|---|---|---|---|
| **Metrics** | **PULL** — scraper `GET /metrics` | the core's Prometheus endpoint (B1) | aggregate dashboards: volume per decision, latencies (`metric_rollups`, `latency_buckets`) |
| **Decision log** | **PUSH** — `POST /ingest/events` | the WAF's JSON file/stdout, via an **external log shipper** | **per-request drill-down** (`decision_events`) |

- The **drill-down does NOT come from `/metrics`**: metrics are aggregates and, because of the
  **cardinality constraint** (never `path`/`ip`/`request_id` as labels), carry no per-request
  detail. The detail comes from the **JSON decision log**.
- The control plane **does not read the log file**: a **log shipper** (Vector / Fluent Bit / the
  reference script `forward_logs.sh`) does `tail -F` and forwards every NDJSON line to
  `POST /ingest/events`. The WAF stays unaware (out of process, zero datapath). `ingest.rs`
  correlates `→ request` + `request blocked` by `request_id` and writes `decision_events`.

```text
WAF ──writes──> node.jsonl ──tail -F──> [log shipper] ──POST /ingest/events?node=X──┐
WAF ──exposes─> /metrics ──────────────────────────────GET (scraper, 15s)──────────┤──> control plane ──> Postgres
```

### 7.2 One control plane for a multi-node WAF

It works because **both flows are per node** and every datum carries the node's identity (the
`node` column):

- **Metrics**: the config lists **every node** — `[[controlplane.nodes]]` with its `metrics_url`;
  the scraper cycles over them and stores rollups tagged with `node`. **Reset-aware totals**:
  `waf_requests_total` and the latency buckets are **Prometheus counters** (cumulative since the
  process started, **reset when the WAF restarts**). The scraper therefore keeps a persistent,
  reset-aware total in `metric_totals`/`latency_totals` (the delta since the last value, or the raw
  value when it detects a reset), so the Overview volumes **keep growing across restarts** instead
  of dropping to the last snapshot. The state lives in Postgres → it survives both a WAF restart
  (reset detection) and a control-plane restart (the state is re-read).
  `GET /api/decisions/volume` **sums the cumulative totals across nodes** per decision;
  `GET /api/cluster/status` lists them (last seen from `metric_totals`); `GET /api/latency` is per
  node (**lifetime** percentiles). The raw `metric_rollups`/`latency_buckets` stay as raw history.
- **Decision log**: every node has its own shipper doing `POST /ingest/events?node=<name>` →
  `decision_events.node` tells the origin apart (the **shipper** sets the identity, never the core
  → zero core changes). Search and drill-down cover the whole cluster.

```text
edge-1 ─/metrics─┐        edge-1 ─shipper─┐
edge-2 ─/metrics─┼─> [1 control plane] <─┼─ edge-2 ─shipper   →  1 Postgres (`node` column everywhere)
edge-3 ─/metrics─┘        edge-3 ─shipper─┘
```

**Deployment note**: the core's `/metrics` listener is **loopback by default** (an information
leak if public). For a control plane on another host to scrape it, the node must expose it on a
**private/management interface** reachable by the control plane (private network / tunnel), never
on the Internet. That is a network choice, not an architectural limit. **One shipper per node** (or
a central one reading every node's logs) provides the push flow.

- **Web dashboard**: cluster status, volume per decision (`allowed|blocked|rate_limited|
  bad_request|upstream_error|internal_error`), latencies (from the core's Prometheus histograms,
  quantiles computed at scrape time).
- **Blocked-request drill-down**: the verdict rebuilt from the `score_contributions`
  (module/rule_id/severity/points) logged by the core.
- **Rule management**: rule editing/versioning + a validated push to the nodes (it reuses the
  SIGHUP hot reload; the control plane is "the button", the validate-then-swap logic stays in the
  core).
- **Alerting**: thresholds on events.
- **Long-term retention** of metrics/telemetry (the core counters are exporter-neutral → the
  control plane is a second sink, not a rewrite).

> **Cardinality constraint** inherited from the core: NEVER labels from user input on
> `requests_total`. Per-rule/IP/path breakdowns = separate, capped metrics materialized in the
> control plane's store, not labels on the hot path.

### 7.3 API attack-surface inventory (discovery §4-B pt3) — **IMPLEMENTED (2026-07-15)**

The control plane builds an **API attack-surface inventory** from the enforcement decisions it
already persists (`inventory.rs`, `GET /api/inventory` + `/api/inventory/drift`, the "API Inventory"
UI view). **The data reality (decisive):** `decision_events` holds **only denied requests**
(blocked/rejected — benign traffic expires from the correlation buffer and is never stored) → this
is the **observed attack surface**, NOT an all-traffic inventory. **On-demand** aggregation over
`decision_events` (no dedicated table or aggregator): `GROUP BY (method, path)` with
hits/first/last, then in Rust **templating** (numeric/UUID/long-hex segments → `{}`, so `/users/5`
and `/users/6` collapse) and **classification** against the configured OpenAPI spec
(`[controlplane.api_inventory].spec_path`, optional, non-fatal):

- **`documented`** = declared path + method (a known endpoint that still drew blocks — contract
  violations or injection against known APIs),
- **`shadow`** = path/method NOT declared (an undocumented endpoint being hit — the strong
  discovery signal),
- **`unclassified`** = no spec configured.

**Boundary (`BOUNDARY.md` §2.2)**: read-only, off datapath, **core-free** — the control plane does
NOT depend on `waf-core` (it consumes the core's JSON contract), so the path→route matcher is a
**standalone re-implementation (`serde_json` only)** of the datapath `Router` (§4-B A2), not an
import of `waf-schema-enforcement`. **Zombie** (declared but unused) endpoints and all-traffic
discovery = **follow-ons** (they would need an ingest of all traffic, not only denied requests).
A learning mode that drafts an OpenAPI spec from traffic = follow-on.

---

## 8. Governance and compliance — `BOUNDARY.md` §2.3

> **v1 IMPLEMENTED (2026-07-06)** — crate `waf-governance`, a **library** of the control plane
> (zero core, zero datapath; it works on the same Postgres, with its own `apply_schema`). **RBAC**
> with 3 fixed roles (`Viewer` read-only / `Operator` [reserved write tier] / `Admin`) + a pure
> `Permission` matrix. **Local auth**: accounts with **argon2id** passwords + **server-side
> sessions** (an **HttpOnly + SameSite=Strict + Secure** cookie). With governance ON, `/api/*`
> accepts **a session (a human, RBAC by role) OR the static bearer** (a machine/admin principal,
> `actor="api-token"`); `/ingest` stays bearer-only; governance OFF (the default) = the previous
> behavior (bearer only, backward compatible). **Signed audit log**: a tamper-evident
> **SHA-256 + Ed25519** chain (via `ring`) — every action (login/logout, user create/disable/role
> change, bootstrap) is a record that chains the previous record's hash + a signature;
> `GET /api/audit` + `GET /api/audit/verify` (re-checks continuity + hashes + signatures).
> Endpoints `POST /api/login` · `/logout` · `GET /api/me` · `/api/users` (admin CRUD) ·
> `/api/audit` (+ verify). Bootstrap admin from config + env; secrets (audit key, bootstrap
> password) from env. Migration via `apply_schema` (tables `gov_users`/`gov_sessions`/
> `gov_audit_log`). Proven end to end over HTTP (login → RBAC 403/200 → audit verify → tamper →
> fail).
>
> **v2 IMPLEMENTED (2026-07-06)** — **OIDC SSO** + **auth hardening**. *OIDC* (crate
> `openidconnect`, Authorization Code + **PKCE**): `[controlplane.governance.oidc]` (issuer/discovery
> + client + redirect + `role_claim`/`role_map`/`default_role`; secret from env).
> `GET /api/auth/oidc/login` → 302 to the IdP (PKCE/nonce flow state in `gov_oidc_flows`) →
> `/api/auth/oidc/callback` verifies the id_token (**JWKS** signature + nonce + aud + exp), maps the
> roles claim → a role (highest privilege; unmapped → deny unless `default_role`), **provisions the
> federated user** (`auth_source=oidc`, no local password; it does NOT hijack a local account) and
> opens the session. Proven **live end to end** (real Keycloak + a headless browser: group
> `waf-admins` → `admin`). *Hardening*: **named, revocable, role-bound service tokens**
> (`gov_tokens`, only the hash stored, plaintext shown once; bearer resolution: named token → static
> admin) · **session management** (list/revoke own + admin revoke-all + auto-revocation on
> disable/password change) · **password** self-change (revokes the other sessions) + admin reset ·
> **login throttling** against brute force (in-memory per process → 429). Extended audit
> (login.sso, token.*, session.*, password.*). In-place, backward-compatible migration (ALTER +
> `gov_tokens`/`gov_oidc_flows`).
>
> **GOVERNANCE UI IMPLEMENTED (2026-07-06)** — the control-plane SPA (§7) now covers governance.
> Auth **auto-detection** via `GET /api/auth/config`: governance ON → user/password login (+ a
> **"Sign in with SSO"** button when OIDC is configured) on an **HttpOnly cookie** (no token in
> sessionStorage → **closes the XSS trade-off**); governance OFF → the existing token gate (backward
> compatible). Role-gated views: **Users** (admin: CRUD + role + disable + password reset),
> **Tokens** (admin: create [plaintext shown once] / revoke), **Audit** (admin: table + chain
> verify), **Account** (everyone: password change + own sessions). Proven **live in all 3 modes**
> (session via the embedded single binary, OIDC via Keycloak, token mode). CSRF = SameSite=Strict
> (an explicit token = follow-on). **Remaining follow-ons**: cluster-wide throttling, MFA, explicit
> CSRF token.
>
> **COMPLIANCE REPORTS IMPLEMENTED (2026-07-07)** — period-scoped, **signed** **SOC 2 / PCI**
> evidence, aggregated from what the system already holds (governance access + signed audit log +
> WAF telemetry). **Read-only, zero core / zero datapath**, **admin** only (`ViewAudit`), mounted
> **only with governance ON** (it reuses the audit signer). `GET /api/compliance/report?from=&to=`
> (default 90 days) → a bundle with **4 sections**, each annotated with the **SOC 2 / PCI controls**
> it supports: access control (users/roles/tokens/sessions · CC6 / PCI 7-8) · audit integrity
> (`verify_chain` over the WHOLE chain → `chain_ok`/`verified_through_seq` + the period's event
> timeline · CC7 / PCI 10) · WAF effectiveness (denied + top rules + nodes · PCI 6.4.2/11) · alerts
> (CC7.2 / PCI 10.6). The **bundle is signed**: `content_hash` = SHA-256 of the canonical body (via
> `serde_json::Value` → sorted keys = an order-independent signature that survives a JSON round
> trip), `signature` = Ed25519 (the audit key); `POST /api/compliance/verify` re-checks it.
> **CAVEAT**: denied counts are period-accurate (per-event rows), allowed/totals are cumulative
> (Prometheus counters, not per period). A **Compliance** UI view (date range → Generate →
> integrity banner + sections + control chips + signature + **Print**/Verify). Proven end to end
> (generate → verify ok → tamper → fail + RBAC viewer 403) + a browser smoke test. Runbook §K.
> **Follow-ons**: native PDF, an immutable report archive, a dedicated `auditor` role, separate
> per-framework reports, scheduled/emailed reports.
>
> **SAML — FROZEN DECISION (2026-07-07): not natively supported, covered via an IdP broker.**
> Modern SSO is **OIDC** (DONE in v2, live with Keycloak). **Native SAML is deliberately out of
> scope**: XML-DSig verification (**C14N** canonicalization + **XML Signature Wrapping**) is the bug
> class that has broken mature SAML libraries in *every* ecosystem for years; a hand-rolled
> validator would be **false security** — the same discipline as §4 (apollo-compiler), applied in
> reverse: there we picked the mature library because the control was critical; here a mature
> **pure-Rust** library does not exist, so we stay out of that territory. The one mature option
> (`samael` → `xmlsec`/`libxml2`, with a CVE history) would betray the pure-Rust/no-C posture
> **precisely in the trust crate**. Every relevant IdP (Okta, Entra ID, Ping, OneLogin, Keycloak,
> Google Workspace) speaks OIDC natively; the remaining "SAML only" case is covered by an **IdP
> broker** (Keycloak/Dex): the organization's SAML IdP is federated *behind* the broker and the
> control plane speaks **only OIDC** — the XML-DSig risk is handled by software whose job that is.
> Our cost: one **runbook page** (§J). **Native = demand-driven follow-on**: reconsidered ONLY on
> concrete demand that the broker path cannot serve, and ONLY via `samael` (**NEVER** a pure-Rust
> hand-roll).

- **RBAC**: roles/permissions on the control plane (read-only / operator / admin). **[DONE v1]**
- **SSO**: native OIDC · SAML via an IdP broker. **[OIDC DONE v2; native SAML out of scope by
  choice (2026-07-07) → Keycloak/Dex broker, runbook §J; native = demand-driven follow-on]**
- **Signed audit log**: every operator action (rule changes, user and token management, sessions,
  report generation, capture views) → a signed record (verifiable chain) for SOC 2 / PCI DSS.
  **[DONE v1: hash chain + Ed25519; rule publish/rollback are audited since the §7 write path]**
- **Automated compliance reports** + long-term retention. **[DONE 2026-07-07: a period-scoped
  SIGNED (Ed25519) SOC 2 / PCI bundle with audit integrity + access + WAF effectiveness,
  `GET /api/compliance/report` + a UI view; see the callout above. Long retention via
  `retention_days`. Follow-ons: PDF, archive]**

The component audit log is **distinct** from the core decision log: the core logs **verdicts**
(per request); the control plane logs **human/administrative actions**.

---

## 9. Integration — `BOUNDARY.md` §2.5

> **SIEM CONNECTORS IMPLEMENTED (2026-07-07)** — a background **forwarder** in the control plane
> **PUSHes** the stored events (denied WAF verdicts `decision_events` + the **signed audit log**
> `gov_audit_log` + alerts) to HTTP SIEM sinks, normalized into a **versioned, ECS-like NDJSON**
> event (`"version":1`, ECS names where obvious + a `waf.*` namespace). **Read-only, zero core /
> zero datapath** (it reads the stores; the WAF does not know about the SIEM). The value over the
> core's log shipping (§7) = **normalization + correlation + the signed audit stream +
> reliability**. **At-least-once**: a per-`(destination, stream)` cursor advances ONLY on a 2xx ack
> of the whole batch (failure → it does not advance and retransmits; the SIEM deduplicates on the
> stable `event.id` `waf-<stream>-<id>`). **Backpressure = Postgres** (bounded by
> `retention_days`, no in-memory queues); the **lag** (`head - cursor`) is the key operational
> signal, exposed by `GET /api/siem/status` + logs. **Formatter abstracted from day one**
> (`SiemFormatter`; v1 = `EcsNdjsonFormatter`) → CEF/LEEF/syslog + vendor adapters = future
> variants WITHOUT touching the forwarder. Config `[controlplane.siem]` (destinations {endpoint,
> auth_header [env `WAF_CP_SIEM_AUTH_<NAME>`], format, streams} + batch + flush), default OFF.
> Migration `0005_siem` (`siem_cursors`). Proven end to end (at-least-once: failure → cursor held →
> recovery → redelivery; 3 normalized streams + status API). Runbook §L. **Follow-ons**:
> CEF/LEEF/syslog + vendor adapters, a native control-plane `/metrics` (`siem_forwarder_lag`), TLS
> client certificates, a dead-letter queue, filters, OTLP, a SIEM UI.

- **SIEM connectors**: export of events (the core decision log + the component audit log) to
  Splunk/Elastic/QRadar/…, built on the core's structured logging as the source. **[DONE
  2026-07-07: PUSH forwarder → ECS-like NDJSON, at-least-once, 3 streams, `GET /api/siem/status`;
  see the callout above]**

---

## 10. Boundary and stability (operational summary)

| Capability | Core | Components (this document) |
|---|---|---|
| Rate limiting / state | in-memory token bucket | cluster-wide Redis `StateStore` + IP reputation |
| TLS | basic termination, cert from file | ACME / rotation / multi-node / mTLS |
| WASM | Proxy-Wasm runtime | signature verification |
| CRS/ModSecurity | `seclang` parser/engine | curated rule content |
| Detection (SQLi…XXE, GraphQL/gRPC) | **all of it** | schema / OpenAPI enforcement, bot detection |
| Telemetry | Prometheus export, JSON decision log | dashboard + retention + drill-down + SIEM |
| Governance | — | RBAC / SSO / signed audit / reports |

### Stability rules (normative, from `BOUNDARY.md` §5)
1. A core capability is **never** moved out to a component; moving a component capability into
   the core is allowed.
2. The three traits (`WafModule`, `StateStore`, `TlsCertSource`) are a frozen **public ABI**
   (SemVer). New cluster-wide capabilities = a **new method with a default impl** (additive).
3. `Config` is `#[non_exhaustive]`: new component sections (`[state.redis]`, `[controlplane]`,
   `[governance]`, …) are **additive and non-breaking** for the core.
4. Component crates depend on the core **only** through its public API and the core never depends
   on them (`BOUNDARY.md`, dependency rule): the boundary lives in the dependency graph, not only in
   the documentation.
5. Every new feature is labeled in `BOUNDARY.md` **before merge**.

---

## 11. Development conventions (delta from the core)

- Components depend on the core through **workspace path dependencies** and its public API —
  never on a fork or on its internals.
- Component tests do NOT re-test baseline detection (that belongs to the core / `waf-corpus`);
  they test **scale, atomicity, governance**: e.g. property tests on the atomicity of the Redis
  `try_acquire` (no over-allow under concurrency), bite tests on the store's failure mode, TLS
  rotation tests with no downgrade.
- **Update `BOUNDARY.md`** for every new feature (unambiguous label) and this file whenever a
  seam or an at-scale implementation changes.
- The **bite-test** discipline is inherited (core §13): a guard never seen failing is hope, not a
  guarantee — first and foremost for distributed atomicity.

---

## 12. Kubernetes-native deployment — `BOUNDARY.md` §2.5

A feature **entirely in the components, with zero datapath changes**: declarative packaging +
ecosystem integration, NOT a datapath rewrite. The unit is **WAF-per-workload** — a
`waf-enterprise` Deployment in front of **one** application Service (`[proxy].backend` = that
Service), scaled and configured per app. It is NOT a cluster-wide ingress controller: that would
require multi-backend routing in the core (a strategic follow-on), and until it exists **it is not
promised**.

### Components
- **Images** (`Dockerfile.*` + `scripts/images/`): multi-arch builds, SBOM + scan, OCI labels. CI
  only builds and verifies; it never pushes to a registry — publishing is a deliberate manual
  step (like `cargo publish`).
- **Data-plane chart** `charts/waf`: Deployment + optional agent sidecar
  (`shareProcessNamespace`, reload via `kill -HUP $(pidof waf-enterprise)` — under Kubernetes the
  WAF is NOT PID 1), a ConfigMap that renders `config.toml`, Service,
  PodMonitor/PrometheusRule/Grafana, NetworkPolicy, HPA/PDB, Certificate (cert-manager),
  securityContext non-root 10001 / read-only root filesystem.
- **Control-plane chart** `charts/waf-controlplane`: Deployment (auto-migrate, embed-ui) + Service
  + Ingress + Secret + optional bundled Postgres/Redis. Credentials left empty are generated on
  first install and reused on upgrade (no well-known defaults).
- **Operator** `crates/waf-operator` (kube-rs): a namespaced `WafProxy` CRD → reconciles ConfigMap
  + Deployment + Service with ownerRefs. Native declarative UX without routing in the core.
- **Log shipping**: a Vector DaemonSet (`deploy/log-shipper/`) reads the WAF pods' stdout and
  forwards the decision log to the control plane's `/ingest/events` — off process, zero datapath.

### Observability
The core's metrics ABI (`waf_up`, `waf_requests_total{decision}`, `waf_request_duration_seconds`)
→ PodMonitor/PrometheusRule + a Grafana dashboard. No high-cardinality labels (path/IP/rule).

### Graceful shutdown
The core exposes `Proxy::run_with_shutdown(signal)` (core 0.5.4, additive): on the signal the
listener stops accepting new connections and every in-flight connection finishes its current
exchange and closes. `waf-enterprise` wires it to `SIGTERM`, so a rolling update loses no in-flight
request; `terminationGracePeriodSeconds` bounds the total drain time, and a `preStop` sleep lets
the pod leave the Service endpoints first.

### Boundary
The datapath is only the `waf-enterprise` Deployment. Control plane, operator and log shipper are
**off the request path**: they observe or generate manifests, they do not inspect traffic.
End-to-end check on kind: `scripts/k8s/e2e-kind.sh` (SQLi → 403 → event in the control plane) and
CI `e2e-kind.yml`.

## 13. Request capture — `BOUNDARY.md` §2.5

A feature **entirely in the components, optional (default OFF), zero core changes**: it captures
the **complete** HTTP request (method/path/query/**headers/cookies/body**) of **blocked/rejected**
requests and shows it in the control plane's event drill-down. The ordinary decision log carries
only metadata (for privacy and weight); the body **never** travels in the logs/Vector, but on a
**dedicated side channel**.

### Zero-core seam (no change to `waf-core`/`waf-proxy`)
Three pieces in `crates/waf-capture`, gated by `[enterprise.capture] enabled=false`:
- **Capture module** (a `WafModule` injected via `module_factory`, `Phase::RequestLine` +
  `structural`): clones every request into a **bounded ring** (count + bytes + TTL); it is a **pure
  observer** → it always returns `Allow` and never touches the score. Allowed requests are evicted
  without being shipped.
- **CaptureLayer** (a `tracing::Layer` in the component binary's subscriber): intercepts the
  `request blocked`/`rejected` log lines, reads the `request_id`, takes the capture out of the ring
  and queues it. It is **armed lazily** (`OnceLock`): with capture OFF it costs one atomic load per
  event.
- **Shipper**: a bounded queue + best-effort retry → `POST /ingest/captures` (bearer).
  **Drop on overflow with a metric/log, NEVER backpressure on the datapath.**

### Privacy (raw by default + three mandatory defenses in v1)
The capture is **raw by default**. Since plaintext secrets could land in the control plane's
database, v1 requires all three of:
1. **Node-side per-field redaction** (`[enterprise.capture.redaction]`): `headers` +
   `body_fields` lists → `***REDACTED***`, applied **on the node** (the redacted value never leaves
   the node; only the redacted **names** are reported, for the UI banner). The body is redacted
   **structurally** (recursive JSON + form-urlencoded).
2. **Short, independent retention** in the control plane (`[controlplane.captures]
   retention_hours`, default 168 = 7 days): an hourly reaper **hard-deletes** captures, more
   aggressively than the telemetry's `retention_days`.
3. **RBAC `ViewCaptures` (operator+) + audited viewing**: the drill-down
   `GET /api/events/{id}/capture` is gated and every view writes a signed audit row
   (`capture.view`) — access is attributable.

### Control plane (zero core, extends the read model)
Migration `0007_captures` (`request_captures`: `request_id` PK, headers/cookies/redacted as
**JSONB**, body as **BYTEA**, a `body_truncated` flag); `POST /ingest/captures` (bearer, idempotent
`ON CONFLICT`); `GET /api/events/{id}/capture` (RBAC + audit); the `run_retention` reaper. UI: a
**"Captured request"** panel in the event detail, **reveal on click** (access is deliberate and
audited), with a redaction/truncation banner, headers/cookies tables and the body as
**Text/Hex** + copy/download.

### Deploy
Chart `charts/waf`: `capture.enabled` + `capture.redaction.{headers,bodyFields}` +
`capture.tokenSecret` (→ env `WAF_CAPTURE_TOKEN`, never in the ConfigMap). Chart
`charts/waf-controlplane`: `config.captures.retentionHours`. End to end on kind:
`scripts/k8s/e2e-kind.sh` extends SQLi → 403 → event → **full capture** on
`/api/events/{id}/capture`.

### Honest boundary / v1 scope
**Connection-phase** rejects (rate limiting) and 400s from parser limits happen **before**
inspection → the capture module never sees them → they stay **metadata only** (documented).
Datapath cost when ON = one `Bytes` + headers clone per request into the bounded ring (negligible).
The `CaptureLayer` is coupled to the `request blocked/rejected` log strings (already a contract of
the control plane). Follow-ons: response-body capture, connection phase, per-node
sampling/quotas, encryption at rest, signed forensic export.
