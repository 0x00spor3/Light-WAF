# ARCHITECTURE-en.md — Light WAF (Layer 7)

> Project reference document. Re-read it at the start of every work session
> to keep architectural consistency.

---

## 1. Project goals

Build a **Web Application Firewall (WAF)** operating at **Layer 7** of the OSI stack with
the following non-functional requirements:

- **Light**: small memory footprint, few dependencies.
- **Fast**: low added per-request latency (target < 1 ms p99 on the common path).
- **Modular**: every detection capability is a loadable/disableable plugin.
- **Observable**: structured logging, metrics, audit of the rules that fired.
- **Secure by design**: explicit fail-open / fail-closed handling.

### Non-goals (for now)
- **Certificate management at scale** (ACME/Let's Encrypt, rotation, multi-node certs, mTLS with
  managed PKI) → enterprise (`BOUNDARY.md` §3.2). NB: **basic, cert-from-file TLS termination** IS
  implemented and is **core** (Phase 12, §11) — see §9 "TLS termination".
- L3/L4 protections (volumetric DDoS → handed to network infrastructure).
- Distributed multi-node WAF with shared state (future phase).

---

## 2. Technology choices

| Area              | Recommended choice                     | Notes |
|-------------------|----------------------------------------|------|
| Language          | **Rust**                               | Memory safety + throughput |
| Deployment model  | Dedicated reverse proxy                | Isolation, simplicity |
| Regex engine      | the **`regex`** crate (finite automata)| Guaranteed linear time, no catastrophic backtracking (same guarantee as RE2); multi-pattern via `RegexSet` |
| Config            | TOML / YAML                            | Rules, thresholds, modes |
| Logging           | Structured JSON                        | request_id, rule, score |
| Tests             | Unit + integration + external WAF suites | GoTestWAF, OWASP CRS test suite |

---

## 3. High-level architecture

```
            ┌─────────────────────────────────────────────┐
 Client ───▶│                 WAF (reverse proxy)          │───▶ Backend app
            │                                              │
            │  ┌────────────┐   ┌──────────────────────┐   │
            │  │  Listener  │──▶│   Phased pipeline     │   │
            │  └────────────┘   │  (orchestrator)       │   │
            │                   └──────────┬───────────┘   │
            │                              │                │
            │   ┌──────────────────────────┼─────────────┐  │
            │   │ Normalization │ Modules  │ Scoring      │  │
            │   └──────────────────────────┴─────────────┘  │
            │              │ Logging / Metrics              │
            └─────────────────────────────────────────────┘
```

### Extension surface (open-core embedding)

The core is published on crates.io as a **library**; an enterprise tier **depends** on the published
crates and **implements the traits**, with no fork (`BOUNDARY.md` §4). The injection points are
exposed by a **stable** builder — every seam has a default, so a builder with no overrides equals
`Proxy::bind`:

```rust
let proxy = Proxy::builder(&config)
    .state_store(Arc::new(my_store))    // Arc<dyn StateStore>   — default: in-memory token bucket
    .cert_source(Arc::new(my_certs))    // Arc<dyn TlsCertSource> — default: FileCertSource (PEM)
    .modules(extra_modules)             // Vec<Box<dyn WafModule>> — extra, after the built-ins
    .build().await?;
```

The three OPEN→ENTERPRISE seams:
- **`StateStore`** (`waf-core::state`) — rate-limit state (and future IP-reputation). The contract is
  **one atomic operation** `try_acquire(key, cost, params) -> Acquired`, **not** get/update:
  refill-then-consume must be indivisible, else two nodes read the same bucket and both allow
  (cluster-wide over-allow / TOCTOU). In-memory enforces it under one lock; Redis with a server-side
  script. Clock and memory cap are **internal** to the store (out of the ABI). OPEN impl =
  `InMemoryStateStore`; Redis = ENTERPRISE.
- **`TlsCertSource`** (`waf-proxy::tls`) — certificate provenance. OPEN impl = `FileCertSource`;
  ACME/rotation/mTLS-PKI = ENTERPRISE. `[tls].enabled`/`alpn` still come from config.
- **`WafModule`** — additional detection modules (premium = ENTERPRISE).

**ABI freeze (pre-publish §5)**: the three traits are **public ABI** frozen via SemVer. `Config` is
`#[non_exhaustive]` → adding a future top-level section is **additive, non-breaking** (external code
builds from `Config::default()`/TOML, not a literal). Same for the sub-configs taken by-value by a
public fn (`TlsConfig`, `NetworkConfig`, `LimitsConfig`); the rest are protected transitively.

---

## 4. Phased pipeline (hook chain)

Traffic flows through a chain of phases. Each phase may **ALLOW**, **BLOCK**, **MONITOR**
or contribute a **SCORE**.

1. `on_connection`   — IP reputation, geo-blocking, initial rate limiting.
2. `on_request_line` — method, path, HTTP version.
3. `on_headers`      — header validation, anti request-smuggling.
4. `on_body`         — body inspection (chunked streaming, with limits).
5. `on_response`     — leak detection, outbound security headers.

Rule: **normalize BEFORE inspecting**. Normalization happens at the entry of every phase
that produces inspectable data.

> **Skip fast-path (Phase 7 / Pillar 3).** Between normalization and content inspection, a
> **prefilter** decides whether *any* content-detection rule *could* match the canonical
> surface. If not, inspection is **skipped** and the request continues as Allow (same
> forward, same decision-log) — a transparent optimization on benign traffic, not a second
> decision path. The gate is `Pipeline::run_inspection_gated`, the **single** point used by
> both the proxy and the equivalence oracle. Guarantees and numbers in §7.

---

## 5. Module contract (plugin interface)

```rust
/// Decision returned by a module
pub enum Decision {
    Allow,
    Block { rule_id: String, reason: String },
    Monitor { rule_id: String },
    /// Single contribution with explicit points (high-confidence rules /
    /// direct scoring): the module already knows the weight.
    Score { rule_id: String, points: u32 },
    /// N contributions, one per matched rule, each with its own severity.
    /// The pipeline resolves `severity -> points` via `[waf.severity_scores]`,
    /// so the cumulative score sums EVERY rule (3 Notices weigh more than 1).
    Scores(Vec<ScoreItem>),
    /// Direct rejection with an explicit HTTP status, distinct from `Block` (the 403 path).
    /// Two uses: `status:429` (rate limiting, with `Retry-After`) and `status:400`
    /// (request smuggling, illegal framing). Carries `status` and an optional
    /// `Retry-After`. In detection-only the pipeline logs it but does not reject.
    /// Table of the three deny semantics (403/400/429) in §9.
    Reject { rule_id: String, reason: String, status: u16, retry_after: Option<u64> },
}

/// A severity-tagged contribution emitted inside `Decision::Scores`.
pub struct ScoreItem { pub rule_id: String, pub severity: Severity }

pub enum Severity { Critical, Error, Warning, Notice }

/// Interface every detection module must implement
pub trait WafModule: Send + Sync {
    fn id(&self) -> &str;
    fn phase(&self) -> Phase;          // which phase it activates in
    fn init(&mut self, cfg: &Config);  // compile rules ONCE
    fn inspect(&self, ctx: &RequestContext) -> Decision;
}
```

- Modules are **stateless** with respect to the request (state lives in the `Context`).
- Rule compilation happens in `init()`, never in `inspect()`. In `init()` the module filters
  rules by **paranoia level** (`rule.paranoia <= cfg.waf.paranoia_level`).
- The `inspect -> Decision` signature is unchanged: a module returns **one** `Decision`,
  but `Scores` can carry **multiple contributions** (one `ScoreItem` per matched rule).
- The module does **not** assign points: it reports `rule_id` + `severity`. The
  `severity -> points` conversion and the `ctx.score` accumulation happen **only in the
  pipeline**.
- Every module is loadable/disableable from config.

### RequestContext (shared structure)
- `client_ip`, `request_id`, `timestamp`
- `method`, `path`, `raw_path`, `query`, `http_version`
- `headers` (parsed + raw)
- `cookies`
- `body` (chunk handle + parsed: form/multipart/json)
- `normalized` (canonicalized versions of the fields)
- `score` (mutable accumulator)
- `score_contributions` (per-rule breakdown: `{module, rule_id, severity, points}`, filled by the pipeline for audit/logging)

---

## 6. Normalization / Canonicalization

A **critical** point to avoid bypasses. Minimum steps:

- URL decode (single + double-encoding detection).
- Unicode normalization (NFKC) and overlong-encoding handling.
- Path lowercasing where appropriate.
- Null-byte removal, path-separator normalization (`..`, `//`).
- Consistent body decoding based on `Content-Type`.

> **Single shared pass (query / body / cookie).** Per-value canonicalization is a single
> helper (`canonicalize_value`): percent-decode with a **conditional second pass** if double
> encoding is detected (anti-double-encoding defense) + **NFKC**. Query, body **and cookies**
> use it, so "normalize once, inspect clean data" holds for all fields and **all**
> content-inspection modules (SQLi/XSS/RCE/LFI-RFI/Header-injection) benefit without changes.
> Deliberate difference: cookies use a **literal** `+` (RFC 6265 are not form-encoded),
> query/body treat `+` as a space. **Order vs limits**: cookies are decoded **after** the
> defensive limits are applied (`max_cookies` count, `max_header_size` on the raw header),
> never before — a short encoded cookie cannot expand beyond limits already validated.

> **Multipart field-coverage (10b-cont + fix).** For `multipart/form-data`, inspection
> covers, for EACH part, **all three** fields: the `name`, the `filename` and the part
> **value**. gotestwaf (`community-lfi-multipart`) hides the traversal in the **`name=`**
> (without a `filename`!) or in the value, often **double-/overlong-encoded** — the initial
> B1-cont fix only looked at `filename` and was bypassed. `Content-Disposition` parsing is
> **case-insensitive** on the header (`Content-disposition`) and attributes
> (`name`/`filename`). Each field goes through `canonicalize_multipart_field` (see below)
> BEFORE the rules. It is an extension of the **inspected field** + normalization, not a
> pattern broadening: the same path-traversal/LFI rules run. (Only the part fields; the
> `name` stays attacker content, not routing metadata.)

> **Multipart deep-normalization — overlong/`../`-base CLOSED on multipart (10b-cont fix).**
> `canonicalize_multipart_field` applies, before matching: (1) **recursive** percent-decode +
> overlong-collapse up to a fixed point (cap of 5 passes) → `%25C0%25AE`→`%C0%AE`→bytes
> `0xC0 0xAE`→`.` and `..%2f`/`..%5c`→separators; (2) NFKC. The 2-byte **overlong-UTF8**
> sequences that encode an ASCII byte (`0xC0/0xC1`, illegal) are mapped to their character
> BEFORE `from_utf8_lossy` (otherwise → `U+FFFD`, signature lost). So
> `%25C0%25AE…etc%25C0%25AFpasswd` in a part's value/`name` resolves to `../../etc/passwd`
> and is blocked.

> **Overlong PIPELINE-WIDE — query/path limit REMOVED (Phase 10c).** The 2-byte
> overlong-collapse was **promoted from the scoped-multipart to the shared pass**
> `canonicalize_value` (query / body / cookie / multipart, a single source of truth). The
> residual 10b-cont limit (`pt-overlong-utf8-passwd-query` as `ExpectedMiss`) is therefore
> **closed**: `?file=%C0%AE%C0%AE%C0%AF…` now resolves to `../../etc/passwd` and is blocked
> as in multipart. The FP/perf re-gate required for the generalization was performed (P2
> ladder unchanged, FP 0, inspection flat) — see §11 Phase 10c.

> **base64-derived channel (Phase 10c) — `decode-then-match-then-discard`.** Beyond the
> *in-place* canonicalization (above), §6 builds a separate **DERIVED** channel:
> `normalized.derived_decoded`, a list of base64-decoded variants of the inspected values
> (query-value, body form/json/multipart, non-excluded headers). The prefilter and **every**
> module read `derived_decoded` in addition to the canonical surface, so a `Base64Flat`
> payload (e.g. `PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==`) is decoded to
> `<script>alert(1)</script>` and caught by the relevant module's rule.
> - **`decode-then-match-then-discard`**: a derived variant contributes ONLY if it matches a
>   rule; otherwise it is discarded. That is why **candidacy** (`is_base64_candidate`:
>   alphabet `[A-Za-z0-9+/]`+`=`, length `%4==0` and `≥ BASE64_MIN_LEN`) is a **COST gate,
>   not a security gate** (O(1) reject on non-base64 traffic), and the decoded blob is kept
>   only if **`mostly_printable`** (≥90% printable ASCII): a benign high-entropy token/hash
>   decodes to signature-less noise → discarded → **no FP**.
> - **Shared budget `PIPELINE_CAP = 5`**: a SINGLE fixed-point pass counter is shared between
>   the two stages (overlong-collapse + base64-recurse, including base64-of-base64 and
>   base64-wrapping-percent/overlong) → guaranteed termination, linear-time (§13).
> - **The two channels have OPPOSITE freeze implications.** The **overlong** channel is
>   *canonical* (same value, a legal re-encoding resolved) → it is **pipeline-wide without
>   exceptions**. The **base64** channel is a statistical *derived* one → it has a **per-name
>   header exclusion** (D3): `Authorization`/`Proxy-Authorization`/`Cookie`/`Set-Cookie`/
>   `ETag`/`If-None-Match`/`If-Match` + every `*-token` header are base64-benign-heavy and
>   high-volume, so the decode-then-match bet does not pay off there and we exclude them.
>   **Cookies** are outside the base64 channel (session cookies are base64-benign-heavy) but
>   remain inside the overlong/canonical channel.
> - **JSON leaf via the derived channel (10c REOPEN, pcap-driven).** The string values of an
>   `application/json` body were a blind spot found with the pcap: `serde_json` already
>   unescapes `\uXXXX`/`\n`/… (NO JSON-unescape stage is needed, and `\xNN` is not valid JSON
>   → serde would reject the body), but the leaf is then **inspected RAW** — unlike
>   form-urlencoded (decoded at parse) and multipart (decoded in `body_str_values`), the JSON
>   leaf never sees `canonicalize_value`. So a leaf `%25C0%25AE…`/`%3CsvG…` reaches the
>   modules still encoded → bypass. Fix: `json_leaf_derived` feeds the **derived** channel the
>   decoded form of the leaf (percent+overlong fixed-point, pushed only if DIFFERENT from the
>   raw; + base64 expansion), sharing the **single** `PIPELINE_CAP` (no new cap). **The leaf
>   storage is NOT mutated** (decode-then-match-then-discard); the decoded form enters only via
>   `derived_decoded`. **Recursive at every level**: `flatten_json` descends objects+arrays,
>   so every nested leaf (`{"a":{"b":payload}}`, arrays) is covered — a wrapper does not
>   re-introduce the bypass. Isolating control (probe): the same `%25C0%25AE…` in query → score
>   12 (goes through `canonicalize_value`); in a JSON leaf pre-fix → score 0. FP-gate:
>   base64-like/overlong traps on the JSON-leaf surface → `benign_FP=[]` (high entropy
>   discarded by `mostly_printable`).
> - **`derive_variants` — the derived channel is MULTI-TRANSFORM (10c).** Beyond base64,
>   every inspected value goes through a set of anti-evasion transforms, all
>   `decode-then-match-then-discard` (a variant counts ONLY if it matches a rule → no FP):
>   - **§6-D1 EVASION entity-decode** (`html_entity_decode_evasion`): decodes named entities
>     (`&lpar;`→`(`, `&colon;`→`:`, `&equals;`→`=`, …) and numeric ones (`&#99;`/`&#x28;`)
>     **EXCLUDING the 5 structural chars `< > & " '`** — so benign escaping (`&lt;b&gt;`) stays
>     inert while the evasion (`javas&#99;ript:`, `confirm&lpar;1&rpar;`) resolves.
>   - **§6-D2 mid-token tag-strip** (`strip_midtoken_tags`): drops a `<…>` ONLY when surrounded
>     by word-chars on both sides (`\w<…>\w`) → the mutation `o<x>nfocus`→`onfocus`, while tags
>     that WRAP whole words (`<code>onerror</code>`) remain → zero FP.
>   - **§6-D2b mid-token control-strip** (`strip_midtoken_controls`): drops a run of C0 control
>     bytes (NUL/`0x01`–`0x1F`, excluding `\t\n\r`) between word-chars → `<<scr\0ipt>`→`<<script>`.
>   - **§6-D3 VBScript-concat de-obf** (`strip_vbscript_concat`): fuses the `"…&…"` joints of
>     VBScript string concatenation (`"Ex"&"e"&"cute`→`Execute`) for the well-formed `%26` form.
>   **COMPOSITION (cornerstone, found with the probe)**: the structural transforms are applied
>   to EACH **base64-decoded** variant too, not only to the raw — a `Base64Flat` payload has the
>   opaque blob as its raw (no `<`/`&`/control), so without the composition the decoded mutation
>   would stay un-reconstructed (this was the `o<x>nfocus`/`<<scr\0ipt>` Base64Flat bug).
>
> **Tracked 10d deferral (NOT silent) — `hdr-overlong-crlf-header-value`.** An overlong LF
> `%C0%8A` (= `\n`) in a **header value** inspected by `header_injection` stays
> `ExpectedMiss{until_phase:"10d"}`: folding it into that module's CRLF surface is a
> **canonical change** of the input-surface without a bite in 10c (per the §13 discipline a
> canonical change enters with its own bite + full P1/P2/P3 re-gate). Documented and
> under-test, not a silent hole; it flips to `Triggers` at 10d.

> **XSS-URL evasion — CLOSED in 10c (was B2-cont).** The two families that lacked a
> normalization pass are now caught by the `derive_variants` channel (see above),
> `decode-then-match-then-discard`, without opening an FP-factory:
> - **Entity-obfuscation** (`javas&#99;ript:`, `confirm&lpar;1&rpar;`, `&lt;svg/onload&equals;…`):
>   `html_entity_decode_evasion` (§6-D1) decodes the evasion entities **excluding** the 5
>   structural chars `< > & " '` → benign escaping stays inert.
> - **Mutation / tag-splitting** (`autof<x>ocus o<x>nfocus=…`, `<<scr\0ipt>`):
>   `strip_midtoken_tags` (§6-D2) and `strip_midtoken_controls` (§6-D2b) reconstruct the token
>   ONLY mid-token (`\w<…>\w`) → no FP on markup that wraps whole words.
>
> NB residual (frozen by-design): the **intra-token whitespace-collapse** (`java sc ript`,
> D2b-2) stays deferred (high FP on prose, 0 wire payloads); and some XSS-URL "bypasses" are
> `Warning`/PL2 sub-threshold by the anti-FP accumulation choice (§7, Bucket-B) — blocking
> them alone would require raising their severity (frozen).

> **SQLi-URL / MSSQL — CLOSED in 10c (was B3-cont → 10b-bis).** The 3 "medium" families
> (inline-comment `/*!UNiOn*/`, `information_schema` subquery, stacked/blind `sleep()`) and the
> JSON-functions (`JSON_EXTRACT`/`JSON_DEPTH`) already blocked (Critical). `xp_cmdshell` with
> comment padding (`3;/* a */…EXEC …xp_cmdshell @c`), previously sub-threshold, is now caught
> by the **`sqli-mssql-dangerous-proc`** rule (xp_cmdshell/xp_dirtree/xp_reg*/sp_oacreate/…
> Critical). **Invocation-anchored** for anti-FP discipline: the proc-name counts only when
> preceded by `[.;(=]` or `exec[ute] [schema.]` (so the wire `Master.dbo.xp_cmdshell` matches
> but the benign prose `"how to disable xp_cmdshell"` does NOT — probe-demonstrated).
> `severity_scores` stay frozen.

### Defensive limits (anti-DoS on the parser)
- Max header / body size.
- Max number of parameters / cookies / headers.
- Max JSON/XML depth.

---

## 7. Anomaly Scoring

A model inspired by OWASP CRS: blocking is **not binary** but cumulative.

- **Configurable severities** (`[waf.severity_scores]`): `critical/error/warning/notice` →
  points. No hardcoded scores in the modules; each rule declares only a severity.
- **Centralized accumulation in the pipeline**: every matched rule (via `Decision::Scores`)
  adds `severity_scores[severity]` to `ctx.score`. The score is the **sum of all matches**,
  both across modules (SQLi + XSS) and within the same module (3 Notices = 3×notice).
- **Contribution tracking**: the pipeline records in `ctx.score_contributions` who
  (`module`/`rule_id`/`severity`) added how many `points`, for audit/logging.
- **Configurable threshold** (`block_threshold`): if `score >= block_threshold` → in
  `blocking` mode BLOCK, in `detection-only` just log; otherwise ALLOW.
- **`Block` ↔ scoring coexistence**: `Decision::Block` remains a shortcut that blocks (in
  `blocking`) **regardless of the score**, reserved for very-high-confidence rules;
  `Decision::Score`/`Scores` instead feed the cumulative accumulation. Both paths go through
  the same pipeline, the single point that decides the final verdict.
- **Paranoia levels** (`paranoia_level`, 1..=4): each rule declares the minimum paranoia at
  which it activates; `init()` compiles only the rules with `paranoia <= paranoia_level`.
  Higher levels = more rules = more aggressive (and more false positives).
- **Decision logging**: at the end of the pipeline a record is emitted with the total
  `score`, `threshold`, `mode`, verdict and the contribution detail.

### Tuning the weights and the threshold (Phase 7 / Pillar 2)

The tuning of `[waf.severity_scores]` and `block_threshold` is **justified by corpus
evidence** (§10), not by inherited defaults. Three measured facts frame it, without sugar
-coating:

- **The benign corpus does NOT constrain the threshold.** All benigns score 0 (no rule
  matches): for any `threshold >= 1` the benign margin is `threshold-0`. So the threshold
  **does not separate** benign from malicious (it is trivial here) — it **encodes the
  ACCUMULATION POLICY**: how many co-occurring weak signals are needed to block. Pillar 1's
  100% recall is **detection** recall (a rule matches), distinct from the **blocking** recall
  (`score >= threshold`) that Pillar 2 measures from scratch.
- **Critical blocks on its own merit; Warning/Notice only via accumulation.** An isolated
  weak signal is FP-prone: e.g. `rfi-remote-url` is Notice/PL3 **because it matches any URL**
  — making it block on its own would block every `?redirect=https://…` in production. The
  corpus shows FP=0 only because it **avoids those inputs by construction**, not because it is
  safe to lower the threshold. So the weak signals stay sub-threshold by-design.
- **Recommended config C2**: `critical=6, error=4, warning=3, notice=2`, `block_threshold=5`.
  It raises Critical 5→6 so a single Critical blocks with **margin +1** (robustness the CRS
  default 5/T5 lacks), without touching the threshold or making the weak signals block (a lone
  Warning 3 / Notice 2 / `2×Notice`=4 stay below 5). Discarded on the evidence: **C1** (`T4`)
  because `2×Notice=4` would block → mass FP; **C3** (broad rescale) because it eliminates the
  Warning+Notice accumulation and lowers blocking-recall. The sweep verified that C2 has the
  **same blocking-set as C0**, benign-blocking 0 at every PL, `validate()` OK.
  **own-merit `block_margin`**: **PL1/PL2 +1** (the binding case = one Critical), **PL3 +0** —
  and that +0 is **by-design**: the case that binds the margin is not a fragile Critical but
  `lfi-rfi-remote-script` with own = Warning(3)+Notice(2)=5, i.e. the "Warning+Notice via
  accumulation block at the threshold" ladder. Pinned and validated in `tests/validation.rs`
  (five ladder properties).

**Explicit limits (honesty > the appearance of completeness):**
- **Overlap-masking (§8)**: at PL3 three malicious cases block **only** via the cross-module
  overlap `rfi-remote-url`, not on their own merit: `rce-download-exec-query`,
  `ssrf-loopback-query`, `ssrf-ip-obfuscation-query` (own=3, total=5). The blocking-recall gap
  **own 50% vs total 56%** at PL3 quantifies the masking (3/50). Read together with §8.
- **Absence of intra-module multi-signal malicious cases**: the corpus contains no cases that
  accumulate multiple rules from the **same** module. The accumulation behavior ("2×Warning
  blocks", "Warning+Notice blocks") is therefore **predicted by arithmetic** and tested only
  by incidental overlaps, not by dedicated cases. Future work post-freeze, not filled now
  (detection frozen).

**Status**: C2 is validated in the corpus and pinned in `tests/validation.rs`, and the
production default in `waf-core` is **aligned to C2** (`default_critical_score = 6`); the
`waf-pipeline` test that asserts the default is updated accordingly (`c.points == 6`). The
other weights stay CRS (`error=4, warning=3, notice=2`), `block_threshold` default = 5.

### Equivalence fast-path (Phase 7 / Pillar 3)

Reduces the cost of the full path on benign traffic **without changing a verdict**. The
equivalence is **tested** on the corpus (the oracle), not assumed.

- **Sound scope-aware prefilter.** A `RegexSet` union of all active content rules (derived
  from the same `*_RULES` tables → no drift), evaluated on the **canonical surface** (post-§6).
  Soundness by construction: a match is the OR of all patterns → **no match ⟹ no rule matches
  ⟹ Allow**. It can only err toward "candidate" (run the full path), never toward an incorrect
  skip.
  - **Two scope buckets**: `MAIN` (6 content modules + non-host header-injection) over a
    **superset** of the real surfaces {path,query,cookie,header,body}; `HOST` (only the
    `Scope::HostHeaders` rules, broad `[/@]` pattern) **only** over the host values. A
    scope-blind union matched the `/` of every path → 0 skips; the split fixes it.
- **Char-pre-check DISCARDED as unsound** (never implement it): (1) alphanumeric keywords
  (`union select`, `sleep(`, `/etc/passwd`); (2) §6 evasion (`%3C`/fullwidth → `<`). Both =
  false negatives.
- **Asymmetric equivalence (DEC 1)**: the **decision** coincides (Allow/Block/Reject);
  `score`+`matched_rules` only where inspection runs (a skip does not compute them; the
  short-circuit-on-block already produces partial rules by-design). **Fail-safe (DEC 3)**: a
  needless fast→full is only perf; a skip that hides a block is a **critical false negative** →
  a screaming assert.
- **Oracle + guards** (`tests/validation.rs`) on the real `run_inspection_gated` gate:
  full≡fast decision over 79 cases × PL1-3; soundness; completeness + **scope-correspondence**
  (host bucket == `Scope::HostHeaders` rules, derived from the source); 2 adversarial fixtures
  (benign-keyword + encoded). The **bite-test** (deliberate mis-scoping/char-check) turns the
  oracle red on 3 fronts, green on restore — the guard bites.
- **Measured gain** (`examples/fastpath_bench.rs`, @C2/PL3): **29/74** skip-eligible (all
  benigns + 3 gaps), **11.74×** on the benign path (1520→130 ns), 6.7% overhead on the
  malicious. Net positive on mostly-benign traffic.
- **Single construction** (`build_reloadable`): prefilter and pipeline from the same snapshot →
  a reload regenerates them together, never misaligned.

---

## 8. Module catalog (roadmap)

| Module            | Phase       | Priority |
|-------------------|-------------|----------|
| Normalization     | all         | P0 ✅ |
| SQLi              | body/query  | P0 ✅ |
| XSS               | body/query  | P0 ✅ |
| Path traversal    | request_line| P1 ✅ |
| RCE / Cmd inj.    | body/query  | P1 ✅ |
| LFI / RFI         | query       | P1 ✅ |
| SSRF              | body/query  | P1 ✅ |
| Header injection  | headers     | P1 ✅ |
| Request smuggling | connection  | P1 ✅ |
| Rate limiting L7  | connection  | P1 ✅ |
| GraphQL (structural)| body      | Phase 11 ✅ |
| gRPC (structural) | body      | gRPC phase ✅ |
| Geo / IP reputation| connection | P2 |
| Bot detection     | headers     | P2 |

Every detection module is enableable/disableable via config with the `[modules.<name>]`
section and the `enabled` flag (e.g. `[modules.path_traversal] enabled = true`). Modules
share the §7 scoring scheme (severities from `[waf.severity_scores]`, filtered by
`paranoia_level`); no score is hardcoded in the modules.

> **Rule tuning (pre-Phase 7, clean FP baseline)** — three Critical/Warning patterns were
> **narrowed** for known false positives on legitimate traffic (id, severity and
> `paranoia_level` **unchanged**, only the `pattern` changes; recall demonstrated by the
> existing positive tests):
> - `xss-event-handler`: from `on\w+=` (matched `?online=true`, `?onsale=1`) to a **closed
>   list** of real event handlers (`onerror|onload|onclick|on…`).
> - `sqli-tautology-or` / `sqli-tautology-and`: the char-class included the **space** with
>   `+`, crossing phrases (`men or women=adult`, `color or size=large`). Now the operands are
>   **numeric or single-character** (`1=1`, `'a'='a'`, `x=x`). NB: the `regex` crate has no
>   backreference → you cannot enforce the equality of the two sides; the operand narrowing is
>   the backref-free approximation that separates injected tautologies from benign
>   `word=word`.

> Rate limiting L7 (`[rate_limit]`, `on_connection` phase):
> - **Token bucket** per key: O(1) time/memory, configurable burst (`burst`), refill =
>   `requests / window_seconds` tokens/s. Chosen over fixed/sliding-window for the absence of
>   an edge effect and a constant footprint (light/fast goal).
> - **Pre-normalization execution**: the `on_connection` phase runs **before** Phase 2
>   (`Pipeline::run_connection` in the proxy), so over-threshold traffic is rejected without
>   paying for parsing.
> - **Action** (`action`): `block` → `Decision::Reject` (HTTP **429** + `Retry-After` computed
>   from the bucket `ceil((1-tokens)/refill)`); `score` → contribution to the cumulative score
>   (§7). In **detection-only** the overrun is logged but not rejected.
> - **Key** (`key`): `client_ip` = `ctx.client_ip`, i.e. the **resolved IP** from the shared
>   trusted-proxy resolver (see §9 and `[network]`), **not** the raw peer addr anymore. ✅
>   **Option B resolved**: behind a *trusted* LB/CDN the key is the real client taken from
>   `X-Forwarded-For` counting hops from the right; the rate limiter does not read the IP
>   directly — it uses `ctx.client_ip`, derived once in `build_context`. The `RateLimitKey`
>   enum stays ready for future keys (header, path).
> - **Memory**: cap `max_tracked_keys`; on overrun an idle-bucket sweep runs (full buckets →
>   indistinguishable from new keys, hence evictable).

> Path-traversal note: the normalizer (Phase 2) **already resolves** `.`/`..` in the path, so
> `../` sequences are detected on query/cookie/body (where they survive the decode), while on
> `normalized.path` the **sensitive targets** (e.g. `/etc/passwd`) that remain after
> resolution are detected.

> Inter-module boundaries (to avoid double-counting the cumulative score):
> - **Path Traversal** = filesystem manipulation (`../`, `/etc/passwd`, null-byte, UNC).
> - **LFI / RFI** = *inclusion mechanisms* of code/scripts: wrappers/streams (`php://`,
>   `phar://`, `data://`, `expect://`, `file://`, …) and remote inclusion (`http(s)://`/`ftp://`
>   of a script). Does not re-detect filesystem paths. Although it is in the catalog as a
>   `query` phase, it **inspects query + body + cookie** (LFI/RFI via POST exists).
> - **SSRF** = the server making requests to attacker-controlled URLs (metadata
>   `169.254.169.254`, `localhost`, schemes `gopher://`, `dict://`). It detects the **target**
>   (SSRF-specific IP/host/scheme), not the `http(s)://`/`ftp://`/`file://` schemes (which stay
>   with RFI/LFI). So `http://169.254.169.254/` gets `rfi-remote-url` (Notice, weak) **and**
>   `ssrf-cloud-metadata` (Critical) — different, non-redundant signals.

> Header injection notes (CRLF / response splitting):
> - **hyper insight**: the `http`/hyper crate **rejects CR/LF/NUL in inbound header values** at
>   parse, so CRLF injection *in headers* does not reach the WAF. The live surface is the
>   **percent-encoded CRLF in query/body params** (`%0d%0a…Set-Cookie:`), decoded by Phase 2
>   and potentially reflected by the backend into a response header, plus the **Host injection
>   to an absolute-URI** (`Host: http://evil`, which hyper accepts).
> - **Field-aware module**: unlike the other modules, the rules have a `scope` (All / NonBody /
>   HostHeaders / Body) because a bare CR/LF is anomalous in query/cookie/header but legitimate
>   in the body (textarea) — there it is Notice/PL3.
> - **Phase note**: `phase()` indicates only the **order** of execution in the pipeline, **not**
>   the inspected field. Header injection is in `Phase::Headers` but inspects query/body too
>   (the normalized data is all available regardless of phase).
> - **hyper boundary**: shared with Request Smuggling — the invariant "hyper sanitizes the
>   framing/headers upstream" is described **only once** in the Request Smuggling note (an
>   explicit security assumption).

> Request Smuggling notes (a **structural** module, not content-inspection — Phase 6/P4):
> - **What it is**: validation of the **HTTP framing** (body boundaries: `Content-Length` vs
>   `Transfer-Encoding`). Smuggling is the disagreement between how the WAF and the upstream
>   interpret those boundaries; **forwarding** an ambiguous framing IS the vector. So it runs in
>   `Phase::Connection` (in `run_connection`, **before** normalization and detection) and on an
>   illegal framing it **rejects with 400** — **binary**, never `Scores`.
> - **Rules** (all → `Reject{400}`): (1) CL **and** TE simultaneously; (2) duplicate CL or a
>   non-integer/list value; (3) duplicate TE or ≠ the single token `chunked`
>   (case-insensitive) — `xchunked`, `chunked, chunked`, lists `gzip, chunked` included. A
>   **strict** posture: the only accepted TE is `chunked` (lists are the ground of smuggling
>   and we re-serialize toward the backend anyway).
> - **⚠️ EXPLICIT SECURITY ASSUMPTION (hyper boundary)**: the **low-level framing hygiene** —
>   whitespace before `:`, obs-fold, OWS around values, CR/LF/NUL in headers — is guaranteed by
>   **hyper** which **rejects/normalizes it at parse**, *before* the modules see the request; in
>   addition the WAF **parses and re-serializes** toward the backend (the hyper client
>   regenerates CL/TE), structurally neutralizing most smuggling. This module is
>   **defense-in-depth** on the residual semantic ambiguities. **If the HTTP parser is changed,
>   or a path without re-serialization is introduced, the Rule 4 (whitespace-pre-`:`/obs-fold)
>   must be re-implemented on the raw bytes here.** This also applies to Header injection
>   (CR/LF).
> - **Tests**: the logic is covered by deterministic **unit** tests (hyper does not interfere);
>   the integration uses `gzip, chunked` (hyper accepts it because it ends in `chunked`, the
>   strict module rejects it) to exercise the full stack up to the 400.

> SSRF notes:
> - **Declared intra-module overlap**: `169.254.169.254` matches both `ssrf-cloud-metadata`
>   (Critical) and `ssrf-private-ip` link-local (Notice, at PL3) → additive contribution 5+2 at
>   PL3. It is intended defense-in-depth, not a bug.
> - **Known gap (IP obfuscation)**: the decimal/hex/octal rules cover only `127.0.0.1`, not the
>   metadata IP (`169.254.169.254` decimal = `2852039166`).
> - **Known gap (IPv6)**: coverage is limited to `[::1]` and `fd00:ec2::254`; `fc00::/7` (ULA)
>   and `fe80::/10` (IPv6 link-local) are missing.
> - Both gaps are guarded by `ExpectedMiss` cases in the validation corpus (§10): tracked, not
>   gating; if one day they fire, the case must be promoted to `Triggers` (a regression for the
>   better).

> Cookies are now normalized like query/body (double-aware percent-decode + NFKC): a payload
> encoded in a cookie (e.g. `php%3a%2f%2f`) is unwrapped and the decode-based rules fire on
> cookies too, for **all** content-inspection modules. See §6 (single shared pass) for the
> point and the order relative to the defensive limits. NB: `parse_cookies_limited` still keeps
> the raw text (for logging/limits); the decode happens **after**, at the same point where
> query/body are decoded.

> GraphQL notes (a **structural** module, not content-inspection — Phase 11):
> - **What it is**: like `request_smuggling`, it does NOT inspect content (injection in
>   arguments/variables is already caught by the JSON-leaf/derived channel, §6). It enforces
>   **DoS/abuse caps on the SHAPE** of the GraphQL operation: selection-set depth, alias/field/
>   directive counts, batch size, + an introspection policy. The counts come from a **lexical**
>   pass (`graphql_lex`, the 8th custom parser, fuzzed §13): **paren-aware depth** (a `{` counts
>   only outside an argument list `(...)`, so a nested input object does not inflate the depth),
>   skipping strings/block-strings/comments.
> - **Transports**: extracts the query from a JSON `query`/`<i>.query` leaf and GET `?query=`
>   **only on the configured `paths`** (so a non-GraphQL JSON API with a `query` field is left
>   alone), and from an `application/graphql` body (by Content-Type, any path). Default **OFF**
>   (endpoint-specific, caps need tuning).
> - **Decision**: a DoS cap over its limit → `Reject{400}`; introspection (if
>   `block_introspection`) → `Block{403}`.
> - **⚠️ STRUCTURAL module in `Phase::Body` → `WafModule::structural() = true`**: the fast-path
>   (Pillar 3, §7) proves "no **content** rule can match" and skips content inspection; but it
>   cannot prove a structural module inert, so structural modules run **even on the skip path**
>   (`run_phases_filtered(structural_only)`). Without this flag a GraphQL DoS with no content
>   signature would **bypass** the module. Rule: a new structural `Phase::Body` module MUST set
>   `structural()`.
> - **Related §6 fix (Step-0)**: an `application/graphql` body is `ParsedBody::Raw`, inspected raw
>   by `body_str_values` → its percent-decoded form was not inspected (encoded-injection bypass).
>   The body-derived collector now pushes the **Raw-body canonical** into `derived_decoded` (like
>   `json_leaf_derived`).
> - **11-bis (gotestwaf re-capture, wire-driven)** — two introspection bypasses, **two distinct
>   causes/layers**:
>   - **(a) CT-less §6 body-parsing hole** (generic, not GraphQL-specific): a body with **no
>     `Content-Type`** fell through to `ParsedBody::Raw` (JSON is parsed only for `application/json`)
>     → the **per-leaf** §6 channel (`json_leaf_derived`) was skipped, leaving only the whole-string
>     canonicalize. Result: an **encoded-in-leaf** injection (base64 / JSON `\u`) bypassed by simply
>     dropping the CT (plaintext did not — the raw string is still inspected). Fix = **`parse_body`
>     JSON sniff**: when the body looks like JSON (`{`/`[`) and parses, treat it as `application/json`
>     (`body.rs::sniff_json`); else `Raw`; a depth error propagates (fail-closed). Benefits **all**
>     modules.
>   - **(b) GraphQL GET transport**: gotestwaf places the **whole JSON envelope** `{"query":"<doc>"}`
>     in `?query=`, not a bare document → `graphql_lex` skips string contents and never sees
>     `__schema` (depth ≈ 1). Fix = `unwrap_query_envelope` (in `waf-normalizer`, serde already a dep
>     → detection stays serde-free): every *carrier* goes through **"envelope-or-raw"**
>     (`operations()`→`expand()`).
> - **Open/enterprise boundary** (`BOUNDARY.md` §3.1): the **structural caps** are core (OPEN);
>   **schema-enforcement** (validating the query against the app's real schema → schema management
>   = governance) stays **enterprise**.

> gRPC notes (**structural** module + §6 content channel — gRPC phase; needs the HTTP/2 of Phase 12):
> - **Two responsibilities, SEPARATE accounting** (the §6-fix lesson):
>   - **CONTENT (§6, always-on)**: the `application/grpc*` body is binary → the normalizer de-frames it
>     and extracts the protobuf fields (length-delimited leaves) into `derived_decoded`, so the content
>     modules (SQLi/XSS/…) inspect an injection hidden in a field. A SQLi-in-field catch is credited to
>     **§6 / the content module**, NOT to gRPC.
>   - **STRUCTURAL (`grpc` module)**: DoS caps on the SHAPE (message size / field count / nesting depth)
>     + a compressed policy → `Reject{400}`. Default OFF (`[modules.grpc]`).
> - **Parser** `grpc_extract` (9th hand-rolled parser, fuzzed §13): framing `[flag][len:4 BE][msg]` +
>   schema-less protobuf wire-format. Length-delimited heuristic: **valid UTF-8 → leaf string**, else
>   **recurse as a sub-message** (depth-capped). Content inspection is **declared best-effort** (the
>   wire format is ambiguous without the `.proto`: string|bytes|sub-message are indistinguishable) — the
>   guaranteed deliverable is the **structural** signal. NB: a UTF-8 sub-message stays ONE leaf, but the
>   nested text is still a substring of it → a content rule still matches.
> - **Compressed** (`on_compressed`): `grpc-encoding` ≠ `identity` or the per-message flag = opaque
>   payload → `Reject` (fail-closed, default) or `Passthrough` (on record). `identity`/absent = inspected.
> - **`structural()=true`** (like GraphQL): runs on the fast-path skip too (a gRPC DoS with no content
>   signature must not bypass).
> - **Datapath (gRPC phase, over Phase-12 HTTP/2)**: **h2c end-to-end** forwarding via a `http2_only`
>   client **dedicated** to gRPC targets (the general client stays h1 — no global flag) + **trailer
>   relay** (`grpc-status`/`grpc-message`) both ways. The model stays **buffer-then-inspect**
>   (`collect_with_trailers` keeps body AND trailers; `FramedBody` re-emits a data frame + a trailers
>   frame) → unary covered; **streaming deferred** (it would rewrite the body-path). `te: trailers` is
>   re-added on the gRPC forward (gRPC servers require it). An **h2-over-TLS** backend (`https://`) is
>   deferred.
> - **Open/enterprise boundary** (`BOUNDARY.md` §3.1): gRPC inspection = **core/OPEN** (datapath, like
>   JSON/multipart); premium signatures / schema-enforcement = enterprise.

---

## 9. Operability

### External configuration (Phase 6 — Pillar 1)

Loading the config from an external file is a first-class capability; **semantic validation**
is separate and reusable from hot reload (Pillar 3).

- **Path precedence** (most explicit/ephemeral → most implicit):
  1. CLI flag `--config <path>` (also `--config=<path>`) — per-invocation intent;
  2. env var `WAF_CONFIG` — deployment level (container/systemd/CI);
  3. default `config.toml`.
  Manual CLI parsing (no `clap`: a single flag).
- **Explicit pipeline** `resolve_path → load → parse → validate → build`:
  - `Config::validate()` (in `waf-core`, dependency-light) is the reusable **semantic check**;
    `waf-proxy::config::{resolve_path,load,parse_and_validate}` orchestrates fs/CLI and maps the
    errors; `Proxy::bind` is the build.
- **Fail-fast**: any error (I/O, TOML, semantic) → a clear message on **stderr** + **exit code
  2**. Never start with a partial config or silent defaults.
- **A missing file = a fatal error, always** (any source). A WAF must not start with an
  implicit config (`trusted_proxies` empty, rate-limit off, untuned thresholds): that is the
  "looks protected but isn't" scenario. `LoadError` distinguishes the diagnoses: `NotFound`
  ("file not found at <path>") vs `Parse` (bad TOML **or** a missing required field, e.g.
  "missing field `backend`") vs `Validation`.
- **Semantic validation schema** (`ConfigError`):
  - `proxy.backend`: absolute `http(s)` URL with an authority;
  - `waf.block_threshold >= 1`; `waf.paranoia_level ∈ 1..=4` (`MAX_PARANOIA_LEVEL`; PL4 is
    *forward-compatible* — see below);
  - `waf.severity_scores.*` each `>= 1`; `limits.*` each `>= 1`;
  - `rate_limit` (if `enabled`): `requests/window_seconds/max_tracked_keys >= 1`, `burst` (if
    present) `>= 1`, `score >= 1` if `action="score"`;
  - `network.trusted_hops ∈ 1..=10` (`MAX_TRUSTED_HOPS`); every `trusted_proxies` entry a valid
    CIDR; `client_ip_header` non-empty.
  - The reachability of `block_threshold` is guaranteed by construction by the `>= 1` checks on
    the threshold and the weights (no spurious cross-field rule).
- **PL4 "empty but legal"**: the validator guards the *contract* (`1..=4`), not the current
  state of the rules (max `HIGHEST_RULE_PARANOIA = 3`). If `paranoia_level` exceeds the maximum
  paranoia present, `Proxy::bind` emits a **warn** at startup: no additional rule is activated.
  This way PL4 does not silently behave like PL3.

- **Modes**: `detection-only` (default in staging) vs `blocking`.
- **Fail mode**: per-scenario via `[resilience]` (see below) — NOT a single global boolean (the
  old `waf.fail_open` was removed).
- **Hot reload**: reloads rules/config without a restart via **SIGHUP** (see below).
- **Logging**: JSON with `request_id`, module, `rule_id`, `score`, decision.
- **Metrics**: per-phase latency, blocked requests, estimated false positives.
- **Response status** — the **three Reject/deny** cases have distinct semantics:
  - `Decision::Block` (high-confidence detection / score threshold) → **403 Forbidden**;
  - `Decision::Reject{status:400}` (request smuggling: **illegal HTTP framing**) → **400 Bad
    Request**;
  - `Decision::Reject{status:429}` (rate limiting) → **429 Too Many Requests** with
    `Retry-After`;
  - normalization failed (parser limit, Pillar 2) → **400** per `on_parser_limit`.
  `deny_response` picks the reason-phrase from the `status` (400→Bad Request, 429→Too Many
  Requests); the 403 of `Block` is a separate arm. In detection-only there is no rejection: it
  only logs.

### Resilience: fail-open / fail-closed (Phase 6 — Pillar 2)

What the WAF does **when it is the one in trouble**. **Explicit, per-scenario** policy
(`[resilience]`), never implicit behavior. `FailMode` is uniform across all scenarios for
schema consistency, but the *meaning* of `fail_open` is scenario-specific (see the upstream
note).

| Scenario (`[resilience]`) | Default | fail_closed | fail_open |
|---|---|---|---|
| `on_internal_error` (module panic / regex) | **fail_open** | Synthetic Block (403 in blocking, log-only in detection-only) | skip the module, the request continues |
| `on_upstream_error` (origin down/timeout) | **fail_closed** | **502** Bad Gateway | **503** Service Unavailable (retryable) |
| `on_parser_limit` (normalization failed) | **fail_closed** | **400** | forward **uninspected** (critical log) |
| `on_config_error` (invalid reload, P3) | **fail_open** | refuse serving until the config is valid | keep the **last-good** config |
| `upstream_timeout_ms` | 30000 | — | round-trip cap (no worker hang) |

**Default rationale:**
- `on_internal_error = fail_open`: the WAF is an *additive* control; a bug of its own (panic,
  regex blow-up) must not lower availability below what the app would have *without* a WAF.
  Failing closed on an internal defect = a single point of failure.
- `on_upstream_error = fail_closed`: an origin down is not maskable (serving empty is worse); a
  clear 5xx + timeout. **Note**: `fail_open` on upstream does **NOT** mean "let it through"
  (there is no origin to reach) — it only chooses the **retryable 503 instead of the 502**.
  Different semantics from `fail_open` on `on_internal_error`.
- `on_parser_limit = fail_closed`: oversize/malformed input is a DoS and evasion vector (what I
  do not parse I do not inspect); forwarding it uninspected defeats the WAF.
- `on_config_error = fail_open`: a healthy WAF must not break over a bad reload; it keeps the
  last-good config. **Startup stays fail-fast** (Pillar 1): there is no last-good there. Reuses
  `Config::validate()` to detect the corruption.

**Panic isolation**: in `pipeline::run_phases` every `module.inspect()` runs inside
`catch_unwind(AssertUnwindSafe(...))`. `inspect` is read-only over `&RequestContext` → a panic
does not leave `ctx` partially mutated (sound). On a panic: **`error!` log** + applying
`on_internal_error`. **Cross-connection** isolation is also provided by the separate tokio task
per connection: a caught panic does not propagate, the other connections are untouched. Every
fail-open/closed activation is **logged** (a critical operational event).

> Migration: a residual `waf.fail_open` in the TOML produces an **explicit load error**
> (`LoadError::RemovedKey`, "use [resilience]"), never a silent no-op.

### Hot reload (Phase 6 — Pillar 3)

Reload of the config at runtime **without a restart** and **without dropping connections**.

- **Trigger: SIGHUP** (`tokio::signal`, `#[cfg(unix)]`) — a classic pattern (nginx/haproxy),
  zero new dependencies, an explicit operator intent. Discarded: file-watch/`notify` (a dep +
  debounce/race on partial writes) and an admin endpoint (an HTTP surface to authenticate). The
  signal is **only the button**: the validate-then-swap logic (`Reloader::reload_from`) is
  **OS-agnostic** and tested directly (even on Windows, where SIGHUP does not exist).
- **Atomic swap: `Arc<RwLock<Arc<Reloadable>>>` (std, zero-dep)**. Every request does a
  `read()`, **clones the `Arc`** and immediately releases the guard (never held across an
  `.await`) → the critical section = a clone (ns), reads are uncontended. The swap is a
  **single pointer assignment** that cannot panic → the lock is not poisoned by this path
  (poisoning is recovered with `into_inner` for defense anyway). `arc-swap` would give
  lock-free reads but is a dep for a marginal gain (reloads are very rare): a painless refactor
  if it is ever needed.
- **Validate-then-swap** (reuses Pillar 1): `config::load`
  (read→parse→validate→migration-guard). **Invalid config → KEEP the old one + log error**: a
  failed reload never degrades the working state.
- **Rule recompilation**: `build_reloadable` rebuilds **everything** as a unit (regex
  recompiled via `Pipeline::new`, CIDRs re-parsed via `ClientIpResolver`,
  normalizer/limits/backend/resilience) and swaps it atomically → never a mixed state (old
  regex + new thresholds). A request sees either all of the old or all of the new `Reloadable`;
  in-flight connections/requests complete with their own snapshot and are not interrupted.

**Runtime state (NOT reset) vs config (rebuilt):**

| NOT reset (process-lifetime) | Rebuilt in the swap |
|---|---|
| **rate-limit token bucket** (`StateStore` behind `RateLimitState`, re-injected; default in-memory, override `Proxy::builder().state_store(..)`) | rules/regex, paranoia filter, thresholds/severities |
| hyper connection pool (`client`) | rate-limit parameters (capacity/refill/action) |
| in-flight connections/requests | `trusted_proxies` CIDR resolver, resilience policy |
| `request_id` counter | limits, `backend` |

> **Non-exploitability**: the buckets survive the reload → an attacker cannot reset their own
> throttle by inducing a reload. If the new limit **lowers** the capacity, at the next refill
> the tokens are already clamped to `min(new_capacity)` (handled in `inspect`) → safe.

**Reloadable vs restart-required fields:**

| Field | Reload |
|---|---|
| `proxy.listen` (bind address) | **restart-required** — if it changes at runtime: **warn + keep the old value** (the socket is already listening) |
| `proxy.backend`, `[waf]`, `[modules]`, `[limits]`, `[rate_limit]`, `[network]`, `[resilience]` | hot-reloadable |

### Client-IP resolution (trusted-proxy)

An L7 WAF almost always sits behind an LB/CDN/TLS-terminator: the peer addr is the proxy's IP.
The **real client** is resolved by a shared helper (`waf-core::network`, `ClientIpResolver`),
derived **only once** in `build_context` and written to `ctx.client_ip` — a *single source of
truth* read by rate limiting, structured logging (Phase 1) and future Geo/IP-reputation (Phase
8). The rate limiter does **not** re-resolve: it reads `ctx.client_ip`.

`[network]` schema (a global section, `#[serde(default)]`):
- `trusted_proxies` — the CIDRs of one's own proxies (IPv4/IPv6, manual parsing, no
  dependencies). Default **empty**.
- `client_ip_header` — the chain header (default `X-Forwarded-For`).
- `trusted_hops` — how many hops to trust counting **from the right**.

Logic (the order **is** the security boundary):
1. peer **not** trusted → use peer, header ignored (`DirectPeer`).
2. peer trusted → the IP at `trusted_hops` **from the right**; **never** the first IP (it is
   client-controlled → spoofable) (`TrustedHeader`).
3. header absent / malformed / **chain shorter than `trusted_hops`** → fallback to the peer
   addr + `warn` (`FallbackMissingHeader`/`FallbackMalformed`); **never** fall back to the
   spoofable IP.
4. **Fail-safe**: `trusted_proxies` empty (default) → **always** peer, XFF ignored: an
   unconfigured deploy is not spoofable.

> Note: the `X-Forwarded-For` header the proxy **adds** toward the backend stays the **peer
> addr** (a record of the actually-observed hop), distinct from the resolved IP used internally
> for the key/log.

### TLS termination (Phase 12)

**Basic, cert-from-file** TLS termination on the listener — **core/OPEN** (`BOUNDARY.md` §3.2;
single-node self-sufficiency). Config `[tls]` (default **off**): `enabled`, `cert_path`, `key_path`,
`alpn` (default `["h2","http/1.1"]`).

- **Library**: `rustls` (+ `tokio-rustls`, **ring** provider), no OpenSSL — the **only** legitimate
  exception to the "hand-rolled parser" rule (TLS is never hand-rolled).
- **Unified h1+h2 serving**: `run()` uses `hyper-util` `auto::Builder` → one port serves h1 and h2
  (ALPN over TLS, preface over cleartext h2c). **`handle()` is UNCHANGED**: the `Request` is
  protocol-neutral and `body.collect()` delivers the **same** buffered `Bytes` over h1 and h2
  (invariant proven by the Step-0 probe). Inspection is therefore **protocol-agnostic** — bite test:
  a SQLi over h2-over-TLS is blocked 403 just like over h1.
- **ALPN h2-ready**: `["h2","http/1.1"]` negotiates h2 with a capable client and falls back to h1 with
  an h1-only client (it does not force h2). Prerequisite for gRPC-over-TLS (next phase).
- **§4 seam (`waf-proxy::tls`)**: `trait TlsCertSource` with the OPEN impl `FileCertSource` (PEM).
  ACME/rotation/multi-node certs / **mTLS with managed PKI** are ENTERPRISE impls of the same trait
  (mTLS is explicitly outside the core, `BOUNDARY.md` §3.2). **Injection**:
  `Proxy::builder().cert_source(..)` (default `FileCertSource` from config paths); `acceptor_from_source`
  picks the injected source vs the file. `[tls].enabled`/`alpn` stay in config — the source governs only
  the cert *provenance*.
- **No silent downgrade (fail-closed)**: with TLS enabled the listener serves **only** TLS. The
  acceptor is built at `bind` and is **immutable** (not hot-reloadable, like `listen_addr` =
  restart-required): there is no runtime path that downgrades to cleartext. `enabled=true` + an
  unreadable cert is a **fatal boot error**. A per-connection **handshake** error is logged and the
  connection dropped, **non-fatal** to the listener.
- **HTTP/2 DoS posture (on record)**: h2 opens surfaces h1 lacks (max-concurrent-streams, control-frame
  flood SETTINGS/PING/**RST = Rapid Reset, CVE-2023-44487**, HPACK). Phase 12 relies on **hyper/h2
  defaults**; no knob exposed yet — a **conscious, declared** choice, possible future tuning (extends
  the `[limits]` §6).

---

### Observability: logging + metrics (B1)

- **Structured JSON logging** (`tracing` + `tracing_subscriber`, `EnvFilter`): one line per decision
  (`request_id`, decision, score, contributions), plus `→ request`/`← response`.
- **Prometheus metrics** (`[metrics]`, default **off**): text exposition on `GET /metrics`. **OPEN
  baseline** (`BOUNDARY.md` §1.6); OTLP-push deferred (the counters are **exporter-neutral**, `render()`
  is the Prometheus exporter → OTLP later is a second sink, not a rewrite).
  - **SEPARATE listener** (`[metrics].listen`, default `127.0.0.1:9090`, loopback): **never** the data
    port — `/metrics` exposes internal posture (blocked/rate_limited volumes) and is itself an info leak
    if reachable; it would also be inspected by the WAF. **Fail-fast** bind at `bind` (busy port = boot
    error). The service returns **404** to anything that is not `GET /metrics`. *Cardinal bite-test: the
    data port does NOT expose `/metrics`.*
  - **Metrics** (Prom conventions, **base unit = seconds**): `waf_requests_total{decision=...}` (**closed**
    set: `allowed|blocked|rate_limited|bad_request|upstream_error|internal_error` — `internal_error` ≠
    `upstream_error`: the WAF's own failure vs a failed backend); `waf_request_duration_seconds`
    (**fixed-bucket histogram** + `_sum`/`_count`, **no in-process quantiles** → `histogram_quantile()` at
    scrape time); `waf_up`, `waf_build_info`.
  - **Cardinality rule (constraint)**: NEVER user-derived labels (no `path`/`ip`/`rule_id`) → a future
    per-rule breakdown is a separate capped metric, not a label on `requests_total`.
  - **Instrumentation = pure side effect**: `AtomicU64` relaxed counters, no lock/`.await` on the hot
    path; recorded at a **single point** (`handle`, via a returned `Outcome`). Verdicts are unchanged —
    proven by the unchanged validation.

### Importing OWASP CRS / ModSecurity rules (B2)

The core ships the **parser/engine** to import `SecRule` rules (`BOUNDARY.md` §1.7); the **curated
content** stays enterprise (§2.4). `[modules.crs]` (`enabled`, `files`), default **off**. `seclang` files
are read at boot, concatenated in include order, parsed and compiled into a `WafModule` (`crs`); an
unreadable file is logged and skipped (CRS is additive, default-off → fail-open on `on_config_error`, never
a crash). The 10th hand-rolled parser in the workspace (`seclang` lexer → AST → evaluator).

- **Two channels, never crossed (foundation, paletto #1)**: CRS rules declare `t:` transforms that
  ModSecurity applies to the **raw** value. Native modules read the §6 surface (`ctx.normalized.*`), which is
  **already** recursively percent-decoded + NFKC. Feeding that into a `t:urlDecode` would **double-decode**
  (`%2575`→`%75`→`u`) where ModSec decodes once → a silent semantic change. So the CRS channel sources from
  the **raw** `RequestContext` (`ctx.query`/`headers`/`cookies`/`body`) and the rule's `t:` pipeline does
  every decode. ModSec implicitly single-url-decodes when populating `ARGS` (replicated with a single-pass
  `percent_decode`); the rule's `t:` stack on top. *Cardinal bite-test: the double-decode control, both ways.*
- **v1 subset** (explicit; everything else is **SKIP + boot report**, never a silent drop — policy D3):
  directives `SecRule`/`SecDefaultAction`/`SecRuleRemoveById` (`SecAction`/`SecMarker`/`SecRuleUpdate*`/unknown
  = ignored); operators `@rx @pm @contains @beginsWith @endsWith @within @streq` (+ `!` negation), with
  `@detectSQLi`/`@detectXSS` (libinjection = a C dependency, against the ethos) and IP/geo/numeric operators
  out; transforms `lowercase urlDecode(Uni) htmlEntityDecode compressWhitespace removeWhitespace removeNulls
  normalizePath base64Decode none` (`t:none` **resets** the `SecDefaultAction`-inherited pipeline); targets
  `ARGS*`/`REQUEST_HEADERS[:n]`/`REQUEST_COOKIES`/`REQUEST_URI(_RAW)`/`REQUEST_FILENAME`/`QUERY_STRING`/
  `REQUEST_METHOD`/`REQUEST_PROTOCOL`/`REQUEST_LINE`/`REQUEST_BODY` + `:Name` selectors and `!VAR:n` exclusions;
  `chain` supported (all links must match); stateful (`setvar`/`ctl`/`skip`/…) or unknown actions → rule
  skipped. Phases 1/2 = request; 3/4/5 (response/logging) skipped.
- **`structural()=true` + performance (paletto #2)**: CRS rules carry external patterns the `ContentPrefilter`
  does not know → the fast-path cannot prove them inert → the module runs on **every** request (the price of
  faithful import). Mitigation: single-link positive `@rx` rules are **bucketed** by `(variables, t:-pipeline)`
  → one `RegexSet` per bucket (one pass instead of N regexes in a loop); chains/negations/non-`@rx` fall to a
  per-rule slow path. Cost scales with the number of **buckets**, not rules. *Measured*
  (`examples/crs_bench`, release, benign 4-arg request): one shared bucket 50→500 rules = 3.1→4.8 µs
  (sub-linear); 500 rules in 1 bucket (4.8 µs) are cheaper than 50 rules in 5 buckets (11.8 µs) → confirming
  the driver is the bucket count. In line with the native ~4-5 µs inspection → a real CRS file (mostly a few
  `ARGS` buckets) keeps the p99 budget (<1 ms).
- **Scoring + double counting (paletto #4, on record)**: every matched CRS rule emits a `ScoreItem`
  `{rule_id:"crs-<id>", severity}` (CRS `CRITICAL/ERROR/WARNING/NOTICE` → `Severity`; missing severity →
  `Warning`) into the **same** cumulative anomaly score as the native modules (no new decision logic; per-rule
  `block/deny/pass` is **folded** into the cumulative, CRS anomaly model). CRS and natives **overlap by
  construction** → a payload caught by both counts twice → **with CRS on the operator owns threshold tuning**.
  "validation 10/10 unchanged" holds **only because CRS is default-off**; the native corpus does not cover
  scoring with CRS on (we ship no CRS content, §2.4).
- **Declared v1 limits**: `@pmFromFile` (per-file path resolution) unsupported (use inline `@pm`); multipart/
  JSON bodies not mapped to `ARGS` (use `REQUEST_BODY`); `SecDefaultAction` does not apply to chain children;
  operator negation approximated as "no value matches".

### WASM / Proxy-Wasm plugin runtime (B3)

The core ships the Proxy-Wasm **runtime** (`BOUNDARY.md` §1.7); marketplace/signing stays enterprise (§2.4).
`[modules.wasm]` (`enabled`, `plugins[]`, `pool_size`, `fuel_per_request`, `max_memory_bytes`,
`checkout_timeout_ms`), default **off**. Isolated crate `waf-wasm` (depends only on `waf-core` + `wasmi`, so the
interpreter dependency does not fall on the whole workspace); each `.wasm` loads as a `WafModule` (`wasm:<name>`).
Engine = **`wasmi` 1.1.0** (pure-Rust interpreter, no JIT/C, built-in fuel metering — pin validated by the B3-0
probe). A `.wasm` that is unreadable or fails to compile is logged and **skipped** (fail-open at LOAD, like CRS).

- **Model (buffer-then-inspect → request path)**: headers and body are already buffered when the module runs, so
  per request the host runs the Proxy-Wasm sequence in one shot (`end_of_stream=1`): `on_context_create` →
  `on_request_headers` → (if `Continue`) `on_request_body` → `on_done`/`on_delete`. A guest's
  `proxy_send_local_response` is **captured** (never written to the wire) and mapped to a `Decision` (403 →
  `Block`, else `Reject{status}`); no capture → `Allow`. `phase()=Body`, **`structural()=true`** (like CRS: the
  host cannot prove a plugin inert → it runs on every request). **SDK init**: Rust-SDK guests register their
  factory in `_initialize`/`_start` (WASI reactor), which `wasmi` does not call on its own → the host invokes it
  once post-instantiate (found via the real SDK filter; without it the guest panics in `on_context_create`).
- **Host-function subset (paletto #4) + report**: implemented `proxy_log`, `proxy_get_buffer_bytes`,
  `proxy_get_header_map_pairs`/`_value`, `proxy_get_property`, `proxy_send_local_response`,
  `proxy_get_current_time_nanoseconds`, `proxy_set_tick_period_milliseconds`. Every **other** import the guest
  declares is **dynamically stubbed** (matching its `FuncType`) → `Status::Unimplemented` (so a real filter always
  instantiates, never fails on a missing import). **Lesson from the real SDK filter**: the SDK *declares* every
  import regardless of use → "degraded" is **not** derivable from declared imports (the boot report is
  **informational**). The accurate signal is at **runtime**: on the **first actual invocation** of a *semantic*
  stub (`proxy_http_call`/`shared_data`/`set_header*`/grpc/queue/foreign-call) the host emits a `warn!` and marks
  the instance (`semantic_stub_hit`). *Cosmetic* stubs (metrics/tick) do not change detection.
- **DoS (on record)**: **fuel** reset per request (`set_fuel`) is a **latency ceiling**, not just a kill-switch
  (it runs on every request); a **memory cap** (`StoreLimits`); no I/O host call beyond the subset (no filesystem,
  no `proxy_http_call` → anti-SSRF). Any **trap** (fuel/memory/runtime error) **fails closed** → `Reject{500}`
  (reuses the `on_internal_error` binary). The B3-0 probe proved that a trap **inside the reentrant malloc**
  (host→guest), from fuel **or** the memory cap, unwinds cleanly to `Reject{500}` with no host panic. *Measured*
  (`examples/wasm_bench`, release, a guest that reads+scans the header map, benign 5-header request): p50 ~7 µs,
  **p99 ~9 µs**, p99.9 ~12 µs → ~100× under the p99 budget (<1 ms).
- **Concurrency + isolation (paletto #1)**: `Module` compiled once (shared); a **pool** of `(Store, Instance)`
  behind `Mutex`+`Condvar`. `inspect(&self)` does a **checkout** (a `Store` is **never** shared across threads),
  populates `HostState` (host-reset: `req`/`captured`), `set_fuel`, runs, reads the disposition, **checkin**. The
  guest's own state is isolated per request via the Proxy-Wasm lifecycle (`on_context_create`/`on_delete`): a
  plugin that does not clean up is a **plugin bug** (declared trust boundary). **Pool exhaustion** (paletto #3):
  checkout **blocks-with-timeout** (`checkout_timeout_ms`); on expiry → fail-closed (`on_internal_error`).
  *Bite-tests*: two consecutive requests **on the same instance** (2nd benign → `Allow` even if the 1st blocked) +
  a concurrent variant (32 threads, no leakage/panic).
- **Declared v1 limits**: request-path only (response callbacks deferred); headers **read-only** (`set_header_*` =
  semantic stub); ABI fidelity proven against a **real** Proxy-Wasm Rust-SDK filter (env-gated smoke
  `WAF_WASM_FIXTURE`; the in-CI oracle is inline-compiled WAT guests — readable source, no opaque binary).

---

## 10. Testing strategy

- **Unit**: every parser and module with clean and obfuscated payloads.
- **Integration**: end-to-end pipeline through the proxy.
- **External suites**: GoTestWAF, OWASP ModSecurity CRS test suite.
- **Performance**: throughput/latency benchmarks, regex tests against ReDoS.
- **Regression**: a corpus of known false positives to avoid recurrences.

### Validation corpus (Phase 7 / Pillar 1)

A library crate `waf-corpus`: a **single, versioned and reproducible** set of malicious cases
(must fire) and benign ones (must not), which **measures** the **frozen** detection instead of
changing it. It is a library for reuse: the same evidence for threshold tuning (Pillar 2) and
the equivalence oracle for the fast-path (Pillar 3).

- **Format**: static Rust tables (`Case`), zero-parsing and type-safe. Each case: `id`,
  `module`, `field` (Query/RawQuery/FormBody/JsonBody/Cookie/Header/Path/Smuggling — carries the
  **raw** payload), `min_pl`, `expect` (`Triggers`/`Clean`/`ExpectedMiss`) and `rules` (the
  expected rule_id).
- **Raw builders via the `waf-core` `testkit` feature** (additive, never enabled by the proxy →
  zero-cost in production): they build the **pre-normalization** fields; the corpus then runs
  the **real `Normalizer`**, so it exercises the real pipeline and does not bypass it (unlike
  the `normalized.*` shortcuts of the module unit tests).
- **Runner = the proxy's flow**: `run_connection` → `normalize` → `run_inspection`, in Blocking
  with `block_threshold = u32::MAX` (the threshold never short-circuits inspection → every match
  and the complete cumulative score are collected). **Runner invariant**: **a fresh context per
  case** (every case starts from `score = 0`, no shared state) + **rate-limit neutralized** for
  the non-rate-limit cases (no spurious 429 from a shared `client_ip`). **Paranoia is a runner
  parameter**, baseline **PL3** (worst-case = all rules active); a per-case `min_pl` makes a
  case **skip** when `execution_pl < min_pl`, so a miss is never an artifact of having run the
  rule below its activation.
- **Metrics, three distinct ledgers**:
  - **recall / FP-rate** attributed to `case.module` (overlaps do **not** inflate the target
    module); a malicious case is "detected" if the verdict is consistent and at least one of the
    expected `rules` fired;
  - **score-distribution** with the **real cumulative `ctx.score`** (overlaps included) — what
    the pipeline would produce in production, a direct input to Pillar 2;
  - **declared overlaps (§8)** listed separately and made visible (e.g. `rfi-remote-url` on SSRF
    targets with a URL, `ssrf-private-ip` on `169.254.169.254`); **ExpectedMiss** (§8 gaps)
    counted separately, neither recall nor FP.
- **Execution**: `tests/validation.rs` **always runs in CI** as an anti-regression guard — (a)
  0 trigger-fails, (b) 0 FP, (c) §8 overlaps present, (d) all ExpectedMiss still missed, plus
  the **measure-then-pin** targets (recall 100% / FP 0% on the measured baseline + a coverage
  floor of malicious≥50/benign≥26). The verbose report (metrics table + score-distribution +
  overlap) is on-demand: `cargo run -p waf-corpus --example report`.

---

## 11. Phased roadmap (summary)

- **Phase 0** — Repo setup + passthrough reverse proxy.
- **Phase 1** — Pipeline + module contract + detection-only + logging.
- **Phase 2** — Parsing + normalization + defensive limits.
- **Phase 3** — First modules (SQLi, XSS) with a compiled regex engine.
- **Phase 4** — Anomaly scoring with a configurable threshold.
- **Phase 5** — Module expansion + L7 rate limiting.
- **Phase 6 ✅** — Operational robustness (4 pillars): external config ✅, fail-open/closed ✅, hot reload ✅, anti smuggling ✅.
- **Phase 7** — three pillars: **Pillar 1 ✅** validation suite (`waf-corpus`, §10); **Pillar 2
  ✅** threshold tuning → config **C2** (`critical=6`, the rest CRS, `block_threshold=5`),
  validated on the corpus with five ladder properties (§7); **Pillar 3 ✅** equivalence
  fast-path: a sound scope-aware prefilter (skip inspection on provably-clean benign), the
  equivalence proven on the oracle (79 cases, the production gate), 11.74× on the benign path
  (§7).
- **Phase 8 ✅ (sanitizer: smoke batch; long fuzzing in CI)** — Robustness (fuzzing, ReDoS,
  differential): fuzzing of the 7 custom parsers (cargo-fuzz/ASan, Linux/CI) + always-on
  cross-platform proptest invariants; ReDoS = the linear `regex` engine → backtracking
  impossible by construction (the test = an anti-regression guard + composition scaling);
  differential canonicalization with an independent oracle (the A/B/C relation). 0 findings;
  the canonicalization-vs-freeze policy is in §13.
- **Phase 9** — Performance and resilience under load. **Inspection latency**
  (`enqueue→verdict`, the number that depends ONLY on our code) under **criterion** with a
  versioned baseline + a **relative REGRESSION gate** in CI; the ABSOLUTE `<1ms p99` is declared
  on-demand on pinned hardware, not on a shared CI (CI varies 3-10× → an absolute there is
  noise). **e2e open-loop load-test** rate-based (oha/wrk2/k6, constant arrival-rate → no
  coordinated omission) as an informative overhead (WAF-in-path vs passthrough delta), NEVER the
  gate. Benchmarks on the **79 real P1 cases** (§10), not synthetic; worst-case = the cases with
  the most accumulated rules from P2's score-distribution (§7), not the average; the gate is
  **p99**, p99.9/max reported as early-warning. **Resilience** = an e2e bite-test of the
  **§9 ALREADY-declared** contract (module-panic `on_internal_error` additive fail_open /
  kill-upstream 502↔503 / corrupt-reload last-good — BOTH `FailMode`s proven, not just the
  default), no new policy and no re-pin. The **additive-control** rationale of `fail_open`-on
  -panic is on record as a contract, not assumed: the WAF is an *additive* control → a bug of
  its own (panic) must not lower availability below the no-WAF baseline; fail_open skips **only**
  the module that panics (the others run) → degrade-one-signal, **not** a WAF bypass.
  - **Pinned baseline (DEC 1/DEC 4)**: **~2 µs** worst-case PL3 inspection (saturated rules,
    `enqueue→verdict`, the `inspect_worst_case_pl3` bench on `lfi-rfi-remote-script-query`). It
    is NOT the fast-path regime (130–1520 ns) nor should it be — it is the worst-case at
    saturated rules. It is the **versioned reference** of the **relative** regression gate (DEC
    4). **Declared headroom (the DEC 1 story)**: ~2 µs worst-case vs the **p99 1 ms** contract ≈
    **500×** of margin — the number that depends ONLY on our code, isolated from upstream/network.
  - **Worst-case-set distribution** (`examples/latency_distribution.rs`, on-demand): p50 ~2.1 µs
    / **p99 ~3.1 µs** / p99.9 ~5.3 µs; the heaviest case `ssrf-cloud-metadata` (3 rules) crowns
    the p99 (~3.8 µs). **The gate (d) reference = the pinned single-case `inspect_worst_case_pl3`,
    NOT the aggregate** (the aggregate varies with the corpus; the single-case is stable). **`max`
    is NOT the contract**: `max` (~97 µs in the observed runs) is **scheduler jitter**, not a
    property of the code — proven by the fact that the heaviest case crowns the **p99**, not the
    `max`. DEC 2 gates the **p99**, never `max`; the gate (d) MUST ignore `max` by construction.
    The tooling split (criterion=a stable always-green gate / example=an on-demand distribution)
    mirrors the P2/Phase9 pattern.
  - **Permanent requirement of the resilience tests (the finding's lesson)**: the
    **fault-injection** traffic **must be prefilter-candidate** (reach inspection). The Pillar-3
    prefilter skips inspection on benign (§7), so "benign-looking" traffic short-circuits
    **exactly the path under test** and the guard measures nothing — the same class as the
    `prop_path_invariants`-green-with-the-broken-resolver of Phase 8 (§13). Exposed by the
    bite-test with the **atomic counter** in the panicking module; it holds for **all** scenarios
    (panic, kill-upstream, corrupt-reload).
  - **Phase 9 closure — net ledger (proven vs awaiting the ENVIRONMENT, not the work)**:
    - **PROVEN**: worst-case inspection ~2 µs / p99 3.1 µs / p99.9 5.3 µs with no alloc/lock
      cliff (a); the **relative** regression gate bite-verified (d, `examples/regression_gate.rs`);
      resilience **kill-upstream + corrupt-reload + panic-isolation** all bite-verified e2e (b);
      the §13 anti-pattern named (3 instances); the **candidacy bite e2e** green (c,
      `examples/load_overhead.rs`: candidate→403/benign→200, immune to noise).
    - **REFACTOR 1b** (freeze-safe, proven): `forward_to_backend` extracted (fwd/passthrough
      green before AND after, 17/17); `Proxy::bind_passthrough` `#[doc(hidden)]`, **not reachable
      from config** (the line vs the bypass of the rejected option-3); a single forward → the §13
      drift removed at the root.
    - **AWAIT THE ENVIRONMENT (harness built + known-correct, only where to measure is missing)**:
      the e2e overhead curve 1k/5k/10k → **oha on a quiet box** (in-process Windows: the ~3 µs
      signal is below the e2e noise floor ~344 µs → even a negative delta = the sanity-check that
      FIRES, DEC-C2 confirmed; the e2e **is not and never was** the contract, which remains the
      isolated (a)/(d)); CI pipeline wiring → git/CI environment; the **absolute <1 ms** e2e
      assertion → pinned hardware (never on shared CI).
- **Phase 10a ✅** — Detection coverage: the rule-sets that bypassed even in Plain/URL (whole
  missing modules), derived from `gotestwaf-report.json`. **5 new modules** (ldap, nosql, mail —
  B1; **ssti, scanner** — B2) + **2 extensions** (B2: `header_injection` now inspects the **path**
  for CRLF response-splitting smuggled in the URL; `rce` inspects the **path** for command
  injection in the URL — gotestwaf `crlf` / `rce-urlpath`). Each module wires the 8 points (rule
  file + `pub mod` + **`content_rules_split`** [HARD GATE: prefilter = the OR-union of those
  tables] + `ModulesConfig` + `build_modules` + `Module` enum/`name()` + `runner::build_pipeline`
  + corpus cases + the union assertion in `validation.rs`). Severity by decision-3: an
  unambiguous signature = Critical block-alone (ssti template-arith/freemarker, scanner tool-UA
  /OOB-domain, rce chained-command), a weak signal = accumulation (rce backtick).
  - **Per-encoder scoping (the 10a→10c invariant):** measured ONLY on the deduced URL/Plain
    subset. The **Base64Flat** duplicates → `ExpectedMiss{until_phase:"10c"}` (they need the §6
    base64-decode; the `expected_miss_phase_deferrals_honored` oracle FORCES the flip to Triggers
    when `CURRENT_PHASE` reaches 10c). The overlong-unicode CRLF `%e5%98%8d` →
    `ExpectedMiss{until:None}` (a documented limit: it is valid UTF-8 `U+560D 嘍`, the normalizer
    does NOT do best-fit mapping → no CR/LF ever appears; §6).
  - **All bite-verified** (the §13 methodology): exclusive attribution proven by the contributions
    report (every B2 Triggers fires ONLY its module's rules) + destructive bites (break the
    rule/the scope-path → the case goes RED with NOTHING saving it → restore → green): rce-path (3
    cases), header-path (3), ssti (3), scanner (8).
  - **Perf re-baseline (an explicit decision, "overrun" accepted):** worst-case PL3 inspection
    **~2.65 µs (end of B1) → ~4.3 µs (end of B2)**; the heaviest case
    `ssrf-cloud-metadata-query` ~4.9 µs. Attributable to the 2 new `RegexSet`s/request (ssti on
    query/cookie/body; scanner only on User-Agent) + the path added to rce/header_injection.
    **ACCEPTED**: headroom still **~230×** vs the p99 1 ms contract (the DEC 1 story holds with a
    wide margin). A new criterion `pinned` baseline re-saved = the reference of the relative
    regression gate (DEC 4) from here on.
  - **AWAITS THE ENVIRONMENT (work done, where to run it is missing):** re-run gotestwaf → live
    server + tool (the same class as the absent oha/CI, Phase 9); 10b/10c (advanced encoders,
    base64-decode in §6) will close the `until_phase:"10c"` deferrals.

- **Phase 10b ✅** — Detection coverage (continued): broaden EXISTING but weak rules (block <25%
  in URL/Plain) + close the last missing modules. Inverted risk vs 10a (broadening on
  high-traffic modules re-opens the FP trade-off), hence **STRUCTURAL precision** (the `regex`
  crate is a finite automaton: NO lookaround → precision fixes are structural, not `(?!…)`).
  Source = `gotestwaf-report.json`, **per-payload scoping** (URL/Plain → 10b; only Base64Flat →
  `until_phase:"10c"`). The key method **PROBE-FIRST**: the gap measured against the CURRENT
  code, not the stale report (many payloads were ALREADY caught by the post-snapshot evolution).
  - **B1 — `sqli` + `xss` (broadening):** 3 new high-precision CRS-aligned Critical SQLi
    (`sqli-mysql-versioned-comment` `/*!…`, `sqli-information-schema` underscore-anchored,
    `sqli-json-function`); XSS made precise (`xss-javascript-proto` → scheme-CALL
    `javascript\s*:[^()]*…\(` kills the FP "JavaScript: Basics…") + recall
    (`xss-js-sink-call`/`xss-js-sink-invocation` for the bypasses without a tag/handler).
  - **B2 — `shell-injection`/`rce`/`ss-include`:** rce extended (chained `getent|host`, windows
    `set /[ap]`, `rce-yaml-deserialization` `!!python/…`); a **new module `ssi`** (`ssi-directive`
    `<!--#<verb>`, Critical/PL1) that replaces the fragile mis-attribution to `sqli-quote-comment`
    on `"-->`.
  - **B3 — `xml`/XXE + `path-traversal`:** a **new module `xxe`** (Phase::Body, 3 Critical/PL1
    rules): `xxe-entity-declaration` `<!ENTITY`, `xxe-doctype-external` `<!DOCTYPE…SYSTEM`
    (**SYSTEM-only**, not PUBLIC → a legacy XHTML doctype with `PUBLIC` is NOT an FP),
    `xxe-utf7-encoding` `encoding="UTF-7"` (charset-smuggling: the real `<!DOCTYPE`/`<!ENTITY` is
    UTF-7-encoded). **path-traversal** extended: `pt-unc-path` widens the host-class with `:` for
    UNC to an IPv6-literal host (`\\::1\c$\…`, the backslashes survive normalization → it was only
    the char-class that was missing).
  - **Documented limits (`ExpectedMiss{None}` — they need §6, outside 10b rules-only):**
    XInclude/external schema (`xsi:schemaLocation`/`<xs:include>`) indistinguishable from benign
    SOAP/XSD without semantic parsing + URL-reputation → **deferred to avoid opening a SOAP
    FP-factory** (caught anyway as Notice by `rfi-remote-url` on the external URL,
    defense-in-depth); overlong-UTF8 `%C0%AE`=`.`/`%C0%AF`=`/` → `from_utf8_lossy`→U+FFFD, no
    `/etc/passwd` signature forms (the §6 overlong decode is needed).
  - **Bite-verified (§13):** EXCLUSIVE attribution proven on the contributions report (the clean
    Triggers fire ONLY their module's rule, a size-1 set → break the rule → RED with nothing
    saving it); the verbatim gotestwaf payloads with `http://` keep the DECLARED `rfi-remote-url`
    overlap.
  - **P2 GATE green** (`recommended_config_ladder_properties` + `baseline_targets_met`): the new
    Critical SQLi/XXE + XSS sinks → benign-blocking stays **0**, C2 holds, no threshold re-tuning.
    `CURRENT_PHASE="10b"`.
  - **Perf re-baseline (a decision, "overrun" accepted):** worst-case PL3 inspection **~4.3 µs
    (end of 10a) → ~5.1 µs (end of 10b)**, the heaviest case `ssrf-cloud-metadata-query` ~5.5 µs.
    Attributable to the 2 new `RegexSet`s/request (`ssi`, `xxe`) + the extra rules in the existing
    sets. **ACCEPTED**: headroom still **~195×** vs the p99 1 ms contract. The criterion `pinned`
    baseline re-saved (the DEC 4 gate reference).
  - **B1-cont — `path-traversal` `../`-base + multipart field-coverage:** two gaps from
    `gotestwaf-report-after-10b.json` closed. (1) **`../`-base recall without FP**: the
    `/static/img/../../etc/passwd` beacon in the querystring stays caught, but `pt-dotdot-traversal`
    is **structurally narrowed** `\.\.[\\/]` → `(?:\.\.[\\/]){2,}` (≥2 *consecutive* segments = a
    real escape) so a benign relative `../` (`docs/../report.pdf`, `../images/logo.png`) stays
    **Clean**; sensitive targets stay covered by `pt-sensitive-*` regardless. (2) **Multipart
    field-coverage**: `body_str_values` now inspects the **filename** of every part too (beyond the
    part's data), previously a blind spot — the LFI/traversal payload in
    `filename="…/../../etc/passwd"` (gotestwaf `community-lfi-multipart`) is now inspected; field
    NAMES stay out (control metadata, not attacker content). **D1**: UNC `\\::1\c$\…` URL/Plain is
    ALREADY caught by `pt-unc-path` (host-class `:`, B3) → no Windows-specific backslash broadening
    (the 10b-bis deferral confirmed); only the Base64Flat form stays deferred to 10c. **D2**:
    multipart depth = filename + part-value (the textual parts are already covered by the data).
    **D3**: `file:///etc/./passwd` is covered by the existing `file://` scheme in
    `lfi-stream-wrapper` (the `/./` is cosmetic) → a coverage extension, not a pattern one.
    **`ExpectedMiss` limit**: overlong-UTF8 `%C0%AE%C0%AE%C0%AF…` stays distinct from `../`-base
    (now covered) — it is a §6 limit (`from_utf8_lossy`→U+FFFD, see §6), not `../`. Beacon/UNC
    Base64Flat → `until_phase:"10c"`. Bite/smoke red→green demonstrated (multipart-filename
    `[]`→caught; benign `../` trap FP→Clean) before the harvest. **P2 GATE green** (corpus recall
    100% 103/103, FP **0/62**, C2 ladder unchanged); **perf** worst-case PL3 ~4.5 µs (+~4.5% vs
    `pinned`, < the 10% gate — the multipart filename clone weighs only on multipart traffic, not
    the worst-case query). No re-pin (a sub-batch). `CURRENT_PHASE` stays `"10b"`.
  - **B1-cont FIX — multipart `name`/value + overlong/double-encoding.** The initial B1-cont fix
    only looked at `filename`; gotestwaf (`community-lfi-multipart`, confirmed by pcap) puts the
    traversal in the Content-Disposition **`name=`** (without a filename) or in the **value**,
    often **double-encoded/overlong** (`%25C0%25AE…`). Three interventions: (1) `body_str_values`
    now inspects **name + filename + value** of every part; (2) **case-insensitive**
    Content-Disposition parsing on the header and attributes (`name`/`filename`); (3) a new
    `canonicalize_multipart_field` (waf-normalizer) = recursive percent-decode + **overlong-UTF8**
    collapse to a fixed point (cap 5) + NFKC, applied BEFORE the match (`%25C0%25AE`→`.`,
    `..%2f`→`/`). Smoke red→green: name-traversal `[]`→blocked, overlong-value `[]`→blocked, benign
    multipart trap→Clean. **`pt-dotdot {2,}` unchanged** (both pcap cases resolve to `../../` ≥2 +
    `/etc/passwd` → caught; NO return to `{1,}` which would re-open the FP on a single benign `../`
    approved in B1-cont). Overlong on QUERY stays `ExpectedMiss` (decode scoped to multipart, see
    §6). **GATE green**: path_traversal recall **11/11**, aggregate **105/105**, **FP 0/63**,
    fast-path-equivalence green; **perf** worst-case query ~5.3 µs (stable over 2 measurements, "no
    change" — unchanged by my code: the query path does not touch multipart; cross-session vs ~5.1
    µs end-10b). The multipart cost is limited (≤5 passes, short strings, only on multipart
    traffic). No re-pin.
  - **B2-cont — `xss` URL: EVALUATED, CLOSED WITHOUT ACTION.** Probe-first over the 40 distinct
    XSS-URL payloads (canonical surface, PL3): **38/40 already intercepted**; the only 2 real
    pattern-misses are the known §6 limits (entity-obfuscation, mutation/tag-split). The report's
    residual "bypasses" are NOT pattern-misses: a rule matches but is `Warning`/PL2 sub-threshold
    (anti-FP accumulation). The only lever would be raising the severity → **excluded (severities
    frozen, the cycle-b decision)**, even more so at max paranoia. Zero changes; the finding is
    documented in §6.
  - **B3-cont — `sqli` URL: EVALUATED, CLOSED WITHOUT ACTION.** Probe-first over the 3 medium
    families + the sophisticated ones (C2 score, T=5): inline-comment / `information_schema` /
    blind `sleep()` **already block** (`Critical` 6), like `JSON_EXTRACT`/`JSON_DEPTH`
    (`sqli-json-function`). The Triggers-regressions are already in the corpus (B1-10b). The only
    residual `xp_cmdshell`: **detected** (`sqli-cast-convert`) but sub-threshold (Notice/PL3) — NOT
    a pattern-miss and NOT taggable as `ExpectedMiss` (the oracle uses `still_missed = !triggered`:
    a rule fires → it would read as "caught ahead of phase"). A dedicated MSSQL rule **deferred to
    10b-bis**. Severities frozen. Zero changes; the finding is in §6.
  - **Cycle-b closure — a method note.** **Probe-first** drove B1-cont (the real gap = multipart
    field-coverage, not broadening), B2-cont and B3-cont (the real gap = sub-threshold severity
    *by-design*, not coverage). The cycle's key distinction: **coverage vs severity** — a payload
    that bypasses the *block* is not a pattern-miss if a rule *detects* it; you close it by
    freezing the scores, not raising them. `severity_scores` were NEVER unlocked at max paranoia
    (the FP trade-off P2 had frozen stays frozen). Opened as explicit deferrals: **10b-bis** (UNC
    Windows-backslash broadening, `xp_cmdshell`/MSSQL stacked-with-comments) and **10c**
    (Base64Flat encoder + §6 base64-decode). `CURRENT_PHASE` stays `"10b"`.

- **Phase 10c ✅** — Advanced encoders: closes the `until_phase:"10c"` deferrals by opening the
  §6 channel **base64-decode + overlong pipeline-wide** (`decode-then-match-then-discard`, see §6).
  `CURRENT_PHASE` → `"10c"`.
  - **15 deferrals flipped to `Triggers`** (the `expected_miss_phase_deferrals_honored` oracle
    FORCES them caught at 10c): `ldap` 3, `mail` 3, `nosql` 3, `ssti` 3, `path_traversal` 3 (the
    base64 beacon `/static/img/../../etc/passwd`, UNC IPv6, **overlong-UTF8 query** — now
    pipeline-wide). Zero un-flipped residuals. The only open `ExpectedMiss` is the **10d**
    `hdr-overlong-crlf-header-value` (a CRLF canonical change without a bite in 10c — §6/§13).
  - **Per-stage bite (§13, red→green of the two beacons).** A double property demonstrated on
    `pt-faro-base64` and `pt-overlong`: (1) **independent necessity** — `base64-decode→None` drops
    ONLY the base64 beacon (overlong stays 🟢), `overlong-collapse→identity` drops ONLY the overlong
    beacon (base64 stays 🟢); (2) **no rescue via another path** — breaking the stage collapses
    `prefilter_candidate` to `false` TOGETHER with `caught` (it is not the prefilter nor another
    module keeping it up, it is exactly that decode). Restore → 🟢🟢.
  - **Harvest recall-lock (1/module, not gotestwaf-tracked).** Added 4 base64 Triggers-regressions
    on modules not covered by the report's deferrals — `xss-script-tag-b64`,
    `sqli-information-schema-b64`, `rce-chained-command-b64`, `ssi-exec-directive-b64` — to pin that
    the derived channel feeds xss/sqli/rce/ssi too. **All 🟢** (no RED to triage). Purpose: lock the
    under-tested recall, not inflate the corpus.
  - **GATE green** (all 10 validation tests): `fastpath_equivalence` ✓, `no_false_positives` ✓,
    `recommended_config_ladder_properties` (P2) ✓ — the P2 ladder is NOT re-tuned (the derived
    channel only contributes decode-then-match, no benign score shift; FP 0),
    `expected_miss_phase_deferrals_honored` ✓.
  - **PERF — re-baseline (honest reading, pin NOT re-saved).** Worst-case PL3 inspection
    `lfi-rfi-remote-script-query` ~3.74 µs, heaviest `ssrf-cloud-metadata-query` ~4.11 µs, the
    ssrf/rce family 3.7–4.2 µs — all **≤ the end-10b pin ~5.1 µs**, no 10% gate overrun. Criterion
    shows -14/-30% but that is **misleading**: the saved baseline was from a run under load (~5.3
    µs); the correct reading is **flat/within the envelope, no regression from the `.chain(derived)`**.
    The end-10b pin is left as-is (heavy-load) and **declared as such**: re-saving it on a possibly
    "light" run would skew the comparison. **Caveat**: this bench measures **inspection, not
    normalization** — the new cost of the two stages lives in normalization (an O(1)-reject candidacy
    pre-check on non-base64 traffic + an overlong fixpoint bounded by `PIPELINE_CAP=5`); headroom
    **~165–270×** under the p99 1ms contract even with the normalization delta. A clean perf re-pin is
    a dedicated item ("re-pin on a controlled measurement"), NOT forced inside 10c.
  - **Opened as explicit deferrals:** **10d** (`hdr-overlong-crlf-header-value` — a CRLF canonical
    change with a bite + full P1/P2/P3 re-gate) and **10b-bis** (UNC Windows-backslash broadening,
    `xp_cmdshell`/MSSQL stacked-with-comments).
  - **REOPEN 10c (pcap-driven, probe-first) — JSON leaf canonicalize.** A tcpdump pcap of LIVE
    gotestwaf traffic (`bypass.txt`) refuted the corpus-green: two bypass classes on the wire. The
    **STEP-1 probe** (on the LIVE normalizer+pipeline, not the harness) **REFUTED** the hypothesized
    root causes: (#1 JSON) serde ALREADY unescapes `\u` → the cause is the **missing canonicalization
    on the JSON leaf** (body_str_values clones it RAW), proven by the isolating control "same byte:
    query score 12, JSON-leaf score 0"; (#2 multipart name) the field-name is **already routed** by
    the 10b-cont fix (score 12 in-process) → the 200 on the wire was a **STALE live binary**. **FIX
    #1** = `json_leaf_derived` (see §6): decode the JSON leaf into the **derived** channel (shared
    CAP, storage not mutated, recursive over objects+arrays, NO unescape stage). Wire fixtures
    RED→GREEN: `pt-wire-json-unicode-overlong` (score 12), `xss-wire-json-unicode-svg-onload` (score
    9), + the recursion lock `pt-wire-json-nested-overlong`. **FP-gate** demonstrated on the JSON-leaf
    surface (3 base64-like/overlong/percent traps → `benign_FP=[]`). **GATE 10/10** green, perf
    worst-case query **3.58 µs (−4.5%, flat)** — the JSON channel does not touch the query path.
    **UNC CARVE-OUT**: `\\::1\c$\…` as a multipart-name stays **200** (pt-unc-path score 2,
    sub-threshold) = frozen severity, **10b-bis out of scope** (NOT a false-red of the gate). The
    final oracle = a **re-captured pcap** (live gotestwaf + tcpdump): an ENV-GATED step that
    recompiles the binary (closing #2 too) and confirms 403 on all variants except the UNC carve-out.
    `severity_scores` and `pt-dotdot {2,}` **frozen**. `CURRENT_PHASE="10c"`.

  - **Recapture-driven cycle (10c, probe-first on the wire) — CLOSED.** Live gotestwaf re-captures
    (pcap `bypass-*.txt`) used as the **oracle** instead of the corpus-green. Bypass journey
    466→…→59→~28. Closed in sequence, each one re-gated (validation 10/10, FP=0):
    - **P0 (wire-fidelity)**: NON-padded base64 candidacy (`len%4!=1`, gotestwaf Base64Flat does not
      pad), scanning the **path** in the content modules (`std::iter::once(ctx.normalized.path)`),
      base64-in-path from the case-preserved **raw-path**, scanner `openvas\w*`. **Meta rule**: the
      corpus cases MUST be faithful to the wire (non-padded base64, exact UAs, payload in the
      path/header).
    - **P1**: the `rce-expression-language` rule (`${@print(…)}`/SpEL) + a **header-surface
      allowlist** (`header_content_inspectable`: Referer/X-Forwarded-*/`x-*` minus a deny-list) over
      10 modules.
    - **§6-D1/D2/D2b** via `derive_variants` (see §6): entity-evasion-decode, mid-token tag-strip
      (`o<x>nfocus`), mid-token control-strip (`<<scr\0ipt>`). A **composition bug** found with the
      probe (the transforms started from the raw → no-op on the Base64Flat blob) → fix = compose them
      over the **base64-decoded** variants too.
    - **§6-D3 (VBScript/ASP webshell)**: the rules `rce-vbscript-on-error`/`rce-asp-server-intrinsic`/
      `rce-vbscript-createobject` (Critical) — the `&`-concat is LITERAL on the wire → it fragments the
      query, but the intrinsics (`On Error Resume Next`, `Server.ScriptTimeout`) survive INTACT in a
      fragment; + the `strip_vbscript_concat` de-obf (`"&"`-join) for the well-formed `%26` variant.
    - **§6-D5 (external-XML-schema)**: the rules `xxe-xs-include-namespace` (an include with a
      `namespace` attr = malformed) and `xxe-schemalocation-single-url` (a single-URL schemaLocation vs
      a legit pair) — anchored on the **anomalous form**, FP-probed=0 on real SOAP/XSD (a blanket would
      be an FP-factory).
    - **10b-bis**: `sqli-mssql-dangerous-proc` (xp_cmdshell/sp_oacreate/… **invocation-anchored**
      `[.;(=]`/`exec` → no FP on the prose "disable xp_cmdshell") and `pt-unc-admin-share`
      (`\\host\<share>$\` Critical, the generic UNC stays Notice). Probe-first **refuted** 2 gaps
      (sleep-nested score 6, lfi-multipart-name score 12 ALREADY blocked: the 200 on the wire was a
      **stale binary**).
    - **Residual frozen-by-design (documented, NOT coverage gaps)**: **D4** overlong-CRLF
      (`%e5%98%8d`=U+560D 喍, valid CJK; the best-fit→CR is backend-specific → treating it as CRLF would
      FP on Chinese text — a **permanent limit**); **Bucket-B** sub-threshold XSS sink-call (`alert(1)`:
      threshold→3 = a real FP on `alert(message)`/`$or`); **D2b-2** whitespace-collapse (high FP on
      prose, 0 wire payloads). `severity_scores` frozen. **Final DoD = an env-gated gotestwaf
      re-capture** (expected 200→403 on all closed classes). **10c cycle CLOSED.**

- **Phase 11 ✅** — **GraphQL** (structural protections). Not content coverage (injection in
  arguments/variables is already caught by §6: JSON-leaf/derived); the real gap was the
  **semantic GraphQL protections** (DoS/abuse) that regex cannot give. **Probe-first with 3 user
  guardrails** (canonical-not-raw / two-columns-separate / paren-aware trap): Step-0 REFUTED the
  GET suspicion (it canonicalizes) and DISCOVERED that `application/graphql` was **raw** (§6
  raw-body fix, see §6/§8). Pieces:
  - **Lexer `graphql_lex` (8th custom parser, fuzzed §13)**: a linear lexical pass, **paren-aware
    depth** (an input object inside arguments does not inflate the depth), skipping
    strings/block-strings/comments → `max_depth`/`aliases`/`fields`/`directives`/`has_introspection`.
  - **STRUCTURAL `graphql` module** (`Phase::Body`, `structural()=true`): caps → `Reject{400}`,
    introspection → `Block{403}`. Config `[modules.graphql]` default **OFF** (opt-in, tunable caps),
    JSON/GET transports on `paths` + `application/graphql` by Content-Type.
  - **ARCHITECTURAL BUG found by the re-gate (`fastpath_equivalence`)**: a structural `Phase::Body`
    module ran inside the inspection **gated by the content fast-path** → a DoS with no content
    signature was **skipped** (a production bypass, not just corpus). FIX: trait
    `WafModule::structural()` + `Pipeline::run_phases_filtered(structural_only)` (structural modules
    run on the skip path too) + corrected `fastpath_skipped` semantics (`!inspect && Allow`). A
    durable lesson on record in §8.
  - **Open/enterprise boundary**: structural caps = core; **schema-enforcement = enterprise**
    (`BOUNDARY.md` §3.1). **gRPC = Phase 12** (will need HTTP/2, absent today).
  - Re-gate: **validation 10/10, FP 0**, workspace green, clippy clean. GraphQL corpus: 5 DoS caps +
    introspection + 3 transports + path-gating + the paren-aware trap. **Phase 11 CLOSED.**
  - **11-bis (gotestwaf re-capture, wire-driven)** — 4 introspection bypasses (2 payloads × 2
    transports) analysed probe-first on the real path: REFUTED double-encoding (the fixpoint resolves
    it) and module-off (it was ON). **Two distinct causes, separate accounting** (see §8 notes):
    - **(a) CT-less §6 body-parsing hole**: a body with no `Content-Type` → `ParsedBody::Raw` → the
      per-leaf §6 channel was skipped. Falsification matrix: **plaintext does not bypass**,
      **encoded-in-leaf (base64 / JSON `\u`) does**. Fix = `body.rs::sniff_json` (sniff `{`/`[` →
      `JsonFlattened`), benefiting **all** modules; it also closes the CT-less POST introspection.
    - **(b) GraphQL transport gap**: a JSON envelope `{"query":…}` in the GET `?query=` →
      `unwrap_query_envelope` + `operations()`→`expand()` (envelope-or-raw). serde stays confined to
      `waf-normalizer`.
    Re-gate validation 10/10 FP 0; locks: 9 `ctless_json` unit + 3 envelope unit + 6 integration
    `waf-detection/tests/graphql.rs` + 4 corpus cases (2 with **verbatim pcap strings**). **Wire
    confirmed 200→403.** Lesson: the final oracle is the **wire**; a body with no `Content-Type` is
    not an edge case but an **evasion surface** (the CT is attacker-controlled).

- **Phase 12 ✅** — **TLS termination** (basic, cert-from-file → **core/OPEN**, `BOUNDARY.md` §3.2). See
  §9 "TLS termination" for detail. **Probe-first (Step 0)**: before touching the datapath, a throwaway
  proved the **foundation invariant** `body h2 == body h1` at `handle()` (`body.collect()` is
  protocol-agnostic) + ALPN h2 negotiates + the TLS toolchain builds on Windows (ring, no
  aws-lc-rs/cmake) → "if the invariant holds, the rest is mechanical". Pieces:
  - **rustls + tokio-rustls (ring) + rustls-pemfile**, no OpenSSL (the one legitimate exception to
    no-hand-roll).
  - **`auto::Builder` serving** (h1+h2/h2c on one port); `run()` → generic `serve_connection<I>`
    (TcpStream | TlsStream); **`handle()` unchanged**.
  - **config `[tls]`** (default off) + validate (`TlsPathEmpty`/`TlsAlpnInvalid`); **`TlsCertSource`
    seam** + `FileCertSource` (§4: ACME/rotation/mTLS = enterprise).
  - **fail-closed**: unreadable cert = fatal boot error; **no cleartext downgrade** (acceptor immutable
    post-bind); per-conn handshake error non-fatal. **HTTP/2 DoS posture** on record (hyper/h2 defaults,
    Rapid Reset CVE-2023-44487; no knob in P12).
  - Re-gate: **validation 10/10**, workspace green, clippy `-D warnings` clean. Tests: matrix
    `waf-proxy/tests/tls.rs` (4 protocols + 2 fail-safes + **bite SQLi-over-h2-TLS→403** + seam units) +
    3 `[tls]` validation tests in waf-core. **gRPC = next phase** (de-framing + protobuf + h2 backend).

- **gRPC phase ✅** — **gRPC inspection** (`OPEN`, over the Phase-12 HTTP/2). See §8 "gRPC notes". **Two
  user guardrails**: (A) the nesting trap in the corpus BEFORE the parser; (B) separate accounting
  (content→§6, structural→grpc module). **Probe-first (Step 0)**: the foundation invariant was the
  **buffer-vs-trailer** tension — a throwaway proved `Collected` keeps body AND trailers and that a
  `FramedBody` (data+trailers) re-emits them on unary without going back to streaming, + a dedicated h2
  client. Pieces:
  - **Parser `grpc_extract`** (9th hand-rolled, fuzzed): framing + protobuf wire-format; content
    **best-effort**, structural guaranteed (§8).
  - **Structural `grpc` module** (`structural()=true`): size/field/depth/compressed/malformed → `Reject`;
    `[modules.grpc]` default OFF; `on_compressed: reject|passthrough`. **Normalizer hook**: protobuf
    leaves → `derived_decoded` → content modules (§6). **Bug caught**: for a binary body
    `body_str_values` cannot see the leaf → push it to derived ALWAYS.
  - **Datapath**: `forward_to_backend` → **dedicated** h2c client (`http2_only`, not a global flag) +
    trailer relay (`collect_with_trailers`/`FramedBody`) + `te: trailers`; non-gRPC = the unchanged h1 path.
  - Re-gate: **validation 10/10** (4 corpus cases: SQLi-in-field→sqli [paletto B], benign-field,
    **benign nesting→Clean** [paletto A], depth-bomb→Reject), clippy `-D warnings` clean. Tests: parser 9
    units + `waf-detection/tests/grpc.rs` 12 (module + §6 content) + `waf-proxy/tests/grpc.rs` 2 e2e
    (forward+trailer both ways; SQLi-in-field→403). **Streaming + h2-TLS backend = declared deferrals.**

---

## 12. Development conventions

- One task = one module/feature with its tests (test-first where possible).
- Atomic commits per phase.
- Update this file when an interface or an architectural choice changes.
- Review/refactor at the end of every phase before proceeding.
- **A new detection vector ⇒ a new corpus case** (§10), at the same time: a `Triggers` for the
  rule and, if you narrow a pattern for an FP, the corresponding `Clean`/trap. Test-first extends
  to the corpus, not only to the module unit tests.

---

## 13. Robustness: fuzzing, ReDoS, differential (Phase 8)

Three distinct fronts, not to be confused:
1. **Fuzzing of the parsers/normalizers** → zero panics, zero hangs on hostile input.
2. **ReDoS** → every regex time-bounded on adversarial input.
3. **Differential canonicalization** → normalization ≡ a reference oracle.

### Canonicalization-vs-freeze policy (cornerstone)

Triage a divergence by **exploitability** (threat-model = the backend's interpretation):
- **Robustness bug** (panic/hang/OOB/overflow) → immediate fix; does not change *which* rules
  match, no conflict with the freeze.
- **EXPLOITABLE canonicalization divergence** (the WAF sees a benign canonical while the backend
  derives a payload, or vice versa) → **fix even if it moves the canonical**, as a **conscious,
  documented unlock** of the freeze: P1/P2/P3 are re-run and declared green. The finding becomes
  a **permanent regression test** (the minimized input of the old bypass + an assert that it is
  now neutralized).
- **NON-exploitable divergence** → document + schedule, freeze maintained.
Every divergence carries the exploitable/non classification written in the finding (it is a
security judgment, revisable in the future).

### Toolchain and placement

- **proptest** (pure Rust, nightly-free): invariants **always-on in `cargo test`**,
  cross-platform — the net a dev sees at every commit.
- **cargo-fuzz/libFuzzer + ASan/UBSan** (nightly, Linux/CI): coverage-guided depth, finds
  OOB/overflow/hang that proptest in safe-Rust does not generate. The `fuzz/` crate **excluded
  from the workspace** (it does not break `cargo build/test --workspace` on a stable/Windows
  toolchain).
- **Crash → minimized (`cargo fuzz tmin`) → a permanent regression test** in the owning crate's
  suite (the P1 corpus model).

### Target inventory: custom vs lib

Fuzzed because they are **our code** (9 custom parsers in `waf-normalizer`):
percent-decode/`canonicalize_value`, multipart, `normalize_path`/`resolve_path`, `parse_query`,
`flatten_json` (recursion), cookie, form-urlencoded, `graphql_lex` (8th, Phase 11), `grpc_extract`
(9th, gRPC framing + protobuf wire-format, gRPC phase). **Delegated to libs** (out of scope, trust
in the lib): NFKC → `unicode-normalization`; JSON parse → `serde_json`; header/request-line
parsing **and chunked transfer-decoding** → **hyper/`http`** (we receive already-parsed headers
and an already-collected body via `collect().await`). ⚠️ **Explicit trust boundary on hyper**:
the transport-layer robustness is delegated; if one day something of the transport were parsed
by hand, that target re-enters scope.

> **Methodological note** (the lesson of #3): **untargeted** generators give coverage, **biased**
> generators give detection. Only the **bite-test** distinguishes which of the two is biting —
> e.g. with the `..` resolver deliberately broken, the property over arbitrary input stayed green
> while the one biased toward `..` went red.

### The differential equivalence relation (percent-decode)

It is not a global equality (our canonicalize does more: 2 conditional passes + NFKC):
- **(A)** single-pass decode == the independent oracle, **byte-exact**.
- **(B)** the canonical is a **fixed-point of NFKC** (proof that NFKC is applied).
- **(C)** vs `decode_until_stable`, the divergence is **characterized**: EXACTLY the set of
  **>2-encoded** inputs (e.g. `%252527` → us `%27`, stable → `'`). The "2 passes" bound (§6) is
  itself under test (`>2` witnesses that MUST diverge). The **overlong UTF-8** (`%C0%AE`) is
  neutralized to the replacement char (lossy) — a documented WAF-vs-backend residual, not a
  WAF-vs-oracle divergence.

### ReDoS: the engine's reality

The engine is the **`regex`** crate (finite automata, **guaranteed linear time**, no
backtracking) — **backtracking-ReDoS is impossible by construction**. Patterns all `&'static`
(no regex from input → no DoS in compilation), input bounded by the defensive limits. So the
ReDoS test does **not** look for catastrophic backtracking but is: (1) an **anti-regression
guard** against the future introduction of a backtracking engine; (2) a check of the **linear
scaling of the COMPOSITION** (45 regex × large input × per-field prefilter scan — super-linearity
arises from the aggregate, not from a single regex). **Budget = a test assert, NOT a runtime
guard** (a sync CPU-bound match is non-cancellable + linearity with bounded input ⟹ a runtime
timeout is unnecessary; `upstream_timeout_ms` covers the round-trip, not the inspection).
**Explicit review trigger**: revisit ONLY if regex-from-input or a backtracking engine is
introduced.

### On-record notes (declared policy boundaries)

- **Cookies not canonicalized in `parse_cookies_limited`**: it only does split+trim; the
  canonicalization is downstream (`canonicalize_value(_, false)`, **literal** `+`, RFC 6265).
  Intentional (cookie names = restricted tokens).
- **Form body: strict `from_utf8` → empty** (all-or-nothing) on invalid UTF-8 — a policy
  **opposite** to the value canonicalizer (#1/#3, lossy→replacement). A single invalid byte drops
  the whole body (never partial parsing of the valid prefix = anti-smuggling).

### Discipline and status

Every guard is proven with the **bite-test**: an injected bug → property/witness red → restore
green (an oracle never seen to fail is hope, not a guarantee). **Status**: 7/7 targets covered;
proptest cross-platform **green**; sanitizer batch **green** (no crash in the explored budget;
long fuzzing scheduled in CI); **0 real findings**.

> **Known codebase anti-pattern — "a test that does not exercise the path it thinks it tests"**
> (a property of the codebase, not bad luck: 3 instances). A test stays **green for the wrong
> reason** when the traffic does not reach the path under test, or when the assertion is satisfied
> by a different path. Recurring structural roots here: (1) the **prefilter** (§7) skips inspection
> on benign → fault-injection on non-**candidate** traffic never reaches the modules; (2)
> **detection-only** makes the response 200 regardless of protection → a test in detection-only
> does not distinguish protection-active from protection-fallen. Instances: `prop_path_invariants`
> green with the `..` resolver broken (Phase 8, arbitrary input does not generate `/../`);
> `integration.rs` panic never reached (the prefilter skips the benign, Phase 9 smoke);
> `reload_invalid_keeps_old_config` 200-either-way (detection-only, Phase 9 b). **The only reliable
> detector = the bite-test** (break the path → the test MUST go red; if it stays green, it was
> testing nothing). **Operational rule**: fault-injection/measurement on **candidate** traffic + an
> assertion that *changes* between ok-path and broken-path (e.g. blocking 403-vs-200, atomic counter),
