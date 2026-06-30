# Light WAF (Layer 7)

[![CI](https://github.com/0x00spor3/Light-WAF/actions/workflows/ci.yml/badge.svg)](https://github.com/0x00spor3/Light-WAF/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/waf-proxy.svg)](https://crates.io/crates/waf-proxy)
[![docs.rs](https://img.shields.io/docsrs/waf-core)](https://docs.rs/waf-core)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

A Web Application Firewall in **Rust** operating as a **reverse proxy** at Layer 7: it
inspects every HTTP request, applies detection rules, accumulates an **anomaly score**
(CRS-style model), and decides **Allow / Block (403) / Reject (400 | 429)** before
forwarding to the backend.

Goals: *light* (few dependencies), *fast* (< 1 ms p99 on the common path), *modular*
(every detection is a plugin toggled from config), *observable* (structured JSON logs),
*secure by design* (explicit per-scenario fail-open / fail-closed).

---

## Capabilities

| Detection | Surface | Notes |
|---|---|---|
| SQLi, XSS, LFI/RFI, SSRF | body/query/cookie | regex content-inspection on canonicalized data |
| RCE/Cmd-inj | path + body/query/cookie | command injection (incl. in the URL path), expression-language `${@print(…)}`/SpEL, **VBScript/ASP** webshell (`On Error Resume Next`, `Server.*`, `CreateObject`) |
| SQLi (MSSQL proc) | body/query/cookie | OS-exec stored procedures `xp_cmdshell`/`sp_oacreate`/… invocation-anchored (no FP on prose) |
| LDAP, NoSQL, Mail (SMTP/IMAP), SSTI | body/query/cookie | per-category injection, unambiguous signatures → Critical |
| SSI (Server-Side Includes) | body/query/cookie | `<!--#exec\|include\|printenv\|…` directive → Critical |
| XXE (XML External Entity) | body/query/cookie | `<!ENTITY` / `<!DOCTYPE…SYSTEM` / `encoding="UTF-7"` / external-schema (`xs:include namespace=`, single-URL `xsi:schemaLocation`) → Critical |
| Scanner / tool fingerprint | User-Agent | sqlmap/nuclei/OpenVAS/ffuf/… + OOB domains (Collaborator/interactsh/oast) |
| Path traversal | request_line | path + query/cookie/body |
| Header injection (CRLF) | path + headers/query/cookie/body | field-aware (per-rule scope); CRLF smuggled in the URL path |
| Request smuggling (CL/TE) | connection | structural framing validation → 400 |
| GraphQL (structural) | body (JSON / `application/graphql` / GET `?query=`) | DoS/abuse caps on the operation shape — depth / aliases / fields / directives / batch → 400, introspection → 403; opt-in per endpoint |
| gRPC (structural) | body (`application/grpc*`, HTTP/2) | de-frames the protobuf body → fields inspected by the content modules (§6); structural caps (message size / field count / nesting depth) + compressed-payload policy → 400; opt-in. Forwards h2c with trailer relay (unary) |
| Rate limiting L7 | connection | token bucket per resolved IP |

Plus: anti-evasion normalization (double-encoding-aware percent-decode + NFKC +
pipeline-wide overlong-collapse + **multi-transform derived channel**
`decode-then-match-then-discard`: base64, evasion HTML-entity decode, mid-token
tag-strip/control-strip, VBScript-concat de-obf — also composed over the base64 variants),
configurable cumulative anomaly scoring, paranoia levels (PL1–4), external config with hot
reload (SIGHUP, Unix), trusted-proxy client-IP resolution, **TLS termination** (rustls,
cert-from-file; one port serves HTTP/1.1 **and** HTTP/2 via ALPN/`auto`; opt-in `[tls]`,
fail-closed — no cleartext downgrade), and a **fast-path** that skips inspection on provably
benign traffic (equivalence tested).

**Extensibility & observability** (all OPEN, all default-off — see `BOUNDARY.md`):

- **WASM plugins** — a [Proxy-Wasm](https://github.com/proxy-wasm/spec) runtime on `wasmi`
  loads `.wasm` filters as modules without forking the core (`[modules.wasm]`); instance pool,
  per-request fuel/memory DoS caps, fail-closed. See [`examples/wasm-plugin/`](examples/wasm-plugin/).
- **OWASP CRS / ModSecurity import** — a `seclang` parser + subset evaluator runs imported
  `SecRule` files as a module (`[modules.crs]`), with a boot skip-report for unsupported directives.
- **Prometheus metrics** — opt-in `/metrics` export on a separate loopback listener (`[metrics]`).

---

## Workspace layout (7 crates)

```
waf-core ────────┐ (base types, no internal dependencies)
   ▲   ▲   ▲  ▲   │
   │   │   │  │   ▼
   │   │   │  └── waf-normalizer   (Phase 2: decode + NFKC + parsing + limits)
   │   │   └───── waf-pipeline     (phased orchestrator + anomaly scoring)
   │   └───────── waf-detection    (modules/rules + ContentPrefilter fast-path)
   └───────────── waf-wasm         (Proxy-Wasm runtime on wasmi; loads .wasm filters as modules)
                   ▲
         ┌─────────┴──────────┐
   waf-proxy (the binary)   waf-corpus (validation/tuning/fast-path: lib + tests + examples)
```

| Crate | Role |
|---|---|
| **waf-core** | `Config`, `Decision`, `RequestContext`, `Severity`, `Normalized`; client-IP resolution; `testkit` (test builders, behind a feature) |
| **waf-normalizer** | Phase 2: percent-decode (double-encoding-aware), NFKC, query/cookie/body parsing, defensive limits |
| **waf-pipeline** | `Pipeline`: runs modules per phase, accumulates the score, decides the verdict |
| **waf-detection** | The modules with their `*_RULES` tables; `ContentPrefilter` (scope-aware fast-path) |
| **waf-wasm** | Proxy-Wasm runtime on `wasmi`: loads `.wasm` filters as `WafModule`s (instance pool, fuel/memory DoS caps, fail-closed); `[modules.wasm]`, default off |
| **waf-proxy** | The **binary**: hyper/tokio reverse proxy, config loading, fail-open/closed, hot reload |
| **waf-corpus** | The 260 validation cases + runner + metrics. **Not** in production: it is the evidence (oracle) tool |

### Request flow (`waf-proxy/src/lib.rs::handle`)

1. **`build_context`** — resolves the real client IP (trusted-proxy / `X-Forwarded-For`).
2. **`run_connection`** — rate limit + request smuggling, **before** parsing → can reject
   429/400 without paying for normalization.
3. **`normalize`** (Phase 2) — decode + NFKC + parse; limit overrun → 400 (`[resilience]` policy).
4. **Fast-path + inspection** — the prefilter decides whether *any* rule could match; if not
   it skips inspection (Allow), otherwise it runs the content modules and at `score ≥ block_threshold` → 403.
5. **Forward** to the backend, response to the client.

---

## Hardening & performance (Phases 8–9)

Phases 8–9 add **no** detection: they *prove* (don't assume) the non-functional guarantees.
Every guard is proven with a **bite-test** — break the path, the test MUST go red; if it
stays green it wasn't testing anything. Details in `ARCHITECTURE.md` §11 (performance) and
§13 (robustness). Reproduction commands: see *On-demand tools*.

**Performance — inspection latency.** The contract number is the latency that depends ONLY
on our code (`enqueue→verdict`), isolated from network and upstream:

- **~2 µs** worst-case PL3 (saturated rules) → **~500×** under the **p99 < 1 ms** contract;
- worst-case-set distribution: **p50 ~2.1 µs / p99 ~3.1 µs / p99.9 ~5.3 µs**, with no
  alloc/lock cliff; the heaviest case (`ssrf-cloud-metadata`, 3 rules) crowns the p99;
- **`max` (~97 µs) is NOT the contract**: it's OS scheduler jitter, not a property of the
  code (proven by the fact that the heaviest case crowns the **p99**, not the `max`);
- the CI gate is **relative** on the pinned single case (`inspect_worst_case_pl3`), **not**
  on the aggregate nor the `max`: it catches regressions without the noise of an absolute on
  a shared CI (an absolute `<1 ms` on a shared runner varies 3–10× → noise).

**Resilience — what the WAF does when *it* is the one in trouble** (per-scenario
`[resilience]` policy, §9), all proven end-to-end and with the bite-test:

- **kill-upstream** → declared 502/503, and the WAF **still inspects** — an attack is blocked
  *before* the dead upstream (upstream down ≠ WAF bypass);
- **corrupt-reload** → validate-then-swap: an invalid config is **rejected**, the last-good
  stays active, **no unprotected window**;
- **panic in a module** → isolated (`catch_unwind`): `fail_open` skips **only** the broken
  module (the others run), `fail_closed` → deny. Default **`fail_open`** (*additive* control:
  a bug of ours must not lower availability below the no-WAF baseline).

**Validation — the basis of trust** (Phase 7, §7/§10). Detection is **frozen** and measured
by a versioned corpus (`waf-corpus`): **260 cases**, **100% detection-recall** on the
tracked-malicious cases and **0% false positives** at PL3 (the few documented `ExpectedMiss`
deferrals aside). Weights and threshold (config **C2**: `critical=6`, `block_threshold=5`)
are justified by the corpus evidence, not inherited. NB **detection-recall** (a rule matches)
is distinct from **blocking-recall** (`score ≥ threshold`).

**Robustness (Phase 8, §13).** Fuzzing of the 9 custom parsers (cargo-fuzz/ASan, Linux/CI) +
always-on cross-platform **proptest** invariants; ReDoS **impossible by construction**
(linear-time `regex` engine, no backtracking); differential canonicalization against an
independent oracle. **0 real findings.**

**Test quality — a principle, not a detail.** There is a known class of anti-pattern (§13):
*a test that doesn't exercise the path it thinks it tests* — green for the wrong reason,
because the traffic isn't **candidate** (the fast-path skips benign) or because the assertion
is satisfied by a different path. **The only reliable detector = the bite-test.**
Fault-injection measurements run on **candidate** traffic, with assertions that *change*
between ok-path and broken-path (403-vs-200, atomic counter), never a green/200 that a second
path could produce.

**Waiting on the ENVIRONMENT (not the work).** The harnesses are built and *known-correct*
(proven by the green candidacy bite); only **where** to measure is missing:

- **e2e overhead curve** (1k/5k/10k RPS) → `oha` on a **quiet** box. In-process over loopback
  the ~µs inspection signal is **below the e2e noise floor** (~344 µs of jitter):
  `examples/load_overhead` shows it honestly (even a negative delta = the sanity-check firing)
  — the e2e **is not and never was** the contract, which remains the isolated (a)/(d);
- **CI pipeline wiring** of the regression gate → git/CI environment;
- **absolute `< 1 ms` e2e assertion** → pinned hardware (never on shared CI).

---

## Requirements

- **Rust** stable (toolchain with `cargo`).
- To see the proxy actually working you need a **backend** listening on the address in
  `config.toml` (`backend = "http://127.0.0.1:3000"`).

## Build

```sh
cargo build              # debug
cargo build --release    # optimized
```

## Run

The binary is `waf-proxy`. Config path precedence: `--config` > env `WAF_CONFIG` > `config.toml`.

```sh
# uses ./config.toml by default
cargo run -p waf-proxy

# explicit config
cargo run -p waf-proxy -- --config /path/to/mine.toml
```

```powershell
# PowerShell: via env var, or raising the log level (JSON, default "info")
$env:WAF_CONFIG = "E:\path\to\mine.toml"; cargo run -p waf-proxy
$env:RUST_LOG = "debug"; cargo run -p waf-proxy
```

Notes:

- The **default** (`config.toml`) listens on `0.0.0.0:8080`, forwards to `127.0.0.1:3000`,
  in **`mode = "detection-only"`** (logs but does not block). To block: `mode = "blocking"`.
- Invalid config or missing file → message on **stderr** + **exit code 2** (fail-fast).
- **Hot reload via SIGHUP** is `#[cfg(unix)]` → not available on Windows (the validate-then-swap
  logic stays tested separately).
- Quick test (with a backend on :3000):
  ```sh
  curl "http://localhost:8080/?q=1%20UNION%20SELECT%20pass%20FROM%20users--"
  ```
  and watch the decision log.

## Tests

```sh
cargo test --workspace                       # the whole suite (unit + integration)
cargo test -p waf-detection                  # a single crate
cargo test -p waf-corpus --test validation   # the oracle (recall/FP + ladder + fast-path equivalence)
cargo clippy --workspace --all-targets       # lint (must be clean)
```

## On-demand tools (runnable reports, not CI tests)

The `waf-corpus` examples produce the Phase 7 evidence:

```sh
cargo run -p waf-corpus --example report      # recall/FP per module + score-distribution + overlap
cargo run -p waf-corpus --example coverage     # rule → case(s) → min_pl map
cargo run -p waf-corpus --example tuning       # config sweep thresholds × paranoia (margins)
cargo run --release -p waf-corpus --example fastpath_bench   # fast-path benchmark
```

Performance and resilience (Phases 8–9):

```sh
cargo bench -p waf-corpus                                          # inspection microbench (criterion); baseline ~2µs
cargo run --release -p waf-corpus --example latency_distribution   # worst-case-set distribution: p50/p99/p99.9/max
cargo run --release -p waf-proxy  --example load_overhead          # e2e smoke WAF vs passthrough (candidacy bite; e2e informative, not the contract)
```

Relative regression gate (DEC 4) — two-run workflow on the **same** runner (baseline pinned
on the base commit, comparison on the candidate), then the gate exits `1` on regression
beyond threshold:

```sh
cargo bench -p waf-corpus --bench inspection -- --save-baseline pinned   # on the base commit
cargo bench -p waf-corpus --bench inspection -- --baseline pinned        # on the candidate
cargo run  -p waf-corpus --example regression_gate                       # relative PASS / FAIL (ignores max and aggregate)
```

> The resilience guarantees (kill-upstream, corrupt-reload, panic isolation) and robustness
> (parser proptests) run in the normal suite: `cargo test --workspace`. Coverage-guided
> fuzzing (`fuzz/`, cargo-fuzz + ASan) is nightly/Linux, excluded from the workspace to avoid
> breaking stable/Windows builds.

---

## Configuration

`config.toml` (self-documented, every section commented) collects: `[proxy]` (listen/backend),
`[waf]` (mode, `block_threshold`, `paranoia_level`, `severity_scores`), `[resilience]`
(per-scenario fail-open/closed), `[rate_limit]`, `[network]` (trusted-proxy), `[limits]`,
`[modules.*]` (enable/disable each detection). Schema detail and defaults in
`ARCHITECTURE.md` §9.

## Where to read the code

- `crates/waf-proxy/src/lib.rs` → `handle()` for the end-to-end flow.
- `crates/waf-pipeline/src/lib.rs` → score accumulation and verdict.
- `crates/waf-detection/src/<module>.rs` → each module's rules (`*_RULES`).

---

## License

Light WAF is open source under the **Apache License, Version 2.0** — see
[`LICENSE`](LICENSE) and [`NOTICE`](NOTICE). The open-source vs. enterprise boundary
(what is core vs. paid, and why) is normatively documented in [`BOUNDARY.md`](BOUNDARY.md).

## Contributing

Contributions are welcome. Every commit must be signed off under the
[Developer Certificate of Origin](https://developercertificate.org/) (`git commit -s`), and
contributors accept the [Contributor License Agreement](CLA.md) — which lets the project be
offered under both its open-source license and its enterprise license. See `BOUNDARY.md` §6
for the governance rationale.
