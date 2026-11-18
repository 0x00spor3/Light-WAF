# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

Light WAF: a Layer-7 Web Application Firewall in Rust, running as a reverse proxy. One Cargo
workspace (19 crates under `crates/`), all crates versioned in lockstep (`[workspace.package]`).

## Commands

```sh
cargo build --workspace
cargo clippy --workspace --all-targets -- -D warnings      # CI gate (CI also sets RUSTFLAGS=-D warnings)
cargo test --workspace                                     # CI gate
cargo test -p waf-corpus --test validation                 # detection oracle: recall / FP / fast-path equivalence
cargo test -p waf-detection sqli                           # one crate, tests whose name matches a filter
cargo test -p waf-proxy --test <file_stem> -- <test_name>  # one integration test

cargo run -p waf-proxy -- --config examples/balanced.toml  # run the core WAF (default ./config.toml, or env WAF_CONFIG)
cargo run -p waf-corpus --example report                   # recall/FP per module, score distribution, overlaps
```

- Postgres/Redis integration tests skip silently unless `WAF_CP_DATABASE_URL` /
  `WAF_REDIS_URL` are set (see `CONTRIBUTING.md` for the `docker run` lines CI mirrors).
- Dashboard (`crates/waf-controlplane/ui`, React + Vite + TS, Node 22): `npm ci`, `npm run build`
  (tsc + vite), `npm run e2e` (builds UI + release control plane with `--features embed-ui`, then
  Playwright; needs `WAF_CP_DATABASE_URL`).
- Charts: `helm lint charts/<chart>`.
- `fuzz/` is excluded from the workspace (nightly + Linux only): `bash run_fuzz.sh`.
- Perf regression gate (relative, same machine): see "Building and testing" in `README.md`.

## Conventions that are easy to get wrong

- **Do not run `cargo fmt`** across files: the codebase is not rustfmt-normalized. Match the
  surrounding style and keep diffs scoped to the change.
- New source files need the SPDX header (`bash add-spdx.sh`).
- Commits are signed off (`git commit -s`, DCO).
- New config is default-off, documented in the commented example config (`config.toml` /
  `examples/`), and validated at load time. `Config` and a few sub-configs are
  `#[non_exhaustive]` — see `BOUNDARY.md` §5 before changing config structs.
- Public ABI (`WafModule`, `StateStore`, `TlsCertSource`, `ProxyBuilder`) is SemVer-frozen:
  extend only with new methods that have default bodies.
- Every new feature must be placed (CORE / COMPONENT / SPLIT) in `BOUNDARY.md` before merge.
- Tests must "bite": they must fail if the protected path is broken. Benign-looking traffic is
  skipped by the fast-path prefilter, so a detection test needs input that actually reaches the
  module.
- Hot reload (SIGHUP) is Unix-only; development also happens on Windows, so don't assume it.

## Architecture

### Core vs components (`BOUNDARY.md` is normative)

- **Core** (`waf-core`, `waf-normalizer`, `waf-pipeline`, `waf-detection`, `waf-wasm`,
  `waf-proxy` → binary `waf`, `waf-corpus`): the self-sufficient single-node datapath. It
  **never depends on a component**.
- **Components** (Redis state, managed TLS/ACME/mTLS, threat intel, curated CRS, schema
  enforcement, WASM signing, capture, governance, control plane, node agent, operator) use only
  the core's public seams. "enterprise" in names (`waf-enterprise`, `[enterprise]` config) just
  means the component layer; old docs also say OPEN = CORE.
- Components plug in via `Proxy::builder(&config)` seams: `.state_store(..)`,
  `.cert_source(..)`, `.module_factory(..)`. Use `.module_factory` for injected modules —
  `.modules(..)`/`.add_module(..)` are dropped on reload. `waf-enterprise/src/main.rs` is the
  reference wiring.
- If a component needs a seam the core lacks, add the seam to the core first (additively).
- `waf-controlplane` does not link `waf-core`; it consumes the telemetry contract (JSON decision
  log + Prometheus). `waf-node-agent` writes the managed SecRule `.conf` and triggers the WAF's
  own reload, pre-validating with the core seclang parser.

### Request flow (`crates/waf-proxy/src/lib.rs::handle`)

`build_context` (client IP via trusted proxies) → `run_connection` (rate limit + smuggling,
before parsing → 429/400) → `normalize` (decode + NFKC + parse; limit overrun → 400) →
`Pipeline::run_inspection_gated` (prefilter skip, else modules run; `score ≥ block_threshold` →
403) → forward. `mode = "detection-only"` logs but never blocks.

### Modules and scoring

- `WafModule` (`waf-core`): `id`, `phase`, `init` (compile rules once, filter by paranoia level),
  `inspect(&RequestContext) -> Decision`. Modules report `rule_id` + `Severity`; **only the
  pipeline** converts severity → points (`[waf.severity_scores]`) and accumulates the score.
  Module panics are isolated with `catch_unwind` and handled per `[resilience]` fail-open/closed.
- Each detection module in `waf-detection/src/<name>.rs` has a static `*_RULES` table.
  `ContentPrefilter` (`waf-detection/src/lib.rs`) builds a `RegexSet` union from those same
  tables, so the fast path can't drift from the rules. It must stay sound: never add a cheaper
  pre-check that could skip a request a rule would match (`ARCHITECTURE.md` §7).
- Built-in modules are instantiated from config in `build_modules` (`waf-proxy/src/lib.rs`);
  the corpus runner has its own module list (`waf-corpus/src/runner.rs`). A new module has to be
  wired into `build_modules`, the config (`waf-core`), and the corpus runner, and a new *content*
  module's rules into the prefilter. Structural modules (`graphql`, `grpc`, override
  `structural()`) run outside the prefilter.
- Regexes use the linear-time `regex` crate; ReDoS-safety relies on that (no backtracking engines).

### Detection evidence (`waf-corpus`)

The corpus is the proof of recall and false-positive rate. Cases are static Rust tables in
`crates/waf-corpus/src/cases/<module>.rs` (`Triggers` / `Clean` / `ExpectedMiss`, with `min_pl`
and expected rule ids), built from raw pre-normalization fields via the `waf-core` `testkit`
feature and run through the real `Normalizer` + pipeline at PL3. **Any detection change needs a
corpus case** (the attack, plus a benign trap if a pattern was narrowed for an FP), and
`tests/validation.rs` must stay green. Fixed pentest findings are pinned in
`tests/*_report_regression.rs`.

Canonicalization changes are frozen by default; an exploitable WAF-vs-backend divergence is the
exception and must become a permanent regression test (`ARCHITECTURE.md` §13).

## Further reading

`ARCHITECTURE.md` (core design: pipeline, normalization §6, scoring §7, operability §9),
`ARCHITECTURE_ENTERPRISE.md` (components), `docs/` (operator guide), `scripts/*/RUNBOOK.md`
(per-feature manual checks).
