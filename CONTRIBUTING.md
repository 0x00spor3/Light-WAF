# Contributing to Light WAF

Thanks for helping. Bug reports, false-positive reports, detection improvements, docs and code
are all welcome. Everyone taking part is expected to follow the
[Code of Conduct](CODE_OF_CONDUCT.md).

- **Security issues** (including detection bypasses) go through the private channel in
  [`SECURITY.md`](SECURITY.md), never a public issue.
- **False positives**: open an issue with the request (redact anything sensitive), the paranoia
  level and mode, and the rule ids from the decision log.
- **Larger changes**: open an issue first so we can agree on the approach — especially anything
  that touches a public trait, the config schema or the core/component boundary.

## Repository layout

One Cargo workspace, 19 crates under `crates/`. The **core** (datapath) and the **components**
(distributed state, managed TLS, control plane, governance, operator, …) are described in
[`BOUNDARY.md`](BOUNDARY.md), which also says where a new feature belongs. Read it before adding a
feature: components use only the core's public seams, and the core never depends on a component.

| Path | What |
|---|---|
| `crates/` | all Rust crates |
| `crates/waf-controlplane/ui/` | the dashboard (React + Vite + TypeScript) and its Playwright E2E suite |
| `examples/` | ready-to-adapt configs, a WASM plugin example |
| `charts/`, `deploy/` | Helm charts, operator manifests, GitOps examples |
| `scripts/` | per-feature runbooks and check scripts, image build/scan, kind E2E |
| `docs/` | the operator guide |
| `fuzz/` | cargo-fuzz targets (nightly, Linux; excluded from the workspace) |

## Development setup

- **Rust** stable (CI uses the latest stable; run `rustup update`).
- **Docker**, for the Postgres/Redis integration tests and the image builds.
- **Node.js 22**, only if you touch the dashboard.

```sh
cargo build --workspace
```

## Before you open a pull request

CI runs these; please run them locally first.

```sh
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

The codebase is not normalized with `rustfmt` yet: match the style of the surrounding code, and do
not run `cargo fmt` over files you are not otherwise changing (it would bury your change in an
unrelated diff).

**Integration tests.** Tests that need Postgres or Redis are skipped unless their environment
variables are set. To run them as CI does:

```sh
docker run -d --name waf-pg -e POSTGRES_PASSWORD=postgres -p 5432:5432 postgres:16
docker run -d --name waf-redis -p 6379:6379 redis:7
export WAF_CP_DATABASE_URL=postgres://postgres:postgres@localhost:5432/postgres
export WAF_REDIS_URL=redis://localhost:6379
cargo test --workspace
```

**Dashboard.** If you change `crates/waf-controlplane/ui/`:

```sh
cd crates/waf-controlplane/ui
npm ci
npm audit --audit-level=high
npm run e2e        # builds the UI + a release control plane, then runs Playwright (needs WAF_CP_DATABASE_URL)
```

**Charts.** If you change `charts/`: `helm lint charts/<chart>`.

**Fuzzing** (optional, nightly + Linux): `bash run_fuzz.sh`.

## Guidelines

- **Detection changes need evidence.** Add the attack (and, if relevant, a near-miss benign
  request) to the `waf-corpus` cases and keep `cargo test -p waf-corpus --test validation` green:
  the corpus is what proves recall and the false-positive rate. Explain the paranoia level and
  severity you chose.
- **New functionality comes with tests.** A pull request that adds a feature or fixes a bug also
  adds tests for it to the automated suite (`cargo test`, or the Playwright E2E for the dashboard),
  which CI runs on every pull request.
- **Tests must bite.** A test should fail when the code path it protects is broken. Use traffic
  that actually reaches the path (the fast-path skips benign requests) and assertions that differ
  between the working and the broken behavior.
- **Public API is SemVer-stable** (1.0 onward). Extend traits and the `ProxyBuilder` additively,
  with defaults — see [`BOUNDARY.md`](BOUNDARY.md) §5.
- **New config** is default-off, documented in the commented example config, and validated at
  load time.
- **New source files** carry the SPDX header (`bash add-spdx.sh` adds it).
- Keep pull requests focused; one logical change per PR.

## Sign-off (Developer Certificate of Origin)

Contributions are accepted under the project license, **Apache-2.0**. Every commit must be signed
off under the [Developer Certificate of Origin](https://developercertificate.org/), certifying
that you wrote the change or otherwise have the right to submit it under that license:

```sh
git commit -s -m "Describe the change"
```

This adds a `Signed-off-by: Your Name <you@example.com>` trailer. To sign off commits you already
made: `git rebase --signoff main`.
