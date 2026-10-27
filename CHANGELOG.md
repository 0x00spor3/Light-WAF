# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/) — from 1.0.0 the public API (`WafModule`,
`StateStore`, `TlsCertSource`, `ProxyBuilder`, the config schema) is covered by it.

## [1.0.0] — 2026-10-27

The first release of Light WAF as a single open-source project: the core and the components
(previously a separately licensed repository) now live in one workspace, under one license, on
one version.

### Changed

- **One repository, one workspace.** The 12 component crates (distributed state, managed TLS,
  threat intel, curated CRS content, advanced detection modules, signed WASM plugins, request
  capture, control plane, governance, node agent, operator, the `waf-enterprise` binary) joined
  the 7 core crates in this workspace. Components depend on the core by path; their git history
  is preserved.
- **License.** The components were relicensed from the Business Source License 1.1 to
  **Apache-2.0**. The whole repository is now Apache-2.0 (see `NOTICE`).
- **Versioning.** All 19 crates, the Helm charts and the container images share one version,
  starting at 1.0.0 (the core was at 0.5.4, the components at 0.1.0).
- **Contributions** use a Developer Certificate of Origin sign-off (`git commit -s`) instead of
  a Contributor License Agreement.
- `BOUNDARY.md` now describes an architectural boundary (core vs components and the seams
  between them) rather than a commercial one.
- **Renamed before their first publication:** `waf-modules-premium` → **`waf-schema-enforcement`**
  (GraphQL/gRPC schema enforcement, OpenAPI positive security, bot detection) and
  `waf-marketplace` → **`waf-wasm-signing`** (minisign verification of WASM plugins). Config
  tables (`[enterprise.*]`) are unchanged.

### Published on crates.io

- Core: `waf-core`, `waf-normalizer`, `waf-pipeline`, `waf-detection`, `waf-wasm`, `waf-proxy`
  (binary `waf`).
- Components (new on crates.io): `waf-state-redis`, `waf-tls-managed`, `waf-threatintel`,
  `waf-crs-curated`, `waf-capture`, `waf-schema-enforcement`, `waf-wasm-signing`, and the
  `waf-enterprise` binary.
- Not published (`publish = false`), shipped as container images and Helm charts instead:
  `waf-controlplane`, `waf-governance`, `waf-node-agent`, `waf-operator`. The control plane embeds
  a dashboard built by npm, which a crates.io build cannot reproduce. `waf-corpus` (the validation
  corpus) stays unpublished as before.

### Removed

- The `waf-license` crate and the `demo-license` feature of `waf-enterprise`,
  `waf-controlplane` and `waf-node-agent` (signed, time-limited demo builds). Every build is now a
  full build.

### Security

- The `waf-controlplane` Helm chart no longer ships well-known default credentials. An empty
  `secrets.apiToken`, `secrets.bootstrapAdminPassword` or `postgres.bundled.password` is
  generated randomly on first install and reused on upgrade; the bundled Postgres password moved
  from an inline env value to a Secret. The install notes print how to retrieve generated values.
- Dashboard dependencies updated to patched versions (`vite` 6.4.5, `postcss` 8.5.32,
  `react-router` 6.30.6, and transitive packages).
- `chacha20` updated from 0.10.1, which was yanked from crates.io, to 0.10.2 (pulled in through
  the DNS resolver used by ACME DNS-01).
- Container images: CVE-2026-84782 (`libssl3` in the distroless base) is accepted until
  2026-11-16 with a documented justification in `.trivyignore` — no shipped binary links OpenSSL,
  and nothing uses DTLS.
- Added `SECURITY.md` with a private reporting channel.

### Fixed

- A flaky TLS integration test in `waf-proxy`: parallel tests could generate the same temporary
  certificate file names and overwrite each other's key pair.
- The `waf-operator` CRD drift test failed on Windows checkouts (CRLF line endings).
- New `clippy::double_must_use` findings (Rust 1.99) on two `#[async_trait]` traits.

## Before 1.0

The core crates were published on crates.io as 0.1.0 through 0.5.4; the components were
unreleased. See the git history and the crates.io release pages for those versions.
