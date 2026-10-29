# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/) — from 1.0.0 the public API (`WafModule`,
`StateStore`, `TlsCertSource`, `ProxyBuilder`, the config schema) is covered by it.

## [Unreleased]

### Added
- SLSA build provenance on GitHub Releases: `light-waf-<version>.intoto.jsonl` covers every release
  asset, made by the official SLSA generator in the release-assets workflow.
- `osv-scanner.toml`: the three advisories that do not affect Light WAF (`rsa`, `crypto-bigint`,
  `block-buffer`, see 1.0.2) are ignored with their reasons, each until 2027-04-30.

### Removed
- Build output that had been committed by mistake: the `target/` folders of the WASM test fixture
  and of the WASM plugin example. `.gitignore` now ignores `target/` at every level.

## [1.0.2] — 2026-10-29

A supply-chain and dependency release. Images, charts and release assets are now signed and come
with complete SBOMs. The vulnerable and unmaintained dependencies found by an OSV scan are
upgraded or replaced. The repository is graded by OpenSSF Scorecard, analysed by CodeQL and
fuzzed continuously. Detection and the public API are unchanged.

### Added

- `bench/`: a reproducible end-to-end benchmark, run with one command, against no WAF and
  ModSecurity + OWASP CRS. It measures added latency, throughput, memory and gotestwaf detection,
  for the default and the strict profile.
- Dependabot: weekly updates for cargo, the dashboard's npm packages, GitHub Actions and the
  Dockerfile base images.
- OpenSSF Scorecard (`scorecard.yml`): the repository's supply-chain practices graded weekly and on
  every push to `main`, published to the Scorecard API (README badge) and to code scanning.
- CodeQL (`codeql.yml`): static analysis of the Rust workspace, the dashboard's TypeScript and the
  workflows, with the `security-extended` queries.
- Signed container images: every published image is signed with cosign (keyless, bound to the
  release workflow's identity, logged in the Sigstore transparency log) and carries its SPDX SBOM
  as a signed attestation. `SECURITY.md` shows how to verify both.
- Signed release assets (`release-assets.yml`): each GitHub Release gets the source tarball, the
  source SBOM (every crate and npm package), the image SBOMs and `SHA256SUMS`, each with a cosign
  keyless signature bundle (`.sigstore.json`). The workflow first waits for the release's images and
  checks their signatures.
- Published Helm charts (`charts-release.yml`): on each release the `waf` and `waf-controlplane`
  charts are pushed to `oci://ghcr.io/0x00spor3/charts` and signed with cosign, so they install
  without a checkout (`helm install … oci://ghcr.io/0x00spor3/charts/waf --version …`). The charts
  carry Artifact Hub metadata (license, links, images), and the workflow pushes the Artifact Hub
  repository metadata once the repository IDs are configured.
- Continuous fuzzing with ClusterFuzzLite (`.clusterfuzzlite/`, `cflite-pr.yml`,
  `cflite-batch.yml`): the nine cargo-fuzz targets run with AddressSanitizer on every pull request
  (focused on the changed code) and for half an hour every night.

### Fixed

- The cargo-fuzz targets `query`, `form_body`, `flatten_json` and `normalize_path` no longer
  compiled against the current `waf-normalizer`/`waf-core` API (`LimitsConfig` is
  `#[non_exhaustive]`; `parse_query` and `normalize_path` return three values). `fuzz/` is not a
  workspace member, so nothing caught it; the PR fuzzing workflow now builds it on every change.
  `run_fuzz.sh` covers all nine targets.

### Changed

- CI supply chain: every GitHub Action is pinned to a commit SHA, the Dockerfile build images
  (`rust`, `node`) are pinned by digest, every workflow declares least-privilege token permissions,
  no checkout keeps the token after it (`persist-credentials: false`), and the kubeconform and kind
  downloads are checked against their published SHA-256.
- Helm charts: real maintainer, `home` and `icon` pointing at lightwaf.org. The chart lint workflow
  now fails a PR whose chart version, appVersion or listed image tags differ from the workspace
  version.
- Complete image SBOMs: the binaries are built with `cargo auditable`, which embeds their crate
  list, so each image's signed SBOM and the image scan now cover every Rust crate (the data-plane
  image: 356 crates), not just the OS packages.
- One crypto provider: `ring` only. The workspace's `tokio-rustls` no longer enables its default
  features, and the Route 53 client no longer uses the SDK's default HTTPS clients, so `aws-lc-rs`
  (C, built with cmake) is gone from the build; the data-plane image no longer installs cmake.
- Control-plane OIDC SSO: the identity-provider calls (discovery, token, JWKS) go through the
  workspace's reqwest client, which never follows redirects.

### Security

- Dependencies updated within their semver ranges (`cargo update`), which pulls in the fixes for
  hickory-resolver (GHSA-6w6g-hm98-mhgm, GHSA-5j98-2g5x-46v6, GHSA-6f2x-v7q7-m7m5), rustls 0.23
  (RUSTSEC-2026-0285, -0346, -0348, -0349), rustls-webpki 0.103 (RUSTSEC-2026-0382), h2 0.4
  (RUSTSEC-2026-0258), tokio (RUSTSEC-2026-0386), webpki-roots / webpki-root-certs
  (RUSTSEC-2026-0381, -0383), event-listener (RUSTSEC-2026-0221) and ctutils (RUSTSEC-2026-0385).
- `openidconnect` 3 → 4 in the control plane. This removes reqwest 0.11 and the old TLS stack it
  pulled in: rustls 0.21 (RUSTSEC-2026-0346, -0349, GHSA-h2v8-394m-p7vv), rustls-webpki 0.101
  (RUSTSEC-2026-0098, -0099, -0104, -0382), h2 0.3 (RUSTSEC-2026-0258), webpki-roots 0.25
  (RUSTSEC-2026-0381) and the unmaintained rustls-pemfile 1 (RUSTSEC-2025-0134).
- The Route 53 DNS-01 client uses the AWS SDK's hyper 1 client on rustls 0.23 and ring, dropping
  the SDK's legacy hyper 0.14 + rustls 0.21 client.
- `rustls-pemfile` 2 (unmaintained, RUSTSEC-2025-0134) replaced by the PEM parser of
  `rustls-pki-types` in `waf-proxy` and `waf-tls-managed`.
- Dashboard: `react-router` 6 → 7 (GHSA-wrjc-x8rr-h8h6, GHSA-337j-9hxr-rhxg).
- Still reported, not exploitable here: `rsa` (RUSTSEC-2023-0071, Marvin attack, no fixed version)
  is used by `openidconnect` only to verify RS256 signatures with public keys, while the attack
  needs private-key operations. Also still reported: `crypto-bigint` 0.5 and `block-buffer` 0.10,
  indirect dependencies of the signature crates with no fixed release in their lines, and
  `serde_yaml` (unmaintained), which comes in through `kube` in the operator.

## [1.0.1] — 2026-10-28

A packaging and deployment release: official container images, a one-command demo, and fixes to
the control-plane image and the Kubernetes deployment. The Rust crates on crates.io have no API
or behavior changes; they are republished at 1.0.1 to keep one version across the project.

### Added

- **One-command demo** (`demo/`): `docker compose up` runs the WAF, the control plane with its
  dashboard, the node agent, a log shipper and a traffic generator that mixes normal requests with
  attacks — all from the release images, nothing to build. The README opens with a short
  recording of the dashboard.
- **Container images on the GitHub Container Registry.** A release tag now publishes the four
  images — `ghcr.io/0x00spor3/waf-enterprise`, `waf-controlplane`, `waf-node-agent`,
  `waf-operator` — as multi-arch (amd64 + arm64) images tagged `<version>`, `<major>.<minor>`
  and `latest`, only after every image passes the vulnerability scan. The images carry the
  `org.opencontainers.image.source` label linking them to this repository.

### Changed

- The `waf` and `waf-controlplane` Helm charts, the operator manifests and the GitOps examples
  default to the GHCR images. Installs that set `image.repository` explicitly are unaffected.

### Fixed

- `waf-operator`: a `WafProxy` with `mode: detection` rendered `mode = "detection"` into the
  WAF config, which the WAF rejects (the value is `detection-only`), so the data-plane pods failed
  to start. The CR value is unchanged; it now renders `detection-only`. A test parses the rendered
  config with the WAF's own config type.
- `waf` chart: `waf.mode=detection` (the value the chart documented) produced the same invalid
  config. It now maps to `detection-only`; the documented values are `blocking` and
  `detection-only`.
- Docs: the observe-only mode is `detection-only`, not `detection`.
- `waf-controlplane` image: the dashboard reported version 0.1.0 and showed a "UI and API versions
  differ" banner on every page. The image build now reads the workspace version, as a source
  build does.
- Building from a Windows checkout (`core.autocrlf=true`) produced SQL migrations with CRLF line
  endings, whose sqlx checksums differ from the release builds: that control plane refused a
  database created by the release image ("migration 1 was previously applied but has been
  modified"), and the reverse. `.gitattributes` now keeps `*.sql` and `*.sh` files LF on every
  checkout (shell scripts with CRLF also fail inside Linux containers).

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
