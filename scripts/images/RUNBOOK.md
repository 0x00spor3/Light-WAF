<!-- SPDX-License-Identifier: Apache-2.0 -->
# Runbook — container images & supply-chain (K1)

K1 of the **Kubernetes-native deployment** plan. Produces the four container images the Helm
charts (K2/K3) and the operator consume, with reproducible tags, OCI provenance labels, an
SBOM, and a vulnerability scan gate. Release images are published to the GitHub Container
Registry as `ghcr.io/0x00spor3/<image>:<version>` (multi-arch: amd64 + arm64).

The images:

| Image              | Dockerfile              | Role                                   | Inbound |
|--------------------|-------------------------|----------------------------------------|---------|
| `waf-enterprise`   | `Dockerfile.enterprise` | WAF data-plane (the binary we deploy)  | 8080    |
| `waf-node-agent`   | `Dockerfile.node-agent` | Per-node rule-management agent (§7)     | none    |
| `waf-controlplane` | `Dockerfile.controlplane` | Dashboard/API over the telemetry (§7) | 9600    |
| `waf-operator`     | `Dockerfile.operator`   | Kubernetes operator (WafProxy CRD, K4) | none    |

All are multi-stage, run as **non-root uid 10001**, and carry
`org.opencontainers.image.*` labels populated at build time.

## Base-image policy

**Runtime base = `gcr.io/distroless/cc-debian12`, pinned by digest** in every `Dockerfile.*`.
Distroless/cc ships only glibc + libgcc + libstdc++ + libssl3 + the CA bundle — **no apt,
shell, perl, util-linux, ncurses, gzip**. Our binaries are dynamically linked against glibc
only (rustls + ring/aws-lc-rs compile their C statically; the Postgres driver is pure-Rust
`sqlx-postgres`, no libpq/libssl), so this base is sufficient AND keeps the OS CVE surface to
~10 packages. This rebase took the four images from **103 → 0** HIGH/CRITICAL findings — the
entire original surface was unused Debian base-OS packages with no upstream fix.

Rules:

- **Pin the base by digest** (not a moving tag), in every Dockerfile. Bump it deliberately.
- **`waf-controlplane` has no Docker `HEALTHCHECK`** — distroless has no `curl`/shell (removing
  `curl` also drops the curl/libcurl4/libssh2/libldap CVE cluster). Liveness/readiness is the
  Kubernetes `httpGet` probe on `/healthz`; for `docker run`, probe the port from outside.
- **`waf-node-agent` is the one exception to "no shell"**: it runs the configured
  `reload_command` through `sh` (`kill -HUP $(pidof waf-enterprise)` under k8s
  `shareProcessNamespace`). It stays distroless but adds a **single static busybox** copied in
  and symlinked to `sh`/`pidof`/`cat`/`kill`. A lone static binary carries no dpkg metadata, so
  it adds nothing to the OS CVE surface the scanner sees.
- **Accepting a finding** is only via `.trivyignore`, with a justification and an expiry date.
  Prefer fixing (bump the base digest) over ignoring.

## 🔒 Policy — public images come only from a release, through the gate

- **Only CI publishes.** `images.yml` pushes to `ghcr.io/<owner>/<image>` only for a release:
  a pushed `v*` tag, or a manual run with `release_tag` set (to publish a tag that already
  exists). The push job runs **after** the scan gate of all four images — one image failing the
  gate publishes none — and refuses a tag that does not match the workspace version.
- **Nothing else pushes.** Pull requests, plain manual runs and the weekly re-scan build and
  verify only; they never log in to a registry.
- **Not from a workstation.** `build.sh` refuses a `REGISTRY` that resolves to a known public
  index (Docker Hub, GHCR, Quay, public ECR, GCR, GitLab registry) — no override flag exists. It
  pushes only to a **private** registry, for your own builds or a mirror.

### Tags

| Tag | Moves? | Example |
|-----|--------|---------|
| `<version>` | never — one tag per release | `1.0.0` |
| `<major>.<minor>` | to the latest patch of that line | `1.0` |
| `latest` | to the latest stable release | `latest` |

Pre-release versions (`1.1.0-rc.1`) get only their exact tag. The charts default to
`<chart appVersion>`, i.e. an exact version — pin that (or a digest) in production.

### First publication of an image

A new package on GHCR starts **private**. After the first release push, make each of the four
packages public once: *GitHub → Packages → `<image>` → Package settings → Change visibility →
Public*. The `org.opencontainers.image.source` label (set in every Dockerfile) links each package
to the repository.

### Publishing a release

```sh
git tag -s v1.1.0 -m "Light WAF 1.1.0"   # the tag must equal v<workspace version>
git push origin v1.1.0                    # → images.yml: scan gate → push to ghcr.io
```

To publish the images of a tag that already exists (the workflow was added after it, or a run
failed), start **Images** from the Actions tab with `release_tag` = that tag.

## Build

```sh
cd scripts/images

./build.sh                         # all four, host arch, loaded into local docker
IMAGES="waf-enterprise" ./build.sh # just one
MULTIARCH=1 ./build.sh             # amd64+arm64 → dist/images/*.oci.tar (no registry)
VERSION=0.2.0 ./build.sh           # override tag (default: workspace version in the root Cargo.toml)

# Opt-in push to a PRIVATE registry (public hosts are refused):
REGISTRY=registry.internal:5000 ./build.sh
```

Version defaults to `workspace.package.version` in `Cargo.toml`. Each image is
tagged `:<version>` and `:latest`.

## SBOM + scan (supply-chain gate)

```sh
cd scripts/images
./build.sh                 # build first (single-arch, loaded)
./sbom-scan.sh             # SBOM (syft) + vuln scan (trivy/grype), fails on HIGH,CRITICAL
SEVERITY=CRITICAL ./sbom-scan.sh   # relax the gate to CRITICAL only
```

- **SBOM**: `syft` writes SPDX-JSON + CycloneDX-JSON to `dist/images/`.
  Best-effort — skipped with a warning if `syft` is absent.
- **Scan**: `trivy` (preferred) or `grype` — **required**, it is the gate. Reports land in
  `dist/images/<image>-<version>.scan.txt`; a non-zero exit means findings at the severity gate.

## CI

`.github/workflows/images.yml` runs on `v*` tags, PRs touching the Dockerfiles / `.trivyignore`,
manual dispatch, and a **weekly schedule**. Three jobs:

- **scan** — builds each of the four images (amd64, loaded), generates an SBOM (uploaded as an
  artifact), and runs the trivy gate on `HIGH,CRITICAL`. The gate fails on **all** such findings
  (fixed or unfixed) — matching `sbom-scan.sh` — and reads `.trivyignore` for justified accepts.
  `ignore-unfixed` is intentionally NOT set: it would have passed green on the 103 unfixed base
  CVEs that drove the distroless rebase.
- **multiarch** — builds `linux/amd64,linux/arm64` build-only (QEMU) to prove both arches
  compile; nothing is loaded or pushed. Skipped on the weekly schedule and on releases (the
  publish job builds the same two arches).
- **publish** — releases only (see the policy above): `needs: scan`, logs in to GHCR with the
  workflow's `GITHUB_TOKEN` (`packages: write` on this job only), builds `linux/amd64,linux/arm64`
  and pushes the tags. Expect a long run: the arm64 Rust build is emulated.

The **weekly re-scan** (`cron: 0 6 * * 1`) rebuilds amd64 and re-runs the gate against a fresh
trivy DB — so a newly-disclosed CVE against an already-shipped, digest-pinned package turns the
build red. Response: bump the base digest to a patched distroless, or add a justified
`.trivyignore` entry.

## Next

The images feed **K2** (Helm chart `charts/waf`, data-plane), **K3** (chart
`charts/waf-controlplane`) and the operator (`deploy/operator/`). Charts default to
`ghcr.io/0x00spor3/<image>` at the chart's `appVersion`; to run your own build or a mirror, set
`image.repository` (and `agent.image.repository` for the sidecar) in `values`.
