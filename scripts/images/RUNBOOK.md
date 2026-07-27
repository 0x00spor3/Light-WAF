<!-- SPDX-License-Identifier: BUSL-1.1 -->
# Runbook — container images & supply-chain (K1)

K1 of the **Kubernetes-native deployment** plan (enterprise-only). Produces the three
container images the Helm charts (K2/K3) consume, with reproducible tags, OCI provenance
labels, an SBOM, and a vulnerability scan gate.

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
- **Accepting a finding** is only via `enterprise/.trivyignore`, with a justification and date.
  Prefer fixing (bump the base digest) over ignoring.

## 🔒 Policy — never push to a public registry

This is a **hard rule**, enforced in code, not just documented (see
[[feedback-never-public-registry-push]]):

- `build.sh` refuses a `REGISTRY` that resolves to a known public index (Docker Hub, GHCR,
  Quay, public ECR, GCR, GitLab registry) — no override flag exists.
- The `images.yml` CI workflow has **no login/push step**: it builds, SBOMs, and scans only.
- Publishing (to a **private** registry, or anywhere public) is a deliberate manual operator
  action, exactly like `cargo publish` and `git push`.

## Build

```sh
cd enterprise/scripts/images

./build.sh                         # all three, host arch, loaded into local docker
IMAGES="waf-enterprise" ./build.sh # just one
MULTIARCH=1 ./build.sh             # amd64+arm64 → dist/images/*.oci.tar (no registry)
VERSION=0.2.0 ./build.sh           # override tag (default: enterprise Cargo.toml version)

# Opt-in push to a PRIVATE registry (public hosts are refused):
REGISTRY=registry.internal:5000 ./build.sh
```

Version defaults to `workspace.package.version` in `enterprise/Cargo.toml`. Each image is
tagged `:<version>` and `:latest`.

## SBOM + scan (supply-chain gate)

```sh
cd enterprise/scripts/images
./build.sh                 # build first (single-arch, loaded)
./sbom-scan.sh             # SBOM (syft) + vuln scan (trivy/grype), fails on HIGH,CRITICAL
SEVERITY=CRITICAL ./sbom-scan.sh   # relax the gate to CRITICAL only
```

- **SBOM**: `syft` writes SPDX-JSON + CycloneDX-JSON to `enterprise/dist/images/`.
  Best-effort — skipped with a warning if `syft` is absent.
- **Scan**: `trivy` (preferred) or `grype` — **required**, it is the gate. Reports land in
  `dist/images/<image>-<version>.scan.txt`; a non-zero exit means findings at the severity gate.

## CI

`.github/workflows/images.yml` runs on `v*` tags, PRs touching the Dockerfiles / `.trivyignore`,
manual dispatch, and a **weekly schedule**. Two jobs, both **push-free**:

- **scan** — builds each of the four images (amd64, loaded), generates an SBOM (uploaded as an
  artifact), and runs the trivy gate on `HIGH,CRITICAL`. The gate fails on **all** such findings
  (fixed or unfixed) — matching `sbom-scan.sh` — and reads `.trivyignore` for justified accepts.
  `ignore-unfixed` is intentionally NOT set: it would have passed green on the 103 unfixed base
  CVEs that drove the distroless rebase.
- **multiarch** — builds `linux/amd64,linux/arm64` build-only (QEMU) to prove both arches
  compile; nothing is loaded or pushed. Skipped on the weekly schedule (`if: != 'schedule'`).

The **weekly re-scan** (`cron: 0 6 * * 1`) rebuilds amd64 and re-runs the gate against a fresh
trivy DB — so a newly-disclosed CVE against an already-shipped, digest-pinned package turns the
build red. Response: bump the base digest to a patched distroless, or add a justified
`.trivyignore` entry.

## Next

The images feed **K2** (Helm chart `enterprise/charts/waf`, data-plane) and **K3** (chart
`enterprise/charts/waf-controlplane`). Charts reference images by `<image>:<version>` and do
**not** assume a public registry — an operator sets `image.repository` to their private
registry in `values`.
