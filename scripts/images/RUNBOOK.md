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

All three are multi-stage, run as **non-root uid 10001**, and carry
`org.opencontainers.image.*` labels populated at build time.

> **Base image note.** `waf-enterprise` and `waf-controlplane` run their binary directly and
> could move to a distroless base later. `waf-node-agent` **cannot** — it runs the configured
> `reload_command` through a shell, so it keeps a minimal Debian base with `sh`.

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

`.github/workflows/images.yml` runs on `v*` tags, PRs touching the Dockerfiles, and manual
dispatch. Two jobs, both **push-free**:

- **scan** — builds each image (amd64, loaded), generates an SBOM (uploaded as an artifact),
  and runs the trivy gate on `HIGH,CRITICAL` (`ignore-unfixed`).
- **multiarch** — builds `linux/amd64,linux/arm64` build-only (QEMU) to prove both arches
  compile; nothing is loaded or pushed.

## Next

The images feed **K2** (Helm chart `enterprise/charts/waf`, data-plane) and **K3** (chart
`enterprise/charts/waf-controlplane`). Charts reference images by `<image>:<version>` and do
**not** assume a public registry — an operator sets `image.repository` to their private
registry in `values`.
