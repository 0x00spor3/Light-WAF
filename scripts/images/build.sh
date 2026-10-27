#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Build the four container images (data-plane, node-agent, control-plane, operator)
# reproducibly, with OCI provenance labels and semver tags derived from the workspace
# version. K1 of the Kubernetes-native deployment plan.
#
# RULE (enforced below, no override): this script NEVER pushes to a PUBLIC registry.
# The official images on ghcr.io are published only by CI (.github/workflows/images.yml)
# from a release tag, after the vulnerability gate. Default output here is LOCAL only;
# pushing is opt-in and restricted to a PRIVATE registry (your own build or a mirror).
#
#   ./build.sh                       # build all four for the host arch, load into local docker
#   IMAGES=waf-enterprise ./build.sh # build just one (space-separated list)
#   MULTIARCH=1 ./build.sh           # build linux/amd64+arm64 → local OCI tarballs in dist/ (no registry)
#   REGISTRY=registry.internal:5000 ./build.sh   # ALSO push to a PRIVATE registry (must not be public)
#   VERSION=0.2.0 ./build.sh         # override the tag (default: workspace version in the root Cargo.toml)
#
# Requires: docker with buildx. Multi-arch uses a buildx builder (created on demand).
set -euo pipefail

# ── Locate the enterprise workspace root (this script lives at scripts/images/) ──
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"   # repository root
cd "${ENT_ROOT}"

# ── Version: workspace.package.version from Cargo.toml, overridable via $VERSION ──
if [[ -z "${VERSION:-}" ]]; then
  VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' "${ENT_ROOT}/Cargo.toml" | head -n1)"
fi
if [[ -z "${VERSION}" ]]; then
  echo "error: could not determine VERSION (set VERSION=x.y.z)" >&2
  exit 1
fi

VCS_REF="$(git -C "${ENT_ROOT}" rev-parse --short HEAD 2>/dev/null || echo unknown)"
BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# ── Image → Dockerfile map ──────────────────────────────────────────────────────
declare -A DOCKERFILES=(
  [waf-enterprise]=Dockerfile.enterprise
  [waf-node-agent]=Dockerfile.node-agent
  [waf-controlplane]=Dockerfile.controlplane
  [waf-operator]=Dockerfile.operator
)
IMAGES="${IMAGES:-waf-enterprise waf-node-agent waf-controlplane waf-operator}"

# ── Guard: refuse PUBLIC registries outright (no override) ───────────────────────
# Public images come only from the CI release workflow, never from a workstation. Known
# public indexes are rejected; a REGISTRY without a host[:port] (i.e. a bare Docker Hub
# namespace) is too.
assert_private_registry() {
  local reg="$1"
  local host="${reg%%/*}"
  case "${host}" in
    docker.io|index.docker.io|registry-1.docker.io|ghcr.io|quay.io|\
    public.ecr.aws|gcr.io|*.gcr.io|registry.gitlab.com|registry.hub.docker.com)
      echo "error: REGISTRY '${reg}' is a PUBLIC registry — refused by policy." >&2
      echo "       This script only pushes to a private registry; the public images are" >&2
      echo "       published by CI (.github/workflows/images.yml) from a release tag." >&2
      exit 1 ;;
  esac
  # A private registry host must be qualified: contain a '.' or ':' (host:port) or be localhost.
  if [[ "${host}" != localhost* && "${host}" != *.* && "${host}" != *:* ]]; then
    echo "error: REGISTRY '${reg}' has no host — looks like a Docker Hub namespace (public). Refused." >&2
    exit 1
  fi
}

REGISTRY="${REGISTRY:-}"
if [[ -n "${REGISTRY}" ]]; then
  assert_private_registry "${REGISTRY}"
fi

# ── Buildx builder (needed for multi-arch / OCI output) ──────────────────────────
BUILDER=waf-images
ensure_builder() {
  if ! docker buildx inspect "${BUILDER}" >/dev/null 2>&1; then
    docker buildx create --name "${BUILDER}" --driver docker-container >/dev/null
  fi
  docker buildx use "${BUILDER}"
}

MULTIARCH="${MULTIARCH:-0}"
DIST="${ENT_ROOT}/dist/images"
mkdir -p "${DIST}"

echo "── enterprise images ──────────────────────────────────────────"
echo "  version   : ${VERSION}"
echo "  revision  : ${VCS_REF}"
echo "  images    : ${IMAGES}"
echo "  multiarch : ${MULTIARCH}"
echo "  registry  : ${REGISTRY:-<local only>}"
echo "───────────────────────────────────────────────────────────────"

for img in ${IMAGES}; do
  dockerfile="${DOCKERFILES[$img]:-}"
  if [[ -z "${dockerfile}" ]]; then
    echo "error: unknown image '${img}'" >&2; exit 1
  fi

  common_args=(
    --file "${dockerfile}"
    --build-arg "VERSION=${VERSION}"
    --build-arg "VCS_REF=${VCS_REF}"
    --build-arg "BUILD_DATE=${BUILD_DATE}"
    --tag "${img}:${VERSION}"
    --tag "${img}:latest"
  )
  # If pushing to a private registry, also tag with the registry prefix.
  if [[ -n "${REGISTRY}" ]]; then
    common_args+=(--tag "${REGISTRY}/${img}:${VERSION}" --tag "${REGISTRY}/${img}:latest")
  fi

  echo ">> building ${img}:${VERSION}"
  if [[ "${MULTIARCH}" == "1" ]]; then
    ensure_builder
    out="${DIST}/${img}-${VERSION}.oci.tar"
    # Multi-arch cannot --load into the docker daemon; emit a local OCI archive
    # (no registry involved) so both arches are proven to build.
    docker buildx build "${common_args[@]}" \
      --platform linux/amd64,linux/arm64 \
      --output "type=oci,dest=${out}" .
    echo "   wrote ${out}"
    if [[ -n "${REGISTRY}" ]]; then
      docker buildx build "${common_args[@]}" \
        --platform linux/amd64,linux/arm64 --push .
      echo "   pushed ${REGISTRY}/${img}:${VERSION} (private)"
    fi
  else
    # Single-arch (host): load into the local docker daemon so it's usable/scannable now.
    docker buildx build "${common_args[@]}" --load .
    echo "   loaded ${img}:${VERSION} into local docker"
    if [[ -n "${REGISTRY}" ]]; then
      docker push "${REGISTRY}/${img}:${VERSION}"
      docker push "${REGISTRY}/${img}:latest"
      echo "   pushed ${REGISTRY}/${img}:${VERSION} (private)"
    fi
  fi
done

echo "✔ build complete (version ${VERSION}). Next: scripts/images/sbom-scan.sh"
