#!/usr/bin/env bash
# SPDX-License-Identifier: BUSL-1.1
#
# Generate an SBOM and run a vulnerability scan for the locally-built enterprise
# images. K1 supply-chain gate. Operates on images already in the local docker
# daemon (run scripts/images/build.sh first — single-arch/host build, no push).
#
#   ./sbom-scan.sh                       # SBOM + scan all three images at the workspace version
#   IMAGES="waf-enterprise" ./sbom-scan.sh
#   VERSION=0.2.0 ./sbom-scan.sh         # match a specific tag
#   SEVERITY="CRITICAL" ./sbom-scan.sh   # fail only on CRITICAL (default: HIGH,CRITICAL)
#
# SBOM  : syft  (SPDX-JSON + CycloneDX-JSON) — skipped with a warning if not installed.
# Scan  : trivy (preferred) or grype — at least one is REQUIRED; the scan is a gate.
# Output: dist/images/<image>-<version>.{spdx,cdx}.json and .scan.txt
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

if [[ -z "${VERSION:-}" ]]; then
  VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' "${ENT_ROOT}/Cargo.toml" | head -n1)"
fi
IMAGES="${IMAGES:-waf-enterprise waf-node-agent waf-controlplane waf-operator}"
SEVERITY="${SEVERITY:-HIGH,CRITICAL}"
DIST="${ENT_ROOT}/dist/images"
mkdir -p "${DIST}"

have() { command -v "$1" >/dev/null 2>&1; }

# ── Pick a scanner (required — this is a gate) ───────────────────────────────────
SCANNER=""
if have trivy; then SCANNER=trivy
elif have grype; then SCANNER=grype
else
  echo "error: no vulnerability scanner found. Install trivy or grype." >&2
  echo "  trivy: https://aquasecurity.github.io/trivy/   grype: https://github.com/anchore/grype" >&2
  exit 1
fi
echo "scanner: ${SCANNER}   severity gate: ${SEVERITY}   version: ${VERSION}"

fail=0
for img in ${IMAGES}; do
  ref="${img}:${VERSION}"
  if ! docker image inspect "${ref}" >/dev/null 2>&1; then
    echo "error: image ${ref} not found locally — run scripts/images/build.sh first." >&2
    exit 1
  fi

  echo "── ${ref} ─────────────────────────────────────────────────────"

  # SBOM (best-effort — informative, not a gate)
  if have syft; then
    syft "docker:${ref}" -o "spdx-json=${DIST}/${img}-${VERSION}.spdx.json" \
                         -o "cyclonedx-json=${DIST}/${img}-${VERSION}.cdx.json" >/dev/null
    echo "  SBOM  → ${DIST}/${img}-${VERSION}.{spdx,cdx}.json"
  else
    echo "  SBOM  → skipped (syft not installed)"
  fi

  # Vulnerability scan (gate on ${SEVERITY})
  report="${DIST}/${img}-${VERSION}.scan.txt"
  if [[ "${SCANNER}" == "trivy" ]]; then
    # --ignorefile: honour the repo's justified accept-list (same file CI reads), so
    # the local gate and CI agree. No --ignore-unfixed: unfixed HIGH/CRIT still fail
    # (distroless keeps these rare; accept them explicitly in .trivyignore instead).
    if trivy image --scanners vuln --severity "${SEVERITY}" \
         --ignorefile "${ENT_ROOT}/.trivyignore" \
         --exit-code 1 --no-progress "${ref}" | tee "${report}"; then
      echo "  SCAN  → clean (${SEVERITY})"
    else
      echo "  SCAN  → FOUND ${SEVERITY} vulnerabilities (see ${report})"
      fail=1
    fi
  else
    # grype: --fail-on takes a single lowest severity; map from ${SEVERITY}.
    lowest="high"; [[ "${SEVERITY}" == "CRITICAL" ]] && lowest="critical"
    if grype "docker:${ref}" --fail-on "${lowest}" | tee "${report}"; then
      echo "  SCAN  → clean (>=${lowest})"
    else
      echo "  SCAN  → FOUND >=${lowest} vulnerabilities (see ${report})"
      fail=1
    fi
  fi
done

if [[ "${fail}" -ne 0 ]]; then
  echo "supply-chain gate FAILED — ${SEVERITY} vulnerabilities present." >&2
  exit 1
fi
echo "✔ supply-chain gate passed for: ${IMAGES}"
