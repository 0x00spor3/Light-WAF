#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# verify_shared_cert.sh — prove the multi-node cert-sharing (SharedCertStore) works: two WAF
# nodes on the same host must serve the SAME certificate (same SHA-256 fingerprint), because in
# cluster mode ONE node issues via DNS-01 and the other converges on it via Redis.
#
# Contrast (the control): with `[tls.acme].cluster = false`, each node issues its OWN cert, so the
# two fingerprints DIFFER — run it both ways to see the seam do its job.
#
# This script does NOT start the nodes (ACME needs your real domain + AWS + WAF_CERT_STORE_KEY);
# bring them up per scripts/cluster-tls/RUNBOOK.md, then run this to check convergence.
#
# It also checks Redis holds exactly ONE cert blob and (best effort) that no stale issuance lock
# lingers — i.e. a single cluster-wide issuance.
#
# Config via env (defaults in brackets):
#   HOST [127.0.0.1]  PORT_A [8443]  PORT_B [8444]  SNI [lightwaf.org]
#   REDIS [redis://127.0.0.1:6379]   POLL_SECONDS [300]   TIMEOUT [5]
#
# Usage:  ./verify_shared_cert.sh
set -euo pipefail

HOST="${HOST:-127.0.0.1}"
PORT_A="${PORT_A:-8443}"
PORT_B="${PORT_B:-8444}"
SNI="${SNI:-lightwaf.org}"
REDIS="${REDIS:-redis://127.0.0.1:6379}"
POLL_SECONDS="${POLL_SECONDS:-300}"   # how long to wait for the first issuance to complete
TIMEOUT="${TIMEOUT:-5}"

command -v openssl >/dev/null || { echo "need openssl" >&2; exit 2; }

# SHA-256 fingerprint of the leaf cert a node currently serves, or "" if none yet / unreachable.
fingerprint() {
  local port=$1
  openssl s_client -connect "${HOST}:${port}" -servername "$SNI" </dev/null 2>/dev/null \
    | openssl x509 -noout -fingerprint -sha256 2>/dev/null \
    | sed 's/^.*=//'
}

echo "Waiting up to ${POLL_SECONDS}s for BOTH nodes to serve a certificate…"
START=$(date +%s)
fa=""; fb=""
while :; do
  fa=$(fingerprint "$PORT_A" || true)
  fb=$(fingerprint "$PORT_B" || true)
  if [[ -n "$fa" && -n "$fb" ]]; then break; fi
  if (( $(date +%s) - START > POLL_SECONDS )); then
    echo "[!] timed out waiting for certs (A='${fa:-none}' B='${fb:-none}')." >&2
    echo "    Check the node logs for 'certificate issued and installed' / 'converged on shared certificate'." >&2
    exit 1
  fi
  sleep 5
done

echo "  Node A (:$PORT_A) leaf SHA-256: $fa"
echo "  Node B (:$PORT_B) leaf SHA-256: $fb"
echo

if [[ "$fa" == "$fb" ]]; then
  echo "[OK] Both nodes serve the SAME certificate → cluster cert-sharing works (one issuance, converged)."
  rc=0
else
  echo "[FAIL] The two nodes serve DIFFERENT certificates." >&2
  echo "       In cluster mode this should not happen. (If cluster=false, different is EXPECTED — this is the control.)" >&2
  rc=1
fi

# Redis cross-check (optional, needs redis-cli): exactly one cert blob, and report any live lock.
if command -v redis-cli >/dev/null; then
  host_port=${REDIS#redis://}
  rhost=${host_port%%:*}; rport=${host_port##*:}
  n_cert=$(redis-cli -h "$rhost" -p "$rport" --scan --pattern 'cert:*' 2>/dev/null | wc -l | tr -d ' ')
  n_lock=$(redis-cli -h "$rhost" -p "$rport" --scan --pattern 'issuance_lock:*' 2>/dev/null | wc -l | tr -d ' ')
  echo
  echo "  Redis: cert blobs=${n_cert} (expect 1), live issuance locks=${n_lock} (expect 0 when idle)"
fi

exit "$rc"
