#!/usr/bin/env bash
# SPDX-License-Identifier: BUSL-1.1
#
# End-to-end test on a kind cluster (K6). Proves the whole Kubernetes-native path:
#   build → kind-load → deploy control-plane (+ bundled Postgres) → deploy a test app →
#   deploy the WAF data-plane in front of it (with request capture ON) → deploy the
#   log-shipper DaemonSet → drive a benign request (200) and a SQLi (403) → assert the
#   blocked event shows up in the control-plane's /api/events AND its FULL captured request
#   (headers/body, shipped on the capture side-channel) surfaces at /api/events/{id}/capture.
#
# NO registry involved: images are loaded straight into kind (aligns with the never-push
# policy). Public images (kind node, whoami, curl, vector) are PULLED to run — that is not
# publishing ours.
#
#   ./e2e-kind.sh              # full run, deletes the cluster at the end
#   KEEP=1 ./e2e-kind.sh       # keep the cluster for inspection
#   CLUSTER=myname ./e2e-kind.sh
#
# Requires: docker, kind, kubectl, helm.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
CLUSTER="${CLUSTER:-waf-e2e}"
NS=waf
TOKEN="e2e-shared-token-$(date +%s)"

VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' "${ENT_ROOT}/Cargo.toml" | head -n1)"
ENT_IMG="waf-enterprise:${VERSION}"
CP_IMG="waf-controlplane:${VERSION}"

log() { printf '\n\033[1;36m== %s ==\033[0m\n' "$*"; }
need() { command -v "$1" >/dev/null 2>&1 || { echo "missing: $1" >&2; exit 1; }; }
need docker; need kind; need kubectl; need helm

cleanup() {
  if [[ "${KEEP:-0}" != "1" ]]; then
    log "deleting kind cluster ${CLUSTER}"
    kind delete cluster --name "${CLUSTER}" >/dev/null 2>&1 || true
  else
    echo "KEEP=1 → leaving cluster ${CLUSTER} up (kind delete cluster --name ${CLUSTER})"
  fi
}
trap cleanup EXIT

# ── 1. Cluster ────────────────────────────────────────────────────────────────
log "creating kind cluster ${CLUSTER}"
kind create cluster --name "${CLUSTER}" --wait 120s

# ── 2. Build + load the two images we need ────────────────────────────────────
log "building images ${VERSION}"
IMAGES="waf-enterprise waf-controlplane" "${ENT_ROOT}/scripts/images/build.sh"
log "loading images into kind"
kind load docker-image "${ENT_IMG}" "${CP_IMG}" --name "${CLUSTER}"

kubectl create namespace "${NS}"

# ── 3. Control plane (bundled Postgres, token mode) ───────────────────────────
log "installing control plane"
helm install waf-cp "${ENT_ROOT}/charts/waf-controlplane" -n "${NS}" \
  --set image.repository=waf-controlplane --set image.tag="${VERSION}" \
  --set image.pullPolicy=IfNotPresent \
  --set postgres.bundled.enabled=true \
  --set postgres.bundled.image=postgres:16 \
  --set config.governance.enabled=false \
  --set secrets.apiToken="${TOKEN}" \
  --set secrets.bootstrapAdminPassword=unused \
  --wait --timeout 180s

# Ingest token for the log shipper (== the control plane's API token in token mode).
kubectl create namespace waf-system
kubectl create secret generic waf-cp-ingest -n waf-system --from-literal=token="${TOKEN}"

# ── 4. Test upstream app ──────────────────────────────────────────────────────
log "deploying test app (whoami)"
kubectl apply -n "${NS}" -f - <<'YAML'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: whoami
spec:
  replicas: 1
  selector: { matchLabels: { app: whoami } }
  template:
    metadata: { labels: { app: whoami } }
    spec:
      containers:
        - name: whoami
          image: traefik/whoami:v1.10
          ports: [{ containerPort: 80 }]
---
apiVersion: v1
kind: Service
metadata:
  name: whoami
spec:
  selector: { app: whoami }
  ports: [{ port: 80, targetPort: 80 }]
YAML
kubectl rollout status -n "${NS}" deploy/whoami --timeout 120s

# ── 5. WAF data-plane in front of the app (request capture ON) ────────────────
# The capture shipper posts to the control-plane's /ingest/captures with WAF_CAPTURE_TOKEN,
# which — in token mode — is the same bearer as the CP's API token.
CP_URL="http://waf-cp-waf-controlplane.${NS}.svc.cluster.local:9600"
kubectl create secret generic waf-capture-token -n "${NS}" --from-literal=token="${TOKEN}"

log "installing WAF data-plane (capture enabled)"
helm install app "${ENT_ROOT}/charts/waf" -n "${NS}" \
  --set image.repository=waf-enterprise --set image.tag="${VERSION}" \
  --set image.pullPolicy=IfNotPresent \
  --set waf.backend="http://whoami.${NS}.svc.cluster.local:80" \
  --set replicaCount=1 \
  --set capture.enabled=true \
  --set capture.controlPlaneUrl="${CP_URL}" \
  --set capture.tokenSecret.name=waf-capture-token \
  --set 'capture.redaction.headers={cookie,authorization}' \
  --set 'capture.redaction.bodyFields={password,token}' \
  --wait --timeout 180s

# ── 6. Log shipper ────────────────────────────────────────────────────────────
log "deploying log-shipper DaemonSet"
kubectl apply -f "${ENT_ROOT}/deploy/log-shipper/vector-daemonset.yaml"
kubectl rollout status -n waf-system ds/waf-log-shipper --timeout 120s

# ── 7. Drive traffic through the WAF ──────────────────────────────────────────
curl_in_cluster() { # $1 = path (already url-encoded); prints HTTP status
  kubectl run "curl-$RANDOM" -n "${NS}" --rm -i --restart=Never -q \
    --image=curlimages/curl:8.10.1 --command -- \
    curl -s -o /dev/null -w '%{http_code}' "http://app-waf.${NS}.svc.cluster.local:8080$1"
}

log "benign request (expect 200)"
BENIGN="$(curl_in_cluster "/?id=1")"
echo "benign → ${BENIGN}"

log "SQLi request (expect 403)"
SQLI="$(curl_in_cluster "/?id=1%27%20OR%20%271%27%3D%271")"
echo "sqli → ${SQLI}"

[[ "${BENIGN}" == "200" ]] || { echo "FAIL: benign request was ${BENIGN}, expected 200" >&2; exit 1; }
[[ "${SQLI}" == "403" ]]   || { echo "FAIL: SQLi request was ${SQLI}, expected 403 (WAF did not block)" >&2; exit 1; }

# ── 8. Assert the blocked event reached the control plane ─────────────────────
cp_get() { # $1 = path (query string ok); prints the response body
  kubectl run "cpq-$RANDOM" -n "${NS}" --rm -i --restart=Never -q \
    --image=curlimages/curl:8.10.1 --command -- \
    curl -s -H "Authorization: Bearer ${TOKEN}" "${CP_URL}$1" 2>/dev/null || true
}

log "checking control-plane /api/events for the blocked event"
RID=""
for i in $(seq 1 30); do
  out="$(cp_get "/api/events?decision=blocked&limit=5")"
  RID="$(echo "${out}" | grep -oE '"request_id":"[^"]+"' | head -1 | sed 's/.*:"//; s/"$//')"
  if [[ -n "${RID}" ]]; then
    echo "found blocked event ${RID} after ${i} tries"
    break
  fi
  sleep 3
done
[[ -n "${RID}" ]] || { echo "FAIL: no blocked event surfaced in the control plane" >&2; echo "last: ${out}" >&2; exit 1; }

# ── 9. Assert the FULL captured request reached the control plane ──────────────
# The capture module buffered the denied request off the datapath and the shipper POSTed it
# to /ingest/captures; it must now join the event at /api/events/{id}/capture (RBAC-gated;
# in token mode the static bearer is the admin-equivalent).
log "checking control-plane /api/events/${RID}/capture for the captured request"
cap=""
for i in $(seq 1 30); do
  cap="$(cp_get "/api/events/${RID}/capture")"
  if echo "${cap}" | grep -q "\"request_id\":\"${RID}\""; then
    echo "found the captured request after ${i} tries"
    break
  fi
  sleep 3
done
echo "${cap}" | grep -q "\"request_id\":\"${RID}\"" \
  || { echo "FAIL: no captured request surfaced (capture disabled or not shipped)" >&2; echo "last: ${cap}" >&2; exit 1; }
echo "${cap}" | grep -q '"method":"GET"' \
  || { echo "FAIL: captured request missing the expected method" >&2; echo "last: ${cap}" >&2; exit 1; }

log "E2E PASSED — WAF blocked the SQLi (403), the event reached the control plane, and the full captured request was joined at /api/events/{id}/capture"
