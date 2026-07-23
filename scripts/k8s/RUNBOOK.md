<!-- SPDX-License-Identifier: BUSL-1.1 -->
# Runbook — Kubernetes deployment (K6)

End-to-end verification of the Kubernetes-native path. The WAF-per-workload topology:

```
Internet ─▶ Ingress / Gateway ─▶ Service (WAF) ─▶ [waf-enterprise] ─▶ Service (app)
                                                         │ stdout decision-log
                                                         ▼
                              Vector DaemonSet ─▶ control-plane /ingest/events ─▶ dashboard
```

Everything is enterprise-only and off the datapath except the WAF Deployment itself. Images
are never pushed to a public registry — build locally and `kind load` / push to a private one.

## A. Automated e2e on kind

```sh
cd enterprise
scripts/k8s/e2e-kind.sh          # build → load → deploy → SQLi 403 → event in control plane
KEEP=1 scripts/k8s/e2e-kind.sh   # keep the cluster to poke around
```

What it asserts:
- a benign request (`/?id=1`) is **200** (forwarded to the app);
- a tautology SQLi (`/?id=1' OR '1'='1`) is **403** (WAF blocks at PL3);
- the blocked event surfaces in the control plane's `GET /api/events` (via the log shipper).

Requires `docker`, `kind`, `kubectl`, `helm`. Also runs in CI (`.github/workflows/e2e-kind.yml`).

## B. Manual install (real cluster)

```sh
# 1. Build + push to YOUR private registry (never public):
REGISTRY=registry.internal:5000 scripts/images/build.sh

# 2. Control plane (managed Postgres in prod; bundled shown here for brevity):
helm install waf-cp charts/waf-controlplane -n waf --create-namespace \
  --set image.repository=registry.internal:5000/waf-controlplane \
  --set postgres.bundled.enabled=true \
  --set secrets.apiToken=$(openssl rand -hex 24) \
  --set secrets.auditKey=$(openssl rand -hex 32) \
  --set secrets.bootstrapAdminPassword=$(openssl rand -hex 12)

# 3. WAF in front of your app:
helm install myapp-waf charts/waf -n prod --create-namespace \
  --set image.repository=registry.internal:5000/waf-enterprise \
  --set waf.backend=http://myapp.prod.svc.cluster.local:8080

# 4. Log shipper (edit WAF_CP_URL + the ingest token Secret first):
kubectl -n waf-system create secret generic waf-cp-ingest --from-literal=token=<api-token>
kubectl apply -f deploy/log-shipper/vector-daemonset.yaml

# 5. Route external traffic to the WAF Service:
kubectl apply -f deploy/examples/ingress/ingress-to-waf.yaml   # or gateway/httproute-to-waf.yaml
```

Alternatively, drive it declaratively with the operator (`deploy/operator/`) — apply a
`WafProxy` CR and it renders the data-plane for you.

## C. Observability

Enable in the `waf` chart: `metrics.podMonitor.enabled`, `metrics.prometheusRule.enabled`,
`metrics.grafanaDashboard.enabled` (Prometheus Operator + Grafana sidecar). The dashboard JSON
is also at `charts/waf/dashboards/waf-overview.json`.

## D. Request capture (full denied requests)

Capture the FULL denied request (headers/cookies/body) for the event drill-down. Optional, OFF by
default, zero data-plane core changes. **Raw by default → redact + keep retention short.** Viewing a
capture needs `ViewCaptures` (operator+) and is audited (`GET /api/events/{id}/capture`).

```sh
# 1. A Secret with the ingest bearer token (== the control-plane API token) in the WAF's namespace:
kubectl -n prod create secret generic waf-capture-token --from-literal=token=<api-token>

# 2. Enable capture on the data-plane chart (redact sensitive names node-side):
helm upgrade myapp-waf charts/waf -n prod --reuse-values \
  --set capture.enabled=true \
  --set capture.controlPlaneUrl=http://waf-controlplane.waf.svc.cluster.local:9600 \
  --set capture.tokenSecret.name=waf-capture-token \
  --set 'capture.redaction.headers={cookie,authorization,set-cookie}' \
  --set 'capture.redaction.bodyFields={password,token,secret}'

# 3. Retention (hard-delete) is a CONTROL-PLANE concern — keep it short (default 7d = 168h):
helm upgrade waf-cp charts/waf-controlplane -n waf --reuse-values \
  --set config.captures.retentionHours=168
```

The redacted value never leaves the node (only the names are reported, for the UI banner). The body
is truncated at `capture.maxBodyBytes` (flagged in the UI). Connection-phase rejects (rate-limit) and
parser-limit 400s happen before inspection, so they stay metadata-only. The kind e2e
(`scripts/k8s/e2e-kind.sh`) asserts SQLi → 403 → event → the captured request at
`/api/events/{id}/capture`.

## E. Static validation (no cluster)

```sh
helm lint charts/waf charts/waf-controlplane
helm template rel charts/waf -f charts/waf/ci/full-values.yaml | kubeconform -strict -ignore-missing-schemas
cargo test -p waf-operator     # operator render + CRD-drift guard
bash -n scripts/k8s/e2e-kind.sh
```
