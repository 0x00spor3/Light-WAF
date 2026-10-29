<!-- SPDX-FileCopyrightText: 2026 0x00spor3
     SPDX-License-Identifier: Apache-2.0 -->

# 9. Kubernetes deployment

Run Light WAF natively on Kubernetes. This is **packaging and ecosystem integration only** — the data
path is the same `waf-enterprise` binary from [chapter 2](02-getting-started.md); nothing here changes
how a request is judged.

The unit of deployment is **WAF-per-workload**: one WAF `Deployment` fronts **one** upstream `Service`
(set as the backend). It is *not* a cluster-wide ingress controller — that would need multi-backend
routing in the core, which is a deliberate non-goal for now.

> **Images.** Multi-arch images (amd64 + arm64) are published on the GitHub Container Registry:
> `ghcr.io/0x00spor3/waf-enterprise`, `waf-controlplane`, `waf-node-agent` and `waf-operator`,
> tagged with the release version. The charts and the operator manifests use them by default, at
> the chart's `appVersion`. To run your own build or a mirror, see
> [`scripts/images/RUNBOOK.md`](../scripts/images/RUNBOOK.md).

## What you deploy

| Piece | Path | Role |
|---|---|---|
| **Data-plane chart** | `charts/waf` | The WAF `Deployment` + `Service` in front of your app, ConfigMap-rendered `config.toml`, optional agent sidecar, metrics, TLS, NetworkPolicy, HPA/PDB. |
| **Control-plane chart** | `charts/waf-controlplane` | The dashboard/API `Deployment` (auto-migrate, embedded UI), Service, Ingress, Secret, optional bundled Postgres/Redis. |
| **Operator** (optional) | `crates/waf-operator`, `deploy/operator/` | A `WafProxy` CRD (`waf.io/v1alpha1`, namespaced) — declare a CR and the operator renders the data-plane for you. |
| **Log shipper** | `deploy/log-shipper/` | A Vector `DaemonSet` that tails WAF pod stdout and posts the decision-log to the control plane. |
| **Examples** | `deploy/examples/` | Ingress, Gateway API, cert-manager, and GitOps (Argo/Flux) wiring. |

## Install with Helm

The charts are published as signed OCI artifacts on GHCR, one version per release (Helm 3.8 or
later):

```sh
# 1. Control plane (managed Postgres in prod; bundled shown for a quick start):
helm install waf-cp oci://ghcr.io/0x00spor3/charts/waf-controlplane --version 1.0.2 \
  -n waf --create-namespace \
  --set postgres.bundled.enabled=true \
  --set secrets.apiToken=<ingest-token>

# 2. The WAF in front of your app:
helm install myapp-waf oci://ghcr.io/0x00spor3/charts/waf --version 1.0.2 \
  -n prod --create-namespace \
  --set waf.backend=http://myapp.prod.svc.cluster.local:8080
```

From a checkout of the repository, `charts/waf` and `charts/waf-controlplane` work in place of the
`oci://` references. The later examples on this page use the chart paths from a checkout.

Then route external traffic to the WAF `Service` (an Ingress or a Gateway `HTTPRoute` — see
`deploy/examples/`). The full manual and per-cluster options are in the
[Kubernetes runbook](../scripts/k8s/RUNBOOK.md).

The data-plane chart renders the same TOML described in [chapter 3](03-waf-configuration.md) from
`values.yaml`: `waf.mode`, `waf.modules.*`, `rateLimit.*`, `apiSchema.*`, `tls.*`, `capture.*`, and so
on. Anything not templated goes verbatim into `waf.extraConfig`.

## Declarative with the operator

Instead of `helm install` per app, apply the CRD once and then a small `WafProxy` per workload:

```sh
kubectl apply -f deploy/operator/crd.yaml
kubectl apply -f deploy/operator/rbac.yaml -f deploy/operator/operator.yaml
kubectl apply -f deploy/operator/sample-wafproxy.yaml   # → renders CM + Deployment + Service
```

The operator owns what it renders (owner references), so deleting the `WafProxy` cleans up the WAF.

## Request capture on Kubernetes

Enable [request capture](03-waf-configuration.md#request-capture) per workload from the data-plane
chart, and keep the control-plane retention short:

```sh
# A Secret with the ingest bearer (== the control plane's API token) in the WAF's namespace:
kubectl -n prod create secret generic waf-capture-token --from-literal=token=<api-token>

helm upgrade myapp-waf charts/waf -n prod --reuse-values \
  --set capture.enabled=true \
  --set capture.controlPlaneUrl=http://waf-controlplane.waf.svc.cluster.local:9600 \
  --set capture.tokenSecret.name=waf-capture-token \
  --set 'capture.redaction.headers={cookie,authorization,set-cookie}' \
  --set 'capture.redaction.bodyFields={password,token,secret}'

helm upgrade waf-cp charts/waf-controlplane -n waf --reuse-values \
  --set config.captures.retentionHours=168
```

The token lands in the pod as `WAF_CAPTURE_TOKEN` via a `secretKeyRef` — never in the ConfigMap. The
redacted value never leaves the node; retention (`captures.retentionHours`) hard-deletes captures in
the control plane, independently of and shorter than telemetry retention.

## Observability

The chart ships the WAF metrics ABI (`waf_up`, `waf_requests_total{decision}`,
`waf_request_duration_seconds`) as a `PodMonitor` + `PrometheusRule` and a Grafana dashboard
(`metrics.podMonitor.enabled`, `metrics.prometheusRule.enabled`, `metrics.grafanaDashboard.enabled`).
Labels are deliberately low-cardinality — no path/IP/rule labels.

## Security & lifecycle posture

- Pods run **non-root** (uid 10001), read-only root filesystem, all capabilities dropped, seccomp
  `RuntimeDefault`.
- Graceful shutdown: on `SIGTERM` the health endpoint's `/readyz` flips to `503` so Kubernetes stops
  routing while in-flight requests drain (with a `preStop` grace as backup).
- `NetworkPolicy`, `HPA`, and `PDB` are available (off by default) for a default-deny, autoscaled,
  disruption-budgeted posture.

## Validate before you ship

No cluster needed for static checks:

```sh
helm lint charts/waf charts/waf-controlplane
helm template rel charts/waf -f charts/waf/ci/full-values.yaml | kubeconform -strict -ignore-missing-schemas
cargo test -p waf-operator     # operator render + CRD-drift guard
bash -n scripts/k8s/e2e-kind.sh
```

The end-to-end test on a throwaway [kind](https://kind.sigs.k8s.io/) cluster
(`scripts/k8s/e2e-kind.sh`) builds and loads the images, deploys the whole stack, drives a benign
request (200) and a SQLi (403), and asserts the blocked event **and its full captured request** reach
the control plane. It runs in CI (`e2e-kind.yml`).

---

That's the operator guide. For the design rationale behind the enterprise/core split and the extension
seams, continue to [`ARCHITECTURE_ENTERPRISE.md`](../ARCHITECTURE_ENTERPRISE.md) and
[`BOUNDARY.md`](../BOUNDARY.md); for per-feature copy-paste procedures, the
[`scripts/*/RUNBOOK.md`](../scripts) files.
