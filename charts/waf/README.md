<!-- SPDX-License-Identifier: Apache-2.0 -->
# waf — data-plane Helm chart

Deploys the **WAF data-plane** (`waf-enterprise`) in the **WAF-per-workload** model: one
WAF Deployment fronts **one** upstream Service. Multiple apps ⇒ multiple releases of this
chart. This is not a cluster-wide ingress controller (that needs multi-backend routing in
the core — a strategic follow-on). K2 of the Kubernetes-native deployment plan.

## Install

The chart pulls the release image from the GitHub Container Registry
(`ghcr.io/0x00spor3/waf-enterprise`, multi-arch), tagged with the chart's `appVersion`. To run
your own build or a mirror, set `image.repository` (see `scripts/images/RUNBOOK.md`).

```sh
helm install myapp-waf ./charts/waf \
  --namespace prod --create-namespace \
  --set waf.backend=http://myapp.prod.svc.cluster.local:8080
```

In-cluster the WAF is then reachable at
`http://myapp-waf.prod.svc.cluster.local:8080`, forwarding clean traffic to `waf.backend`.

## What it renders

| Resource            | When                                            |
|---------------------|-------------------------------------------------|
| Deployment          | always (WAF container + optional agent sidecar) |
| ConfigMap           | always (`config.toml`, and `node-agent.toml` if agent) |
| Service (ClusterIP) | always                                          |
| ServiceAccount      | `serviceAccount.create` (default on)            |
| PodMonitor          | `metrics.podMonitor.enabled` (Prometheus Operator) |
| HorizontalPodAutoscaler | `autoscaling.enabled`                       |
| PodDisruptionBudget | `pdb.enabled`                                   |
| Certificate         | `tls.certManager.enabled` (cert-manager)        |

## Key values

| Key | Default | Notes |
|-----|---------|-------|
| `image.repository` | `ghcr.io/0x00spor3/waf-enterprise` | override for your own build or a mirror |
| `image.tag` | `""` | defaults to the chart's `appVersion` |
| `agent.image.repository` | `ghcr.io/0x00spor3/waf-node-agent` | rule-management sidecar image |
| `waf.backend` | placeholder | **required** — the upstream Service URL |
| `waf.mode` | `blocking` | `blocking` or `detection-only` (`detection` is accepted as an alias) |
| `waf.paranoiaLevel` | `3` | CRS paranoia level |
| `waf.modules.*` | all `true` | detection modules on/off |
| `waf.extraConfig` | `""` | raw TOML appended to `config.toml` |
| `metrics.podMonitor.enabled` | `false` | scrape `/metrics` on `:9090` |
| `metrics.prometheusRule.enabled` | `false` | alerting rules over the WAF metrics (down / block-ratio / errors / p99 latency) |
| `metrics.grafanaDashboard.enabled` | `false` | ship `dashboards/waf-overview.json` as a Grafana-sidecar ConfigMap |
| `networkPolicy.enabled` | `false` | default-deny NetworkPolicy (http/metrics ingress + DNS/declared egress) |
| `rateLimit.enabled` | `false` | needs shared Redis for >1 replica |
| `apiSchema.enabled` | `false` | OpenAPI positive-security; `specConfigMap` holds `openapi.json` |
| `tls.enabled` / `tls.certManager.enabled` | `false` | PEM from a Secret / issued by cert-manager |
| `agent.enabled` | `false` | rule-management sidecar (§7) |
| `redis.urlSecret.name` | `""` | `WAF_REDIS_URL` for cluster-wide state |
| `autoscaling.enabled` / `pdb.enabled` | `false` | HPA / PDB |
| `probes.type` | `tcp` | switch to `http` (`/healthz`) once K0 ships |

Secrets are **referenced**, never templated in plaintext: `agent.tokenSecret`,
`redis.urlSecret`, `tls.secretName`, and `extraEnvFrom` (e.g. cloud creds for managed TLS).

## Agent sidecar (§7 rule management)

With `agent.enabled=true` the pod runs `waf-node-agent` alongside the WAF and sets
`shareProcessNamespace: true` so the agent can signal the WAF to reload. Because under
Kubernetes the WAF is **not** PID 1 (the pause container is), the reload command is
`kill -HUP $(pidof waf-enterprise)` — hence the node-agent image ships `procps`. Each pod
gets a distinct `node_name` (its pod name), rendered per-pod by an init container.

## Graceful shutdown (interim)

Until the K0 `Proxy::run(shutdown)` seam lands, drain relies on a `preStop` sleep plus
`terminationGracePeriodSeconds`: the pod leaves Service endpoints before the process is
signalled, so short in-flight requests finish.

## Log shipping

This chart runs **no** log sidecar. Decision-logs go to stdout and are collected by the
cluster-wide DaemonSet (Vector/Fluent-bit → control-plane `/ingest/events`) — the chosen
model for K5.

## Validate locally

```sh
helm lint ./charts/waf
helm lint ./charts/waf -f ./charts/waf/ci/full-values.yaml
helm template rel ./charts/waf -f ./charts/waf/ci/full-values.yaml | kubeconform -strict -summary -ignore-missing-schemas
```
