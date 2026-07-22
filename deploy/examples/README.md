<!-- SPDX-License-Identifier: BUSL-1.1 -->
# Ecosystem examples (K5)

The WAF-per-workload topology — external traffic reaches the WAF, which forwards clean
traffic to the app Service:

```
Internet ─▶ Ingress / Gateway ─▶ Service (WAF) ─▶ [waf-enterprise] ─▶ Service (app)
```

So the **upstream Ingress/Gateway routes to the WAF Service**, and the WAF's
`waf.backend` (chart) or `spec.backend` (WafProxy) points at the **app** Service. TLS can
terminate at the ingress (WAF sees http) or at the WAF (`tls.enabled`).

| Example | File |
|---------|------|
| Ingress (nginx) → WAF Service | `ingress/ingress-to-waf.yaml` |
| Gateway API HTTPRoute → WAF Service | `gateway/httproute-to-waf.yaml` |
| cert-manager ACME ClusterIssuer | `cert-manager/clusterissuer-acme.yaml` |
| Argo CD Application (deploys charts/waf) | `gitops/argocd-application.yaml` |
| Flux HelmRelease (deploys charts/waf) | `gitops/flux-helmrelease.yaml` |

Observability (K5, shipped in `charts/waf`): enable `metrics.podMonitor`,
`metrics.prometheusRule`, and `metrics.grafanaDashboard`. The dashboard JSON also lives at
`charts/waf/dashboards/waf-overview.json` for manual import.

All example manifests use placeholders (`myapp`, `registry.internal:5000`, `example.com`) —
edit before applying.
