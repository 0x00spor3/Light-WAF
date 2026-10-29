<!-- SPDX-License-Identifier: Apache-2.0 -->
# waf-operator — install & usage (K4)

The operator turns a **`WafProxy`** custom resource into a WAF data-plane (ConfigMap +
Deployment + Service) in front of a target Service — the declarative, native UX for the
WAF-per-workload model. No routing lives in the core: **one `WafProxy` ⇒ one WAF in front of
one upstream**. It is control-plane only (it generates manifests; it never inspects traffic).

## Install

The manifests use the release images on the GitHub Container Registry
(`ghcr.io/0x00spor3/waf-operator` and `ghcr.io/0x00spor3/waf-enterprise`). To run your own
build or a mirror (`scripts/images/build.sh`), edit the image refs below.

```sh
# 1. CRD + RBAC + operator
kubectl apply -f deploy/operator/crd.yaml
kubectl apply -f deploy/operator/rbac.yaml
kubectl apply -f deploy/operator/operator.yaml

# 2. Protect an app
# edit sample-wafproxy.yaml → set spec.backend (and spec.image to the release you want)
kubectl apply -f deploy/operator/sample-wafproxy.yaml

kubectl get wafproxy -A          # Mode / Replicas / Ready
kubectl describe wafproxy myapp-waf -n prod
```

Deleting the `WafProxy` cascades to its ConfigMap/Deployment/Service (owner references).

## WafProxy spec

| Field | Default | Notes |
|-------|---------|-------|
| `image` | — (required) | WAF data-plane image, e.g. `ghcr.io/0x00spor3/waf-enterprise:1.0.2` |
| `backend.service` / `backend.url` | — (required) | upstream: a Service ref (→ cluster-local URL) or a raw URL |
| `mode` | `blocking` | `blocking` or `detection` (rendered as the WAF's `detection-only`: observe and log, never block) |
| `paranoiaLevel` | `3` | 1–4 |
| `blockThreshold` | `3` | score to block |
| `replicas` | `2` | data-plane replicas |
| `modules` | image defaults | map name→bool to force modules on/off |
| `crsCurated` | `true` | premium curated-CRS module |
| `apiSchemaSpecRef` | — | ConfigMap with `openapi.json` for positive security |

## Regenerating the CRD

`crd.yaml` is generated from the Rust types. After changing the spec:

```sh
cargo run -p waf-operator -- crd > deploy/operator/crd.yaml
```

A test (`committed_crd_matches_generated`) fails if the committed file drifts from the types.

## Scope

v1 renders ConfigMap + Deployment + Service (no agent sidecar / HPA / PDB / cert-manager —
use the `charts/waf` Helm chart when you need those knobs). `status.ready` means "reconciled/
applied"; wiring it to the Deployment's `availableReplicas` is a follow-on.
