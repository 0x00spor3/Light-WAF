<!-- SPDX-License-Identifier: Apache-2.0 -->
# waf-controlplane — control-plane Helm chart

Deploys the **WAF control plane** (`waf-controlplane`): the dashboard/API over the OPEN
telemetry — read-only observability, governance/RBAC, alerting and SIEM forwarding. It sits
**off the request path** and is backed by Postgres. K3 of the Kubernetes-native deployment plan.

The web UI is embedded in the image (`embed-ui`), and database migrations run automatically
on startup — no separate Job.

## Install

The chart pulls the release image from the GitHub Container Registry
(`ghcr.io/0x00spor3/waf-controlplane`, multi-arch, UI embedded), tagged with the chart's
`appVersion`. To run your own build or a mirror, set `image.repository` (see
`scripts/images/RUNBOOK.md`). Provide a database one of three ways (precedence:
`database.existingSecret` → `postgres.bundled` → `database.url`).

The chart is published as an OCI artifact on GHCR (Helm 3.8 or later). From a checkout of the
repository, use `./charts/waf-controlplane` instead of the `oci://` reference. The published chart
is signed with cosign, like the images (see `SECURITY.md`).

Turnkey (bundled Postgres — dev/demo). The API token, the bootstrap admin password and the
Postgres password are **generated** on first install (the NOTES print how to read them back):

```sh
helm install waf-cp oci://ghcr.io/0x00spor3/charts/waf-controlplane --version 1.0.2 \
  --namespace waf --create-namespace \
  --set postgres.bundled.enabled=true \
  --set secrets.auditKey=$(openssl rand -hex 32)
```

Production (managed Postgres via a Secret carrying `WAF_CP_DATABASE_URL`):

```sh
helm install waf-cp oci://ghcr.io/0x00spor3/charts/waf-controlplane --version 1.0.2 -n waf \
  --set database.existingSecret=waf-cp-db \
  --set secrets.existingSecret=waf-cp-env    # carries the WAF_CP_* env
```

## What it renders

| Resource            | When                                              |
|---------------------|---------------------------------------------------|
| Deployment          | always (control-plane; auto-migrates on startup)  |
| ConfigMap           | always (`controlplane.toml`)                      |
| Secret              | unless `secrets.existingSecret` is set            |
| Service (ClusterIP) | always                                            |
| ServiceAccount      | `serviceAccount.create` (default on)              |
| Ingress             | `ingress.enabled`                                 |
| StatefulSet + Service (Postgres) | `postgres.bundled.enabled`           |
| Deployment + Service (Redis)     | `redis.bundled.enabled`              |
| PodDisruptionBudget | `pdb.enabled`                                     |

## Secrets

Sensitive values are never in the ConfigMap. Either set `secrets.existingSecret` (a Secret
carrying all `WAF_CP_*` keys) or let the chart build one from `secrets.*`:

| Env | Source | Notes |
|-----|--------|-------|
| `WAF_CP_DATABASE_URL` | `database.existingSecret` / bundled / `database.url` | required |
| `WAF_CP_API_TOKEN` | `secrets.apiToken` | ingest + read API bearer |
| `WAF_CP_AUDIT_KEY` | `secrets.auditKey` | 64 hex (32-byte Ed25519 seed) |
| `WAF_CP_BOOTSTRAP_ADMIN_PASSWORD` | `secrets.bootstrapAdminPassword` | initial admin |
| `WAF_CP_OIDC_CLIENT_SECRET` | `secrets.oidcClientSecret` | if OIDC on |
| `WAF_CP_ALERT_WEBHOOK` | `secrets.alertWebhook` | optional |
| `WAF_CP_SIEM_AUTH_*` | `extraEnvFrom` (your Secret) | optional |

### No well-known defaults

`secrets.apiToken`, `secrets.bootstrapAdminPassword` and `postgres.bundled.password` default
to **empty**. An empty value is resolved at render time:

1. the value already stored in the cluster's Secret, if any (so `helm upgrade` keeps it);
2. otherwise a random one (40 / 24 / 32 alphanumeric chars) on first install.

An explicit value always wins. The bundled Postgres password lives in its own
`<release>-waf-controlplane-postgres-auth` Secret (the StatefulSet reads it via
`secretKeyRef`, never inline). If the database URL comes from **your** Secret
(`secrets.existingSecret` / `database.existingSecret`) and Postgres is bundled, set
`postgres.bundled.password` explicitly — the chart fails the render otherwise, because it
cannot make a generated password match a URL it does not own.

**GitOps / `helm template`:** without cluster access Helm's `lookup` returns nothing, so an
empty value would be regenerated on every render (Argo CD would rotate the token on each
sync). In that setup set the values explicitly, or use `secrets.existingSecret`.

## Bundled Postgres / Redis

Both are **off by default** and are plain in-chart workloads (not subcharts — the chart pulls
no public Helm repo). They are a **dev/demo convenience**; for production use a managed
database (`database.existingSecret`) and, if you need cluster-wide data-plane state, a managed
Redis. When `redis.bundled.enabled`, point the `waf` chart's `redis.urlSecret` at a Secret
holding `redis://<release>-waf-controlplane-redis:6379`.

## Keycloak / SSO

Keycloak (or any OIDC IdP) is **external** — set `config.governance.oidc.*` and
`secrets.oidcClientSecret`. This chart does not bundle an IdP (SAML is out of scope; federate
via an OIDC broker).

## Validate locally

```sh
helm lint ./charts/waf-controlplane -f ./charts/waf-controlplane/ci/full-values.yaml
helm template rel ./charts/waf-controlplane -f ./charts/waf-controlplane/ci/full-values.yaml \
  | kubeconform -strict -summary -ignore-missing-schemas
```
