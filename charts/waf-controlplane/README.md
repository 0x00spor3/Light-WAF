<!-- SPDX-License-Identifier: BUSL-1.1 -->
# waf-controlplane — control-plane Helm chart

Deploys the **WAF control plane** (`waf-controlplane`): the dashboard/API over the OPEN
telemetry — read-only observability, governance/RBAC, alerting and SIEM forwarding. It sits
**off the request path** and is backed by Postgres. K3 of the Kubernetes-native deployment plan.

The web UI is embedded in the image (`embed-ui`), and database migrations run automatically
on startup — no separate Job.

## Install

Images are never published to a public registry (see `scripts/images/RUNBOOK.md`); point
`image.repository` at **your** private registry. Provide a database one of three ways
(precedence: `database.existingSecret` → `postgres.bundled` → `database.url`).

Turnkey (bundled Postgres — dev/demo):

```sh
helm install waf-cp ./charts/waf-controlplane \
  --namespace waf --create-namespace \
  --set image.repository=registry.internal:5000/waf-controlplane \
  --set postgres.bundled.enabled=true \
  --set postgres.bundled.image=registry.internal:5000/postgres:16 \
  --set postgres.bundled.password=$(openssl rand -hex 16) \
  --set secrets.apiToken=$(openssl rand -hex 24) \
  --set secrets.auditKey=$(openssl rand -hex 32) \
  --set secrets.bootstrapAdminPassword=$(openssl rand -hex 12)
```

Production (managed Postgres via a Secret carrying `WAF_CP_DATABASE_URL`):

```sh
helm install waf-cp ./charts/waf-controlplane -n waf \
  --set image.repository=registry.internal:5000/waf-controlplane \
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
