<!-- SPDX-FileCopyrightText: 2026 0x00spor3
     SPDX-License-Identifier: Apache-2.0 -->

# 4. Control plane & dashboard

The control plane is a separate service that consumes the WAF's telemetry, stores it in Postgres, and
serves the dashboard and API. It is **read-only over the data path** — it never sits between clients and
your backend, and it does not depend on the WAF's code, only on its telemetry contract.

## Configuration

The control plane reads one TOML file ([`controlplane.toml`](../crates/waf-controlplane/controlplane.toml)).
Secrets are best supplied via environment variables that override the file.

```toml
[controlplane]
listen                  = "127.0.0.1:9600"   # the read/ingest API + dashboard
retention_days          = 30                 # delete telemetry older than this (0 = keep forever)
scrape_interval_seconds = 15                 # how often to scrape node /metrics
# database_url = "postgres://…"              # prefer WAF_CP_DATABASE_URL
# api_token    = "change-me"                 # prefer WAF_CP_API_TOKEN (governance-off bearer)
# ui_dir       = "…/ui/dist"                 # DEV override; production embeds the UI (leave unset)

# Request-capture retention (hard-delete). Independent of — and deliberately SHORTER than —
# retention_days: captured requests may hold raw secrets, so the reaper prunes them aggressively.
[controlplane.captures]
retention_hours = 168                        # 7 days (0 = keep forever, not recommended)

# WAF nodes whose /metrics to scrape (pull side). Node identity is set here, never by the core.
[[controlplane.nodes]]
name        = "edge-1"
metrics_url = "http://10.0.0.1:9090/metrics"
```

| Env var | Overrides |
|---|---|
| `WAF_CP_DATABASE_URL` | `database_url` |
| `WAF_CP_API_TOKEN` | `api_token` (the static bearer used when governance is off) |

The control plane applies its schema migrations at boot; point it at an empty database and it sets
itself up.

## Feeding it telemetry

Two independent paths, use either or both:

- **Push — the decision log.** Ship the WAF's structured JSON decision-log lines to
  `POST /ingest/events?node=<name>` as an NDJSON batch (bearer-authenticated). This carries the full
  per-request verdict and score breakdown that powers Events and the drill-down.
- **Pull — metrics.** List nodes under `[[controlplane.nodes]]`; the scraper polls their Prometheus
  `/metrics` on `scrape_interval_seconds` for volumes and latency.
- **Push — request captures (optional).** When a node has [request capture](03-waf-configuration.md#request-capture)
  enabled, its shipper posts each full denied request to `POST /ingest/captures` (bearer-authenticated,
  idempotent) on a side-channel. These are stored separately, pruned by `[controlplane.captures]`, and
  surfaced in the drill-down — see below.

## The dashboard

Open the `listen` address in a browser. The dashboard is a single-page app with a left rail grouped by
what you're doing — **Monitor**, **Manage**, **Govern** — plus your account. Which groups appear
depends on your role (see [Governance](06-governance.md)); with governance off you get the Monitor and
Manage views behind the bearer token.

### Monitor

- **Overview** — the operational snapshot. Instrument readouts (total requests, allowed, blocked,
  rejected, and a **block rate**), a **Traffic disposition** bar showing how all traffic was disposed,
  a **Denied mix** bar breaking blocked vs rejected, denied events over time, per-node latency
  (p50/p95/p99), and cluster status (which nodes are reporting and when they were last seen).
- **Events** — search denied requests (filter by `rule_id`, `decision`, `client_ip`), newest first.
  Each row shows the time, node, method, path, client IP, verdict, matched rule, and score. Click a row
  to open the **drill-down**.
- **Event drill-down** — the full verdict for one request. The **Verdict Meter** shows the accumulated
  score as stacked per-rule contributions colored by severity, with the outcome flagged; below it, the
  request metadata and a **score breakdown** table listing every rule that contributed (module, rule
  id, severity, points). This is how you see *why* a request was blocked.
- **Captured request** (when [request capture](03-waf-configuration.md#request-capture) is on and you
  have the `ViewCaptures` permission) — the panel on the drill-down that shows *what* was blocked: the
  full request headers, cookies and body. It is **reveal-on-click** because the content may hold raw
  secrets and every reveal is written to the audit log. Once revealed it shows a redaction/truncation
  banner (which names were stripped node-side), the request line, headers/cookies tables, and the body
  with a **Text / Hex** toggle plus copy and download. If a capture has not arrived yet (it ships a
  moment after the verdict), was dropped under load, or the request was denied before inspection, the
  panel says so — use **Try again** for the timing case.
- **Alerts** — recently fired alerts (newest first) and the configured alert rules.

### Manage

- **Rules** — governed rule management: publish a new ruleset version, browse the immutable version
  history, roll back to an earlier version, and watch per-node convergence. Covered in
  [chapter 5](05-rule-management.md).

### Govern (admin)

- **Users**, **Tokens**, **Audit**, **Compliance** — covered in [Governance](06-governance.md) and
  [Compliance](07-compliance-and-siem.md). These appear only with governance enabled and only for
  admins.

### You

- **Account** — change your password and review/revoke your active sessions.

## Alerting

The alerting evaluator queries stored decision events on an interval and fires when a rule's
per-group count crosses a threshold within a window. Fired alerts are recorded, delivered to a generic
webhook, and shown in the Alerts view. A cooldown prevents the same `(rule, group)` re-firing too soon.

```toml
[controlplane.alerting]
enabled               = true
eval_interval_seconds = 30
webhook_url           = "https://hooks.slack.com/services/…"   # or env WAF_CP_ALERT_WEBHOOK

# >= 20 blocks from one client IP within 60s = a per-IP burst = attack signature
[[controlplane.alerts]]
name           = "block-burst-per-ip"
decision       = "blocked"     # optional filter
group_by       = "client_ip"   # none | client_ip | rule_id
window_seconds = 60
threshold      = 20
severity       = "critical"
cooldown_seconds = 300          # don't re-fire the same (rule, ip) within 5 min
```

## API

Everything the dashboard does is a same-origin HTTP API. `/healthz` and `/api/version` are public; the
static UI is public; every other route requires a session cookie or a bearer token. The full route
table is in the [control-plane README](../crates/waf-controlplane/README.md#http-routes). Notable
read endpoints:

| Endpoint | Purpose |
|---|---|
| `GET /api/cluster/status` | scraped nodes + last-seen |
| `GET /api/decisions/volume` | current per-decision totals |
| `GET /api/decisions/series?window_seconds=&bucket_seconds=` | denied counts over time (`bucket_seconds` ∈ {60,300,3600}, window ≤ 7d) |
| `GET /api/latency` | per-node p50/p95/p99 |
| `GET /api/events?…` | search denied events |
| `GET /api/events/{request_id}` | full drill-down |
| `GET /api/siem/status` | SIEM export cursor / lag / last delivery |

Next: [Rule management](05-rule-management.md).
