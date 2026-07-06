# waf-controlplane (enterprise, BSL 1.1)

Control plane for Light WAF (`ARCHITECTURE_ENTERPRISE.md` §7). A **separate service** — never on
the WAF data port — that consumes the **OPEN telemetry** and persists it for long-term retention,
dashboards and **blocked-request drill-down**.

- **Zero-core datapath.** It consumes the telemetry *contract* (the structured JSON decision-log +
  the Prometheus `/metrics` ABI), not the datapath crate — it deliberately does **not** depend on
  `waf-core`. Its DTOs mirror the frozen decision-log schema (see the core's `score_contributions`
  shape test), so it can ingest logs from a core it does not share a build with.
- **v1 = read-only observability.** Rule management (a write path → SIGHUP push) is deferred behind
  §8 governance (RBAC/audit); alerting is a fast-follow.

## Status: v1 read API + v2 alerting + web dashboard complete

Implemented: config, data model + Postgres store (Phase 1); ingestion — a `/metrics` scraper and a
decision-log ingest endpoint with request/decision correlation (Phase 2); the read API (Phase 3);
end-to-end bite-test against a real WAF node (Phase 4); alerting — config rules → background evaluator
→ fired-record + cooldown → generic webhook (v2); and the **web dashboard** (§7) — a React + Vite +
Recharts SPA under `ui/`, with an `GET /api/decisions/series` time-series endpoint and a `GET
/api/version` drift check.

### HTTP routes

`/healthz`, `/api/version` and the static UI (when `ui_dir` is set) are **public**; every other route
requires `Authorization: Bearer <api_token>` when a token is configured. (A formal OpenAPI spec is a
follow-on.)

| Method + path | Purpose |
|---|---|
| `GET /healthz` | Liveness (public). |
| `GET /api/version` | Backend version (public), so the UI can warn on a UI↔API version drift. |
| `POST /ingest/events?node=<name>` | Ingest a NDJSON batch of decision-log lines from `<name>`. |
| `GET /api/cluster/status` | Scraped nodes + last-seen timestamp. |
| `GET /api/decisions/volume` | Current per-decision totals (latest counter snapshot). |
| `GET /api/decisions/series?window_seconds=&bucket_seconds=` | Denied-event counts over time. `bucket_seconds` ∈ {60, 300, 3600}; the window is capped at 7 days server-side. |
| `GET /api/latency` | Per-node p50/p95/p99 (ms) from the latest histogram snapshot. |
| `GET /api/events?rule_id=&decision=&client_ip=&limit=` | Search denied-request events (newest first). |
| `GET /api/events/{request_id}` | Full drill-down: the reconstructed verdict + per-rule breakdown. |
| `GET /api/alerts?limit=` | Recent fired alerts (v2), newest first. |
| `GET /api/alerts/rules` | The configured alert rules (v2). |

When **governance** (§8) is enabled, `/api/*` is gated by a session cookie (a human, RBAC per role) or
the bearer (a machine/admin principal), and these endpoints are added:

| Method + path | Purpose |
|---|---|
| `POST /api/login` | Log in (username/password) → HttpOnly session cookie (public). |
| `POST /api/logout` | Invalidate the current session. |
| `GET /api/me` | The current principal (actor, role, session vs token). |
| `GET/POST /api/users`, `PATCH/DELETE /api/users/{id}` | User management (admin). |
| `GET /api/audit?limit=` | The signed audit log, newest first (admin). |
| `GET /api/audit/verify` | Verify the audit hash chain + signatures (admin). |

Governance **v2** adds SSO + hardening:

| Method + path | Purpose |
|---|---|
| `GET /api/auth/oidc/login` → `…/callback` | OIDC SSO (Authorization Code + PKCE) → session cookie. |
| `GET/POST /api/tokens`, `DELETE /api/tokens/{id}` | Named, revocable, role-bound service tokens (admin). |
| `GET /api/sessions`, `DELETE /api/sessions/{id}` | List / revoke your own sessions. |
| `DELETE /api/users/{id}/sessions` | Revoke all of a user's sessions (admin). |
| `POST /api/me/password` | Change your password (revokes your other sessions). |
| `POST /api/users/{id}/password` | Reset a user's password (admin). |

### Web UI

A React + Vite + TypeScript SPA (`ui/`, charts via Recharts) consuming the read API (same-origin, no
CORS). Build it with Node 22 / npm 10:

```sh
cd ui && npm ci && npm run build      # → ui/dist  (npm audit should report 0 vulnerabilities)
```

Two serving modes:

- **Dev override** — set `[controlplane].ui_dir = "…/ui/dist"`; the backend serves it via `ServeDir`
  (decoupled from `cargo build`). Or run `npm run dev` in `ui/` for a hot-reload dev server that
  proxies `/api` to a control plane on `:9600`.
- **Single-binary (production)** — embed `ui/dist` into the binary with the **`embed-ui`** cargo
  feature and leave `ui_dir` unset:

  ```sh
  cd ui && npm run build && cd ..
  cargo build --release --features embed-ui
  ```

Static assets are public; only `/api/*` (+ `/ingest`) sit behind the auth layer. A plain `cargo build`
(feature off) needs no frontend and simply serves no UI. See `scripts/controlplane/RUNBOOK.md` §E.

**Auth in the UI (§8):** the SPA auto-detects the mode via `GET /api/auth/config`. With governance ON it
logs in with username/password (+ a "Sign in with SSO" button when OIDC is configured) backed by an
**HttpOnly session cookie** — no token in `sessionStorage` — and exposes the role-gated governance views
(Users / Tokens / Audit / Account). With governance OFF it falls back to the bearer-token prompt
(backward-compat). See RUNBOOK §H.

## Storage

Postgres (`sqlx`, pure-Rust driver, runtime queries → `cargo build` needs no database). The store
tests are **env-gated** on `WAF_CP_DATABASE_URL` (skipped when unset):

```sh
docker run -d --name waf-cp-pg -p 5432:5432 -e POSTGRES_PASSWORD=pw postgres:16
WAF_CP_DATABASE_URL=postgres://postgres:pw@localhost:5432/postgres \
  cargo test -p waf-controlplane
```
