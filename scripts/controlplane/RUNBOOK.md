<!-- SPDX-License-Identifier: BUSL-1.1 -->
# Runbook — control plane (§7)

Verifies the control plane (`waf-controlplane`): a **separate service** (never on the WAF data port,
**zero-core on the datapath**) that consumes the OPEN telemetry — the structured JSON decision-log
and the Prometheus `/metrics` — and persists it to Postgres for retention, dashboards and
**blocked-request drill-down**. v1 is **read-only observability** (rule management is post-§8).

Three layers:
- **A. Offline suite** (`cargo test`, no environment) — Prometheus parser + histogram quantiles,
  config parsing, decision-log parse + request/decision correlation, bearer-token check.
- **B. Env-gated suite** (needs Postgres) — the store round-trip, the ingest→store path, the Phase-3
  queries, and the **end-to-end bite-test** (a real WAF node's telemetry → drill-down).
- **C. Live wire** — a running WAF + a log shipper + the control plane, then the read API.

---

## A. Offline suite

```sh
cd enterprise
cargo test -p waf-controlplane        # parser/quantile, config, ingest+correlation, bearer (no DB)
```

## B. Env-gated suite (Postgres)

```sh
docker run -d --name waf-cp-pg -p 5433:5432 -e POSTGRES_PASSWORD=pw postgres:16
export WAF_CP_DATABASE_URL=postgres://postgres:pw@localhost:5433/postgres
cd enterprise
cargo test -p waf-controlplane        # runs the env-gated store/ingest tests + e2e.rs + alert_webhook.rs
# e2e.rs: spins a REAL Proxy (blocking + metrics), drives a blocked SQLi, feeds the WAF's own
# decision-log through the control plane, and asserts the drill-down reconstructs the verdict +
# the SQLi/Critical breakdown; then scrapes the WAF's real /metrics for the blocked counter.
# alert_webhook.rs (v2): events cross a rule threshold → the evaluator stores an alert AND POSTs it
# to a local webhook receiver (whole store→evaluate→deliver path).
docker rm -f waf-cp-pg
```

## C. Live wire (operator setup)

1. **Backend + WAF node** (metrics on, JSON log to a file):
   ```sh
   # a backend on :3000, then the OPEN WAF (config with [metrics].enabled = true) logging JSON:
   waf config.toml > /var/log/waf/node.jsonl 2>&1 &
   ```
2. **Postgres + control plane**:
   ```sh
   export WAF_CP_DATABASE_URL=postgres://postgres:pw@localhost:5432/waf_cp
   export WAF_CP_API_TOKEN=change-me
   waf-controlplane controlplane.toml &    # serves :9600 (ingest + read API)
   ```
   (`controlplane.toml` lists the node's `metrics_url` so the scraper polls `/metrics`.)
3. **Ship the decision-log** to the ingest endpoint. In production use Vector/Fluent-bit; a minimal
   reference shipper is included:
   ```sh
   ./forward_logs.sh /var/log/waf/node.jsonl http://127.0.0.1:9600 edge-1 "$WAF_CP_API_TOKEN"
   ```
4. **Drive an attack, then read it back**:
   ```sh
   curl "http://<waf>/?q=1%20UNION%20SELECT%20a,b%20FROM%20users--"      # → 403 (blocked)
   TOKEN="Authorization: Bearer $WAF_CP_API_TOKEN"
   curl -s -H "$TOKEN" 'http://127.0.0.1:9600/api/events?decision=blocked&limit=5'
   curl -s -H "$TOKEN"  http://127.0.0.1:9600/api/events/<request_id>     # full drill-down
   curl -s -H "$TOKEN"  http://127.0.0.1:9600/api/decisions/volume
   curl -s -H "$TOKEN"  http://127.0.0.1:9600/api/latency
   curl -s -H "$TOKEN"  http://127.0.0.1:9600/api/cluster/status
   ```

## E. Alerting (v2)

Config an evaluator + a rule (a per-IP block burst), then cross the threshold and read it back:

```toml
# controlplane.toml
[controlplane.alerting]
enabled = true
eval_interval_seconds = 5
# webhook_url = "https://hooks.slack.com/services/..."   # or env WAF_CP_ALERT_WEBHOOK

[[controlplane.alerts]]
name = "block-burst-per-ip"
decision = "blocked"
group_by = "client_ip"      # none | client_ip | rule_id
window_seconds = 60
threshold = 20
severity = "critical"
cooldown_seconds = 300
```

```sh
# Send ≥ threshold blocked requests from one IP through the WAF (the shipper forwards the logs),
# then, after eval_interval:
TOKEN="Authorization: Bearer $WAF_CP_API_TOKEN"
curl -s -H "$TOKEN" http://127.0.0.1:9600/api/alerts          # the fired alert(s)
curl -s -H "$TOKEN" http://127.0.0.1:9600/api/alerts/rules    # the configured rules
# If webhook_url is set, the alert JSON is POSTed there once per (rule, group) per cooldown.
```

Notes: the window uses each event's own log timestamp (real WAF logs are ≈now); the alert fires once
per `(rule, group)` and re-arms only after `cooldown_seconds`. The evaluator reads ONLY the control
plane's Postgres — it never touches the WAF (zero-datapath).

## D. Performance non-regression (the control plane must NOT tax the datapath)

The control plane is **off the request path** by construction: it PULLs `/metrics` on the WAF's
**separate** loopback listener (reads atomic counters; default 15s), and it ingests logs the WAF
**already writes** via an **out-of-process** shipper. The only WAF-side change (core 0.4) serializes
`score_contributions` **only on a denied request** — never on the benign hot path. To confirm
empirically that an active scrape does not perturb request latency, run the OPEN WAF's own bench
with and without a scraper hitting `/metrics`:

```sh
# baseline (no scrape)
cd <core repo> && cargo bench -p waf-corpus            # or: examples/latency_distribution

# under an aggressive scrape (separate shell): hammer /metrics far faster than production
while true; do curl -s http://127.0.0.1:9090/metrics >/dev/null; done &
cargo bench -p waf-corpus                              # compare: p50/p99 must be unchanged
kill %1
```
Expectation: **no measurable change** — the metrics listener and its atomic reads never contend with
the data serving path. (Keep the production `scrape_interval_seconds` sane; the loop above is only a
stress probe.)

## E. Web UI (§7 dashboard)

The dashboard is a React + Vite + TypeScript SPA under `crates/waf-controlplane/ui/`, consuming the
read API (same-origin, no CORS). It has **two serving modes**:

- **Dev override** — `[controlplane].ui_dir` points at a built `dist/`; the backend serves it via
  `ServeDir` (decoupled from `cargo build`, handy while iterating on the frontend).
- **Single-binary (production)** — the UI is embedded into the binary via `rust-embed`, behind the
  **`embed-ui`** cargo feature. No `dist/` on disk at runtime; `ui_dir` is left unset.

Build the frontend (Node v22 / npm 10):

```sh
cd crates/waf-controlplane/ui
npm ci                 # install from the committed lockfile
npm audit              # supply-chain gate (expect 0 vulnerabilities)
npm run build          # tsc --noEmit + vite build → ui/dist
```

### Mode 1 — dev override (ui_dir)

```sh
# controlplane.toml: ui_dir = "crates/waf-controlplane/ui/dist"
cargo run -p waf-controlplane -- controlplane.toml
# open http://127.0.0.1:9600/ → enter the api_token → Overview / Events / Alerts
```
Or run the Vite dev server (hot reload; it proxies /api to a control plane on :9600):
```sh
cd crates/waf-controlplane/ui && npm run dev   # http://localhost:5173
```

### Mode 2 — single-binary (embed-ui)

```sh
cd crates/waf-controlplane/ui && npm run build   # dist must exist at compile time
cd ../../..                                       # back to enterprise/
cargo build -p waf-controlplane --release --features embed-ui
# The binary now serves the UI itself — copy it anywhere (no dist needed) and run with NO ui_dir set:
./target/release/waf-controlplane controlplane.toml
# open http://127.0.0.1:9600/ — same UI, served from the binary.
```

### Browser checklist (both modes)

- `/` loads the SPA; a bad/absent token shows the login screen; the api_token signs in.
- **Overview**: decision-volume cards + bar chart, denied-events-over-time area chart (range
  selector 1h/6h/24h/7d), per-node latency p50/p95/p99 bars, cluster-status table.
- **Events**: filter by rule_id/decision/client_ip/limit → table → click a row → **drill-down** with
  the per-module score breakdown.
- **Alerts**: fired alerts + configured rules.
- A wrong token → any `/api/*` call 401s → the app drops back to the login screen.
- The footer version chip warns if the UI (`__APP_VERSION__`) and API (`GET /api/version`) differ.

Notes: static assets are **public**; only `/api/*` (+ `/ingest`) sit behind the bearer. The token is
held in `sessionStorage` (a v1 trade-off — XSS could read it; §8/SSO moves to an HttpOnly cookie +
server session). Zero-datapath: the UI is just another API consumer.

## F. Governance (§8): RBAC + local auth + signed audit

Enable governance in `controlplane.toml` and supply the two secrets via env:

```toml
[controlplane.governance]
enabled = true
session_ttl_hours = 12
cookie_secure = true          # set false only for local http dev
bootstrap_admin = "admin"     # created if there are zero users at boot
```

```sh
# 64 hex chars = an Ed25519 seed. MUST persist across restarts (stable audit public key).
export WAF_CP_AUDIT_KEY=$(head -c32 /dev/urandom | xxd -p -c32)
export WAF_CP_BOOTSTRAP_ADMIN_PASSWORD='change-me-strong'
export WAF_CP_API_TOKEN='svc-token'        # bearer = machine/admin principal + the ingest credential
cargo run -p waf-controlplane -- controlplane.toml
# boot logs the audit public key and "bootstrapped initial admin account".
```

With governance on, `/api/*` accepts EITHER a session cookie (a human, RBAC per role) OR the bearer
(a machine/admin principal, `actor = "api-token"` in the audit log). `/ingest` stays bearer-only.
Governance **off** (default) keeps the single static bearer with no sessions (backward-compat).

### Live checklist

```sh
B=http://127.0.0.1:9600
# No auth → 401; bearer = admin → 200.
curl -s -o /dev/null -w '%{http_code}\n' $B/api/cluster/status
curl -s -o /dev/null -w '%{http_code}\n' -H 'Authorization: Bearer svc-token' $B/api/cluster/status

# Login (stores the HttpOnly session cookie in cookies.txt).
curl -s -c cookies.txt -X POST $B/api/login -H 'content-type: application/json' \
  -d '{"username":"admin","password":"change-me-strong"}'
curl -s -b cookies.txt $B/api/me                         # {actor, role:"admin", via:"session"}

# Admin creates a viewer; RBAC then restricts them.
curl -s -b cookies.txt -X POST $B/api/users -H 'content-type: application/json' \
  -d '{"username":"alice","password":"alicepw","role":"viewer"}'
curl -s -c alice.txt -X POST $B/api/login -H 'content-type: application/json' \
  -d '{"username":"alice","password":"alicepw"}'
curl -s -o /dev/null -w '%{http_code}\n' -b alice.txt $B/api/cluster/status   # 200 (read)
curl -s -o /dev/null -w '%{http_code}\n' -b alice.txt $B/api/users            # 403 (RBAC)

# Signed audit chain: list + verify (verify recomputes the hash chain and every signature).
curl -s -b cookies.txt "$B/api/audit?limit=5"
curl -s -b cookies.txt $B/api/audit/verify               # {"ok":true,"count":N,"public_key":"…"}

# Logout invalidates the session.
curl -s -b cookies.txt -X POST $B/api/logout
curl -s -o /dev/null -w '%{http_code}\n' -b cookies.txt $B/api/cluster/status # 401
```

### Automated bite-test

```sh
export WAF_CP_DATABASE_URL=postgres://postgres:pw@localhost:5433/postgres
cargo test -p waf-governance                       # argon2 / RBAC matrix / audit chain (+ tamper) + store
cargo test -p waf-controlplane --test governance   # HTTP e2e: login → RBAC 403/200 → audit verify → tamper→fail
```

Notes: the token is held in `sessionStorage` by the UI (a v1 trade-off — XSS could read it); §8/SSO's
next step is an HttpOnly cookie + server session for the UI too. SSO (OIDC), a governance UI, automated
compliance reports and the §7 rule-management write path build on this layer. Audit writes are
best-effort in v1 (a failure is logged, not fatal — in practice it only fails if Postgres is down, in
which case the action failed too); transactional action+audit is a follow-on.

## G. Governance v2: SSO (OIDC) + auth hardening

Builds on §F. Adds SSO via OpenID Connect, named service tokens, session management, self-service
password change, and login brute-force throttling.

### OIDC SSO (live, against Keycloak)

Bring up a Keycloak with a realm/client/group/user (a realm-import JSON is the quickest path):

```sh
# realm "waf": client "waf-cp" (secret waf-cp-secret, redirect http://localhost:9600/*, standard flow),
# a group "waf-admins" with an id_token "groups" mapper, and a user in it. Then:
docker run -d --name waf-kc -p 8080:8080 \
  -e KEYCLOAK_ADMIN=admin -e KEYCLOAK_ADMIN_PASSWORD=admin \
  -v "$PWD/import:/opt/keycloak/data/import" \
  quay.io/keycloak/keycloak:26.0 start-dev --import-realm
```

Control-plane config + secret:

```toml
[controlplane.governance.oidc]
issuer_url = "http://localhost:8080/realms/waf"
client_id = "waf-cp"
redirect_url = "http://localhost:9600/api/auth/oidc/callback"
role_claim = "groups"
# default_role = "viewer"     # omit to DENY users matching no role_map entry
[[controlplane.governance.oidc.role_map]]
claim = "waf-admins"
role = "admin"
```

```sh
export WAF_CP_OIDC_CLIENT_SECRET=waf-cp-secret
cargo run -p waf-controlplane -- controlplane.toml    # boot logs "oidc SSO enabled"
```

In a browser open `http://localhost:9600/api/auth/oidc/login` → the IdP login → back to the app with a
session cookie. `GET /api/me` then reports the SSO user + the role mapped from their group. The flow was
verified end-to-end with a headless browser (Keycloak group `waf-admins` → role `admin`).

### Service tokens (named, revocable, role-bound)

```sh
B=http://127.0.0.1:9600
# Create → the plaintext is returned ONCE (only its hash is stored).
curl -s -b cookies.txt -X POST $B/api/tokens -H 'content-type: application/json' \
  -d '{"name":"ci-bot","role":"operator"}'        # → {"id":..,"token":"<secret>"}
curl -s -H 'Authorization: Bearer <secret>' $B/api/cluster/status     # 200 (operator can read)
curl -s -o /dev/null -w '%{http_code}\n' -H 'Authorization: Bearer <secret>' $B/api/users  # 403
curl -s -b cookies.txt $B/api/tokens                                  # list (no secrets)
curl -s -b cookies.txt -X DELETE $B/api/tokens/<id>                   # revoke → then Bearer 401
```

### Sessions + password

```sh
curl -s -b cookies.txt $B/api/sessions                               # your sessions (current flagged)
curl -s -b cookies.txt -X DELETE $B/api/sessions/<id>                # revoke one of your own
curl -s -b admin.txt -X DELETE $B/api/users/<uid>/sessions           # admin: revoke all of a user's
curl -s -b cookies.txt -X POST $B/api/me/password -H 'content-type: application/json' \
  -d '{"old_password":"...","new_password":"..."}'                    # revokes your OTHER sessions
curl -s -b admin.txt -X POST $B/api/users/<uid>/password -H 'content-type: application/json' \
  -d '{"new_password":"..."}'                                         # admin reset (revokes all)
```

### Throttle

After `login_max_failures` failed logins for a username within `login_window_seconds`, further attempts
return `429` for `login_lockout_seconds` (per-process, in-memory).

### Automated bite-test

```sh
export WAF_CP_DATABASE_URL=postgres://postgres:pw@localhost:5433/postgres
cargo test -p waf-governance                       # + v2 store: tokens, sessions, oidc-flow, password
cargo test -p waf-controlplane --test governance   # HTTP e2e now also covers tokens/sessions/pw/throttle
```
The OIDC redirect flow is verified live (Keycloak + a headless browser), not in the automated suite
(no IdP in CI); the pure OIDC helpers (claim extraction, JWT-payload decode, role mapping) are unit-tested.

## H. Web UI — governance (dashboard §8)

The SPA (built + served as in §E) now covers governance. It **auto-detects** the auth mode at startup
via `GET /api/auth/config`:

- **governance ON** → a username/password login (+ a **"Sign in with SSO"** button when OIDC is
  configured) backed by an **HttpOnly session cookie** — no token is held by JS (closes the
  sessionStorage XSS trade-off).
- **governance OFF** → the original bearer-token prompt (unchanged; existing deployments keep working).

Governance views (nav is role-gated; the backend enforces RBAC regardless):

| View | Who | What |
|---|---|---|
| **Users** | admin | list/create users, change role, disable/enable, reset password, delete. |
| **Tokens** | admin | list/create service tokens (the secret is shown **once**), revoke. |
| **Audit** | admin | the signed audit log + a **Verify chain** button (✓ verified / broken seq). |
| **Account** | everyone | change your password + list/revoke your own sessions. |

### Live checklist (three modes)

```sh
# Session mode (governance ON), single-binary:
cd crates/waf-controlplane/ui && npm run build && cd ../../..
cargo build -p waf-controlplane --release --features embed-ui
export WAF_CP_AUDIT_KEY=... WAF_CP_BOOTSTRAP_ADMIN_PASSWORD=...   # governance secrets
./target/release/waf-controlplane controlplane.toml               # governance.enabled = true
# → open the UI, sign in as the bootstrap admin → Users/Tokens/Audit/Account appear.

# SSO: with [controlplane.governance.oidc] set (see §G) the login shows "Sign in with SSO".
# → click it → IdP login → back to the dashboard as the SSO user (role from their group).

# Token mode (governance OFF): the login is the bearer-token prompt; only Overview/Events/Alerts show.
```

Verified end-to-end with a headless browser in all three modes (session via the embedded single-binary,
OIDC via Keycloak, and token-mode backward-compat). Follow-on: an explicit CSRF token (in addition to
the SameSite=Strict cookie), auto-refresh, and E2E Playwright.
