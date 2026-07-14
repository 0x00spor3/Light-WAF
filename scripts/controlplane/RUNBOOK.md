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

## I. Rule management (§7 write-path, v3)

The write path: the control plane versions **one managed SecRule `.conf`**; a per-node **agent**
(`waf-node-agent`) pulls the current version, **pre-validates** it with the OPEN seclang parser, writes
it atomically, and runs a `reload_command` (a SIGHUP) so the WAF hot-reloads it (**validate-then-swap**).
**Zero-core**: the agent writes a file the core already loads (`[modules.crs].files`) and triggers the
core's existing reload — nothing in the datapath changes. Publish/rollback are gated by
`Permission::ManageRules` (operator+) and **audited** (`rule.publish` / `rule.rollback`); the
agent-facing routes only need `ReadObservability`.

**Two fail-safe levels**: (1) the agent refuses to touch the WAF if the ruleset does not parse into the
supported subset; (2) the WAF's own reload does validate-then-swap (a bad file keeps the last-good rules).

### 1. Point the WAF at a managed file

In the WAF's own `config.toml`, enable the CRS module on a file the agent owns:

```toml
[modules.crs]
enabled = true
files = ["/etc/waf/managed.conf"]   # the agent overwrites THIS file
```
Create it empty (`# managed by waf-node-agent`) so the WAF boots with zero imported rules. On `SIGHUP`
the WAF re-reads it (`kill -HUP $(cat /run/waf.pid)`), validate-then-swap.

### 2. Run the agent on each node

`node-agent.toml`:
```toml
[agent]
control_plane_url = "http://127.0.0.1:9600"
node_name = "edge-1"
managed_file = "/etc/waf/managed.conf"           # SAME path as [modules.crs].files above
reload_command = "kill -HUP $(cat /run/waf.pid)" # or "systemctl reload waf"
poll_interval_seconds = 15
```
```sh
export WAF_AGENT_TOKEN='svc-token'    # a §8 service token (any role; rules are not secret)
cargo run -p waf-node-agent -- node-agent.toml
```
Each cycle: `GET /api/rules/current` → if the version is new, pre-validate → **valid**: write the file +
run `reload_command` + `POST /api/rules/status {applied}`; **invalid**: `POST {rejected, detail}` and
leave the WAF untouched.

### 3. Publish / roll back (API)

```sh
B=http://127.0.0.1:9600
T='Authorization: Bearer svc-token'     # or an operator/admin session cookie
# Publish a new version (becomes current). Content = the full managed .conf text.
curl -s -H "$T" -H 'content-type: application/json' -X POST $B/api/rules/versions \
  -d '{"content":"SecRule ARGS \"@rx (?i)attacktoken\" \"id:9001,phase:2,severity:CRITICAL,block\"","note":"block token"}'
curl -s -H "$T" $B/api/rules/versions          # history (each flagged current or not)
curl -s -H "$T" $B/api/rules/versions/<id>     # one version, full content
curl -s -H "$T" -H 'content-type: application/json' -X POST $B/api/rules/rollback -d '{"version":<id>}'
curl -s -H "$T" $B/api/rules/nodes             # per-node convergence (applied version + last outcome)
```
Within `poll_interval_seconds` the agent applies it; the attack token then returns **403** on that node.
A **rollback** re-points `current` to an older version; the agents converge on the next poll.

### 4. UI (dashboard)

The **Rules** view (nav shown to operator+/admin, or in token mode) has three panels: **Publish**
(a SecRule editor + note), **Versions** (history with the *current* badge, "Load into editor", and
"Roll back to this"), and **Node convergence** (each node's applied version + last outcome). RBAC is
enforced by the backend regardless of the (cosmetic) nav gating.

### 5. Automated bite-tests

```sh
cargo test -p waf-node-agent                   # unit: validate (valid/invalid/empty), atomic write
export WAF_CP_DATABASE_URL=postgres://postgres:pw@localhost:5433/postgres
cargo test -p waf-node-agent --test e2e        # env-gated: publish → agent validate+write → reload
# e2e.rs: a REAL Proxy (blocking + CRS on a managed .conf) + the REAL control-plane API → publish a
# blocking rule → the agent's poll_once pulls+validates+writes → reload_from IN-PROCESS (simulating the
# SIGHUP the reload_command sends) → the SAME request flips 200 → 403 + the node reports convergence.
# Then an INVALID version (missing id) is published → the agent REJECTS it (level-1 fail-safe) and the
# WAF is left untouched (still 403 by the previous version).
cargo test -p waf-controlplane --test governance   # HTTP e2e also covers rule RBAC (viewer 403 on publish)
```

Notes: SIGHUP is Unix; the in-process `reload_from` exercises the same reload path cross-platform. The
manage API stores content **verbatim** (a server-side dry-run that links the parser is a declared
follow-on) — the agent's pre-validation is the enforcing gate before the WAF is touched. Follow-on:
canary/staged rollout, version diff/preview, multiple named rulesets, ruleset signing, WebSocket for
live convergence.

## J. SAML SSO via an IdP broker (Keycloak / Dex)

**The control plane does NOT implement native SAML** (frozen decision 2026-07-07 — `BOUNDARY.md` §2.3 /
`ARCHITECTURE_ENTERPRISE.md` §8). Native SAML means verifying **XML-DSig** (C14N canonicalization +
XML-Signature-Wrapping), the bug class that has broken mature SAML libraries for years; a hand-rolled
validator would be false security, and the one mature crate (`samael`) pulls `xmlsec`/`libxml2` (C, a CVE
history) — betraying the pure-Rust/no-C posture in the *trust* crate. So the control plane speaks **only
OIDC** (§G), and a **SAML customer IdP is federated behind an OIDC broker**. The XML-DSig risk is owned by
a project whose job that is (Keycloak / Dex), not by us.

```text
customer SAML IdP ──SAML──> [ Keycloak / Dex broker ] ──OIDC (Auth Code + PKCE)──> waf-controlplane
        (ADFS, Shibboleth, an old Okta SAML app, …)      (the broker verifies XML-DSig)   (§G, unchanged)
```

### With Keycloak (already used for OIDC in §G)

The control plane's OIDC config (§G) is **unchanged** — it still points at the Keycloak realm. You only
add the customer's SAML IdP to that realm:

1. Keycloak admin → realm `waf` → **Identity Providers → Add provider → SAML v2.0**.
2. Set the IdP's **Service Provider Entity ID** + **Single Sign-On Service URL** from the customer's SAML
   metadata (paste their metadata URL/XML; Keycloak imports the signing certificate).
3. Add an **Attribute Importer** mapper: the SAML assertion attribute carrying groups/roles (e.g.
   `http://schemas.xmlsoap.org/claims/Group` or `memberOf`) → a Keycloak **group** or user attribute.
4. Ensure that group/attribute flows into the OIDC **`groups`** claim Keycloak issues to `waf-cp` (the
   `role_claim` the control plane maps — §G `role_map`, e.g. `waf-admins → admin`). No control-plane change.
5. In the UI the existing **"Sign in with SSO"** button now lands on Keycloak, which offers the SAML IdP;
   after the SAML round-trip Keycloak issues the OIDC id_token and the control plane provisions the user
   (`auth_source = oidc`) and maps the role — exactly as in §G.

### With Dex (lightweight alternative)

Dex config: add a `connectors: [{ type: saml, ... }]` block (IdP SSO URL + CA/cert + a `groupsAttr`), and
register the control plane as a `staticClients` OIDC client (the `redirect_url` = `…/api/auth/oidc/callback`).
Point `[controlplane.governance.oidc].issuer_url` at Dex. Same OIDC path as §G.

Cost to us: this page. If real paying-customer demand is blocked by the broker path, native SAML is
reconsidered as a follow-on — and ONLY toward `samael`, never a pure-Rust hand-roll.

## K. Compliance reports (SOC2 / PCI-DSS, §8)

A period-scoped, **signed** evidence bundle assembled from data the system already holds — access
control (governance), the tamper-evident audit log, and the WAF telemetry — with each section
annotated with the SOC2 / PCI-DSS controls it supports. **Read-only, zero-core/zero-datapath**
(it only aggregates existing stores) and **admin-only** (`ViewAudit`). Available only with
**governance enabled** (it reuses the audit signer + chain). SAML is out of scope by design (§J);
native SAML would not affect this.

### Generate + verify (API)

```sh
B=http://127.0.0.1:9600
# Admin session cookie (see §F) or an admin bearer.
COOKIE='Cookie: waf_cp_session=<sid>'
# Default period = the last 90 days; override with RFC3339 from/to.
curl -s -H "$COOKIE" "$B/api/compliance/report" > report.json
curl -s -H "$COOKIE" "$B/api/compliance/report?from=2026-04-01T00:00:00Z&to=2026-07-01T00:00:00Z" > q2.json

# Re-verify a bundle (recomputes the content hash + checks the Ed25519 signature; the public key is
# carried inside the bundle, so an auditor can also verify it offline with the documented method).
curl -s -H "$COOKIE" -H 'content-type: application/json' -X POST "$B/api/compliance/verify" \
  --data-binary @report.json                      # → {"ok":true}
```

### What's in the bundle

```jsonc
{
  "report_version": 1,
  "period": { "from": "…", "to": "…" }, "generated_at": "…", "generated_by": "admin",
  "sections": {
    "access_control":   { "total_users", "admins", "disabled_accounts", "active_sessions",
                          "auth_sources", "users[]", "service_tokens[]",
                          "controls": ["SOC2 CC6.1","PCI 8.1", …] },     // SOC2 CC6 · PCI 7/8
    "audit_integrity":  { "chain_ok", "verified_through_seq", "chain_head_hash", "total_records",
                          "break_reason", "events_in_period{…}", "sample[]",
                          "controls": ["SOC2 CC7.2","PCI 10.5", …] },    // SOC2 CC7 · PCI 10
    "waf_effectiveness":{ "denied_in_period[]", "top_rules[]", "nodes_covered[]",
                          "cumulative_totals[]", "caveat",
                          "controls": ["PCI 6.4.2", …] },                // PCI 6.4.2/11 · SOC2 CC7.1
    "alerts_incidents": { "total", "fired_alerts[]", "controls": ["PCI 10.6", …] }
  },
  "content_hash": "<sha256 hex>", "signature": "<ed25519 hex>", "public_key": "<hex>"
}
```

Reading it:
- **`audit_integrity.chain_ok`** attests the WHOLE signed audit chain verified (continuity + every
  hash + every signature); `verified_through_seq` is how far it holds. This is the SOC2/PCI evidence
  that the operator-action log is tamper-evident.
- The bundle is itself **signed**: `content_hash` = SHA-256 of the canonical body, `signature` =
  Ed25519 over it (the audit key). Any later edit to the body fails `POST /api/compliance/verify`.
- **CAVEAT (stated in `waf_effectiveness.caveat`)**: **denied** counts are period-accurate (each
  denied request is a timestamped row); **allowed / total** volumes are *cumulative counter snapshots*,
  NOT scoped to the period (Prometheus counters are cumulative; only denied events have per-event
  rows). Period-accurate allowed volume is a declared follow-on.

### UI

The **Compliance** view (admin nav) picks a from/to range → **Generate** → renders the audit-integrity
banner, the four sections (with their SOC2/PCI control chips), and the signature footer, with
**Verify signature** and **Print** (browser print-to-PDF; a native PDF is a follow-on) buttons.

### Automated bite-test

```sh
export WAF_CP_DATABASE_URL=postgres://postgres:pw@localhost:5433/postgres
cargo test -p waf-controlplane --lib compliance      # pure: build + sign + verify + tamper + broken-chain
cargo test -p waf-controlplane --test governance     # HTTP e2e: generate → verify ok → tamper → fail + RBAC 403
```

Follow-on: a native PDF, an immutable archive of generated reports (evidence history) + listing, a
dedicated `auditor` role, separate per-framework reports, scheduled/emailed reports.

## L. SIEM export (§9)

A background **forwarder** PUSHes the stored events (denied WAF verdicts + the signed audit log + fired
alerts) to configured SIEM sinks, normalized into a **versioned, ECS-like** event (NDJSON over HTTP).
**Read-only, zero-datapath** (it reads the control-plane stores; the WAF is unaware). The raw OPEN logs
are already shippable via a log shipper (§C) — the SIEM connector adds *normalization + correlation + the
signed audit stream + delivery reliability*.

**At-least-once**: a `(destination, stream)` cursor advances ONLY after the whole batch is acked (HTTP
2xx); on any failure it stays put and the batch is retransmitted next cycle. The SIEM dedups on the stable
`event.id` (`waf-decision-<id>` / `waf-audit-<seq>` / `waf-alert-<id>`). The buffer is Postgres itself
(bounded by `retention_days`) — no in-memory queue; a sink that is down just lets the **lag** grow, which
is the key operational signal (`GET /api/siem/status`).

### Configure

```toml
[controlplane.siem]
enabled = true
flush_interval_seconds = 10        # temporal batching, not event-per-event
batch_size = 500

[[controlplane.siem.destinations]]
name = "splunk"
endpoint = "https://splunk:8088/services/collector/event"
# The Authorization header VALUE. Prefer the env var WAF_CP_SIEM_AUTH_SPLUNK over the file.
# auth_header = "Splunk <hec-token>"     # Elastic: "ApiKey <key>"
format = "ecs"                      # v1: ecs (NDJSON). cef/leef/syslog = follow-on
streams = ["decisions", "audit", "alerts"]

[[controlplane.siem.destinations]]
name = "elastic"
endpoint = "https://elastic:9200/waf-events/_doc"
streams = ["decisions"]            # each destination exports its own subset
```

```sh
export WAF_CP_SIEM_AUTH_SPLUNK='Splunk 00000000-0000-0000-0000-000000000000'   # secret out of the file
cargo run -p waf-controlplane -- controlplane.toml       # boot logs "siem export enabled; starting forwarder"
```

### Event shape (ECS-like, versioned)

```jsonc
{ "version": 1, "@timestamp": "…",
  "event": { "kind": "alert", "category": ["network","intrusion_detection"],
             "action": "blocked", "outcome": "failure", "id": "waf-decision-1234" },
  "source": { "ip": "203.0.113.7" },
  "http": { "request": { "method": "GET" } }, "url": { "path": "/x" },
  "rule": { "id": "sqli-union" },
  "observer": { "vendor": "Light WAF", "product": "waf", "version": "0.1.0" },
  "waf": { "node": "edge-1", "score": { "total": 6 },
           "contributions": [ { "module": "sqli", "rule_id": "sqli-union", "severity": "critical", "points": 6 } ] } }
```
ECS field names where the mapping is obvious; the WAF domain lives under `waf.*`. The schema carries its
own `version` — we promise OUR schema, not conformance to an external one. Audit events add
`waf.audit.{seq,hash,signature}`; alert events add `waf.alert.{rule,group,value,threshold,severity}`.

### Test against a mock sink + read the status

```sh
# A trivial NDJSON receiver (nc / a tiny server); or point at a real HEC/Elastic endpoint.
B=http://127.0.0.1:9600
T='Authorization: Bearer <api_token>'   # or an operator session
curl -s -H "$T" "$B/api/siem/status" | jq   # per (destination, stream): cursor, head, LAG, last_success/error
```
`lag` climbing and a `last_error` on a destination means the sink is unreachable — the forwarder keeps
retrying from the cursor, so nothing is lost until it exceeds retention.

### Automated bite-test

```sh
export WAF_CP_DATABASE_URL=postgres://postgres:pw@localhost:5433/postgres
cargo test -p waf-controlplane --lib siem            # pure: event mapping + NDJSON framing
cargo test -p waf-controlplane --test siem           # e2e: at-least-once (fail → cursor held) + 3 streams + status API
```

Follow-on: CEF/LEEF/syslog formatters (+ syslog transport) and vendor adapters (Splunk HEC envelope,
Elastic `_bulk`) as variants over the SAME event; a control-plane-native Prometheus `/metrics`
(`siem_forwarder_lag`); TLS client certs to the sink; a per-event dead-letter queue; export filters;
OTLP; a SIEM status UI.

## M. Web UI end-to-end (Playwright)

A committed Playwright suite (`crates/waf-controlplane/ui/tests/e2e/`) drives the SPA in a real browser
against the **real backend** — two `waf-controlplane` binaries (built with `embed-ui`), one in **token
mode** (governance off) and one in **session mode** (governance on), both on the same Postgres. It
replaces the ad-hoc puppeteer smokes with a maintainable, repeatable suite.

### Run it

```sh
# 1. A throwaway Postgres (a FRESH DB is assumed so the session binary bootstraps `admin`).
docker run -d --name waf-e2e-pg -p 5432:5432 -e POSTGRES_PASSWORD=pw postgres:16
export WAF_CP_DATABASE_URL=postgres://postgres:pw@localhost:5432/postgres

cd crates/waf-controlplane/ui
npm ci                       # install (incl. @playwright/test)
npx playwright install chromium
npm run e2e                  # = npm run build (embeds the UI) + build the release binary + playwright test
```

`npm run e2e` chains: `npm run build` (produces `ui/dist`, embedded into the binary) → `npm run
e2e:server` (`cargo build --release --features embed-ui`) → `playwright test`. Playwright's `webServer`
launches the two binaries (ports 9701 token / 9702 session); `global-setup` seeds a viewer (`alice`) and
a few denied events via the API. Reports: `npm run e2e:report` (HTML); interactive mode: `npm run e2e:ui`.

### What it covers

Two Playwright **projects** (token / session), one browser (Chromium):
- **Smoke** — the SPA is served and `/api/version` + `/api/auth/config` respond (both modes).
- **Auth** — the token gate rejects a bad token and admits the real one; session login rejects a wrong
  password, admits the admin (with the right role + admin nav), logs out; no SSO button without OIDC.
- **RBAC** — a viewer (`alice`) sees no admin nav AND the backend returns **403** on a direct admin route.
- **Views** — every view renders (Overview / Events / Alerts / Rules / Users / Tokens / Audit /
  Compliance / Account); the **Events drill-down** reconstructs a verdict + score breakdown.
- **Flows** — publish a rule → a new **current** version; generate a **compliance** report → sections +
  the audit-integrity banner → **Verify signature**; verify the **audit chain**; mint a service token
  (the plaintext is revealed once).
- **Live (SSE)** — with the Events view open, a fresh event ingested via the API surfaces in the table
  **without a manual reload**, well under the 20s poll fallback: end-to-end proof that the
  "notify-then-pull" stream (`GET /api/stream` → silent refresh) drives the live dashboard.

### Notes

- **Env-gated**: without `WAF_CP_DATABASE_URL` the harness fails fast with a clear message (mirrors the
  Rust bite-tests). Use a FRESH/throwaway DB (the session binary only bootstraps `admin` when there are
  zero users; the audit chain accumulates across runs otherwise).
- Non-secret test fixtures (`e2e-token`, admin password) live in `playwright.config.ts` — a throwaway DB.
- Selectors are accessible/text-based (roles, placeholders, panel headings); no production code change.

### CI

A GitHub Actions workflow runs this suite on every push/PR touching `enterprise/**`:
`.github/workflows/e2e.yml`. It brings up a `postgres:16` service, installs Rust + Node 22 +
the chromium browser, then runs `npm run e2e` (build UI → build the release binary → `playwright test`)
against `WAF_CP_DATABASE_URL`. Actions sets `CI=true`, so Playwright starts fresh servers, retries once,
and forbids `.only`; the HTML report is uploaded as an artifact. Cargo and npm caches keep re-runs fast.

Follow-on: **OIDC/Keycloak** E2E, Firefox/WebKit, visual-regression snapshots, exhaustive per-view
interactions, an API-mock lane for fast feedback.
