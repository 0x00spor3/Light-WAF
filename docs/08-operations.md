<!-- SPDX-FileCopyrightText: 2026 0x00spor3
     SPDX-License-Identifier: Apache-2.0 -->

# 8. Operations

Day-2 concerns: reloading config, the failure posture, monitoring, backups, and a troubleshooting
index.

## Reloading configuration

The WAF reloads on **SIGHUP** with **validate-then-swap**: it parses the new config, and only applies
it if it's valid — otherwise it keeps the last-good config running (governed by
`on_config_error`). This makes reloads safe to automate.

```sh
kill -HUP "$(cat /run/waf.pid)"     # or: systemctl reload waf
```

Injected enterprise state survives a reload: the distributed rate-limit store, the reputation module,
and other injected modules are re-initialized and reused, so a reload never silently drops you back to
single-node behavior. (Rule content managed by the [node agent](05-rule-management.md) is applied via
this same SIGHUP path.)

## Resilience posture

The [`[resilience]`](03-waf-configuration.md#resilience) section is the contract for what happens when
the WAF itself is degraded. The principle:

- **Security failures fail closed.** If inspection can't complete (a normalization limit, a hard TLS
  error at boot), the safe default is to deny or refuse to start — never a silent downgrade.
- **Infrastructure failures fail open.** A down rate-limiter or reputation feed must not block
  legitimate traffic, so at *runtime* those degrade to *allow* (loudly logged). This is why
  `[enterprise].fail_open` defaults to `true` — but an unreachable Redis at **boot** is always fatal,
  so a misconfiguration can't quietly run single-node.

Set `on_internal_error = "fail_open"` (the default) so a bug in one module can't take the site down;
set `on_upstream_error` per your preference for origin outages (502 closed vs 503 retryable).

## Monitoring

- **The WAF** exposes Prometheus `/metrics` — request volumes, per-decision counters, and latency
  histograms. Scrape it with your own Prometheus and/or list the node under the control plane's
  `[[controlplane.nodes]]` to feed the dashboard.
- **The control plane dashboard** is the operator's day-to-day view: block rate and traffic
  disposition on Overview, denied-event drill-down on Events, and cluster status (which nodes are
  reporting).
- **SIEM lag** — if you export to a SIEM, watch `GET /api/siem/status`; rising lag means the SIEM isn't
  keeping up.
- **Audit integrity** — periodically run **Verify chain** (Audit view) or `GET /api/audit/verify`.

## Backups & retention

- **Postgres** holds all control-plane telemetry, governance state, and the audit log. Back it up like
  any production database. Telemetry is trimmed by `retention_days` (0 = keep forever); size the disk
  for your traffic × retention.
- **The audit key** (`WAF_CP_AUDIT_KEY`) must persist across restarts and be backed up securely —
  without the same seed, past audit records can't be verified under the same public key.
- **The ACME cache** (`cache_dir`) persists the account and certificates across restarts; back it up to
  avoid re-issuing on every redeploy (and to stay under CA rate limits).

## Version drift

The dashboard warns if the UI and API versions differ (a banner across the top) — a reminder to reload
after deploying a matching build. In the single-binary (`embed-ui`) deployment the two are built
together and never drift; the banner is mainly for the dev-override serving mode.

## Troubleshooting

| Symptom | Likely cause & fix |
|---|---|
| **Every client is rate-limited together / all events show the LB's IP** | `trusted_proxies` is empty, so `X-Forwarded-For` is ignored and everyone shares the proxy's IP. Set `[network].trusted_proxies` to your LB/CDN CIDRs and `trusted_hops` accordingly. |
| **WAF won't start, TLS error** | With `[tls].enabled = true`, an unreadable cert/key is fatal by design (no cleartext downgrade). Check `cert_path`/`key_path` and permissions. |
| **WAF won't start, Redis error** | An unreachable Redis at boot is fatal (so you never silently run single-node). Fix connectivity or remove `[enterprise].redis_url` to use the in-memory store. |
| **A new ruleset shows `rejected` on nodes** | The published version failed validation; the WAF kept the previous file (no impact). Check the node's detail message in the Rules convergence table — usually an invalid regex or missing rule id. |
| **Node stuck at an old version / `error`** | The agent couldn't write the file or run `reload_command`. Verify `managed_file` matches the WAF's `[modules.crs].files`, and that `reload_command` works as the agent's user. |
| **SIEM lag keeps rising** | The SIEM is rejecting or slow. Check the `last error` in `GET /api/siem/status`; the cursor only advances on a whole-batch 2xx, so a persistent 4xx/5xx stalls the stream until fixed. |
| **Compliance numbers look off** | Denied counts are period-accurate; allowed/total are cumulative counters (stated in the report). This is expected, not a bug. |
| **Dashboard shows the token prompt instead of a login form** | Governance is off (or the backend didn't load `/api/auth/config`). Enable `[controlplane.governance]` for user/password + SSO login. |
| **Audit "Verify chain" fails after a restart** | `WAF_CP_AUDIT_KEY` changed. Restore the original seed; the chain verifies only under the key that signed it. |

## Testing your setup

The dashboard ships with an end-to-end Playwright suite (`ui/tests/e2e/`) that drives the real UI
against a real control plane on Postgres — auth (both modes), RBAC, every view, and the key write flows.
Run it with `npm run e2e` (needs `WAF_CP_DATABASE_URL` and a fresh Postgres). It's a good smoke test
after upgrading.

Next: [Kubernetes deployment](09-kubernetes.md).
