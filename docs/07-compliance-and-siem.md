<!-- SPDX-FileCopyrightText: 2026 0x00spor3
     SPDX-License-Identifier: Apache-2.0 -->

# 7. Compliance & SIEM

Two ways to get evidence out of the control plane: an **on-demand signed compliance report** for
auditors, and a **continuous SIEM feed** for your security operations pipeline. Both are read-only over
data the control plane already holds — zero-datapath, zero core.

## Compliance reports

A compliance report is a signed SOC2/PCI evidence bundle for a period, derived from the signed audit
log, governance state, and WAF telemetry. It requires governance on (it reuses the audit signer and the
admin `ViewAudit` permission).

### Generate one

From the **Compliance** view (admin):

1. Pick a **From / To** date range (defaults to the last 90 days).
2. **Generate**. The report renders with an integrity banner and four sections.
3. **Verify signature** re-checks the bundle's Ed25519 signature; **Print** produces a clean,
   paginated PDF via the browser (the rail and filters are hidden in print).

Or via the API:

```sh
curl "$CP/api/compliance/report?from=2026-04-01T00:00:00Z&to=2026-07-01T23:59:59Z" \
  -H "Authorization: Bearer $ADMIN_TOKEN" > report.json
curl -X POST "$CP/api/compliance/verify" -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H 'Content-Type: application/json' --data @report.json      # → {"ok": true}
```

### What's in it

Each section is annotated with the SOC2/PCI controls it satisfies:

| Section | Evidence |
|---|---|
| **Access control** | users, roles, admins, disabled accounts, active sessions, auth sources; service tokens |
| **Audit integrity & activity** | the hash-chain verification result (verified-through sequence, head hash), plus a period event summary (logins ✓/✗, throttled, admin actions, rule changes) |
| **WAF protection effectiveness** | denied traffic in the period, the most-triggered rules, and the nodes covered |
| **Alerts & incidents** | the alerts that fired in the period |

The bundle carries a `content_hash`, an Ed25519 `signature`, and the `public_key`, so an auditor can
verify it independently — the signature covers a canonical form of the body and survives JSON
round-tripping.

### One caveat to state to auditors

Denied counts are **period-accurate** (from stored decision events). Allowed/total counts are
**cumulative** counters, not period-scoped — the report says so in the WAF-effectiveness section. Read
denied numbers as "in this period"; read allowed/total as "lifetime of the counter".

## SIEM export

A background forwarder **pushes** stored events to your SIEM as versioned, ECS-like NDJSON. It's the
complement to the raw log shipper: the control plane sends *normalized, correlated, audit-signed*
events with delivery guarantees.

### Configure a destination

```toml
[controlplane.siem]
enabled                = true
flush_interval_seconds = 10       # temporal batching, not event-per-event
batch_size             = 500

[[controlplane.siem.destinations]]
name        = "splunk"
endpoint    = "https://splunk:8088/services/collector/event"
auth_header = "Splunk <hec-token>"    # or env WAF_CP_SIEM_AUTH_SPLUNK
format      = "ecs"                    # v1: ecs (NDJSON)
streams     = ["decisions", "audit", "alerts"]
```

The auth header is best supplied via `WAF_CP_SIEM_AUTH_<NAME>` (name upper-cased, non-alphanumerics →
`_`) — so `WAF_CP_SIEM_AUTH_SPLUNK` for the destination above. It is never exposed by the status API.

### The three streams

| Stream | Content |
|---|---|
| `decisions` | denied verdicts (with the score breakdown) |
| `audit` | the signed governance audit records |
| `alerts` | fired alerts |

### Delivery guarantees

- **At-least-once.** Each `(destination, stream)` has a cursor that advances **only** on a whole-batch
  `2xx` acknowledgement. If a batch fails, nothing advances and it is retried — so on a transient SIEM
  outage you get redelivery, not loss. The SIEM should dedup on the stable `event.id`.
- **Backpressure** is bounded by Postgres retention, not an in-memory queue — a slow SIEM can't OOM the
  control plane.
- **Lag** is the key health signal. Monitor it via `GET /api/siem/status`, which reports, per
  `(destination, stream)`, the cursor, the stream head, the lag between them, and the last
  success/error — without ever exposing the auth header.

```sh
curl "$CP/api/siem/status" -H "Authorization: Bearer $TOKEN"
```

Rising lag means the SIEM isn't keeping up (or is rejecting batches — check the last error). Multiple
destinations each keep their own cursor, so you can fan out to several SIEMs independently.

> Additional output formats (CEF/LEEF/syslog) and vendor adapters are on the roadmap; v1 emits ECS-like
> NDJSON over generic HTTP, which Splunk HEC and Elastic accept directly.

Next: [Operations](08-operations.md).
