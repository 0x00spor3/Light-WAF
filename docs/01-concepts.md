<!-- SPDX-FileCopyrightText: 2026 0x00spor3
     SPDX-License-Identifier: Apache-2.0 -->

# 1. Concepts

Read this once. Everything else in the guide — tuning, the dashboard, rule management — assumes the
model described here.

## How a request is judged

Light WAF is a reverse proxy. Every request that arrives is inspected by a pipeline of **detection
modules** before it is allowed to reach your backend. Modules run in phases as the request is read:

```
client ──▶  Connection ──▶ Headers ──▶ Body ──▶  backend
                 │            │          │
              rate limit   header      SQLi / XSS / RCE / … content inspection
              IP reputation smuggling  CRS rules, schema enforcement
```

No single module decides the outcome on its own. Instead each module that matches contributes
**points** to a cumulative **anomaly score** for that request. When the score reaches the configured
**block threshold**, the request is denied. This is the one idea the whole product is built around:
*risk accumulates, and a verdict is reached when it crosses a line.*

```
score = Σ (points of every rule that matched)
verdict = blocked   if score ≥ block_threshold
          allowed   otherwise
```

### Points come from severity

A rule does not carry a hard-coded point value. It declares a **severity**, and severity maps to
points through one table you control ([`[waf.severity_scores]`](03-waf-configuration.md#severity-scores--the-block-threshold)):

| Severity | Default points | Meaning |
|---|---:|---|
| `critical` | 6 | high-confidence, single-rule block-worthy signal (e.g. a clear SQLi) |
| `error` | 4 | strong signal |
| `warning` | 3 | suspicious, meaningful only in combination |
| `notice` | 2 | weak signal, accumulation-only |

With the default `block_threshold = 5`, a single `critical` (6) blocks on its own merit, while two
`warning`s (3 + 3 = 6) also block — two weak signals together are treated as one strong one. A lone
`notice` (2) never blocks by itself. **Tuning the WAF is tuning this relationship** between the
threshold and the severities, not editing individual rules.

## Verdicts

A finished request carries one verdict. The ones you will see in the dashboard and logs:

| Verdict | What happened |
|---|---|
| `allowed` | score stayed under the threshold; the request reached the backend |
| `blocked` | score crossed the threshold; the request was denied (403) |
| `rejected` | denied on a **structural** rule before scoring — malformed framing, an oversized body, an illegal HTTP construct (returns 400/413/etc.) |

`blocked` and `rejected` are the two *denied* outcomes. The control plane stores every denied event
(with its score breakdown); allowed traffic is counted but not stored per-request.

## Blocking vs detection mode

The `[waf].mode` switch decides whether the WAF enforces or only observes:

- **`blocking`** (recommended for production) — denied verdicts return an error to the client.
- **`detection`** — nothing is blocked; verdicts are computed and logged/exported but every request
  is forwarded. Use this to tune a new ruleset against live traffic before enforcing.

## Resilience posture: what happens when *the WAF* is in trouble

Security modules **fail closed** — if inspection can't complete, the safe default is to deny. But not
every failure is a security event. The `[resilience]` section makes the posture explicit per
scenario (upstream down, a module panics, a bad config reload, a normalization limit hit). This is
covered in [Operations](08-operations.md#resilience-posture). The one rule to remember: a *down
rate-limiter* (infrastructure) fails **open** so it never blocks legitimate traffic, while a *failed
inspection* (security) fails **closed**.

## Core and components

Light WAF is built in two layers, both open source (Apache-2.0):

- **Core** — the proxy engine, the detection pipeline, the native rule modules
  (SQLi, XSS, RCE, path traversal, SSRF, LDAP/NoSQL/SSTI/…), the CRS rule engine, TLS termination
  from a file, and single-node rate limiting. A WAF built only from the core is a complete,
  standalone product (the `waf` binary, crate `waf-proxy`).
- **Components** — the *at-scale* and *governed* capabilities layered on
  top through the core's extension points, **without forking the core**: cluster-wide rate limiting
  and IP reputation (Redis), managed ACME TLS, curated CRS content, GraphQL/gRPC schema
  enforcement, bot detection, signed WASM plugins — and the three off-datapath services (control
  plane, dashboard, node agent) that give you a dashboard, governed rule management, alerting,
  compliance evidence, and SIEM export. The `waf-enterprise` binary is the data plane with
  every component wired in.

Every component capability is **default-off** and opt-in via an `[enterprise.*]` or
`[controlplane.*]` config table. Turning them all off leaves you with exactly the core
behavior. The rest of this guide notes which layer each feature belongs to; operationally you configure
them the same way. See [`BOUNDARY.md`](../BOUNDARY.md) for the full split.

Next: [Getting started](02-getting-started.md).
