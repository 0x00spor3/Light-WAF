<!-- SPDX-FileCopyrightText: 2026 0x00spor3
     SPDX-License-Identifier: BUSL-1.1 -->

# Light WAF — Operator Guide

This is the **functional and operational manual** for running Light WAF in production: how the
product is put together, how to install and configure each service, and how to run day-2 operations
(rule changes, governance, compliance, SIEM export, reloads, troubleshooting).

It is task-oriented — organized around what an operator actually does, not around the source tree.
For the *why* behind the design (the enterprise/core boundary, the extension seams), see
[`ARCHITECTURE_ENTERPRISE.md`](../ARCHITECTURE_ENTERPRISE.md) and [`BOUNDARY.md`](../../BOUNDARY.md).
For copy-paste runbooks per feature, see [`scripts/*/RUNBOOK.md`](../scripts).

## The three services

Light WAF is not a single process. An operator runs up to three cooperating services:

| Service | Binary | Role | On the request path? |
|---|---|---|---|
| **WAF proxy** | `waf-enterprise` | Terminates traffic, inspects every request, allows or blocks | **Yes** — this is the data path |
| **Control plane** | `waf-controlplane` | Collects telemetry, serves the dashboard + API, governs rules/users | No — separate service, read-only over telemetry |
| **Node agent** | `waf-node-agent` | Pulls published rulesets onto each WAF node and triggers a reload | No — sits beside the WAF, writes its rule file |

The proxy can run entirely on its own. The control plane and agent are added when you want a
central dashboard, governed rule management, alerting, compliance evidence, or SIEM export.

## Table of contents

1. [Concepts](01-concepts.md) — how a request is judged, the anomaly score and block threshold,
   verdicts and severities, editions (OPEN core vs enterprise).
2. [Getting started](02-getting-started.md) — prerequisites, building, and running each service; ports.
3. [WAF configuration](03-waf-configuration.md) — the full proxy config by task: TLS, rate limiting,
   client-IP resolution, limits, detection modules, CRS, resilience, and the enterprise modules.
4. [Control plane & dashboard](04-control-plane.md) — configuring the control plane, the dashboard
   tour (all views), auth modes, alerting, retention, scraping.
5. [Rule management](05-rule-management.md) — the write path: publishing and rolling back ruleset
   versions, the node agent, and watching convergence.
6. [Governance & access control](06-governance.md) — RBAC, local users, service tokens, sessions,
   SSO (OIDC), and the signed audit log.
7. [Compliance & SIEM](07-compliance-and-siem.md) — generating signed SOC2/PCI evidence bundles and
   forwarding events to a SIEM.
8. [Operations](08-operations.md) — reloads, fail-open/closed posture, monitoring, backups, and
   troubleshooting.

## A note on secrets

Every service reads its secrets from **environment variables that override the config file**, so the
`.toml` files can be committed safely. The recurring ones:

| Env var | Used by | What it is |
|---|---|---|
| `WAF_REDIS_URL` | proxy | Redis connection for cluster-wide rate limit / reputation |
| `WAF_CERT_STORE_KEY` | proxy | encrypts the ACME private key at rest (clustered DNS-01) |
| `CF_API_TOKEN`, `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY` | proxy | DNS-01 provider credentials |
| `WAF_CP_DATABASE_URL` | control plane | Postgres connection string |
| `WAF_CP_API_TOKEN` | control plane | static bearer token (governance off) |
| `WAF_CP_AUDIT_KEY` | control plane | Ed25519 seed (64 hex) signing the audit chain — **must persist** |
| `WAF_CP_BOOTSTRAP_ADMIN_PASSWORD` | control plane | initial admin password, used once |
| `WAF_CP_OIDC_CLIENT_SECRET` | control plane | OIDC client secret |
| `WAF_CP_SIEM_AUTH_<NAME>` | control plane | auth header for SIEM destination `<name>` |
| `WAF_AGENT_TOKEN` | node agent | control-plane service token |
