<!-- SPDX-FileCopyrightText: 2026 0x00spor3
     SPDX-License-Identifier: BUSL-1.1 -->

# 6. Governance & access control

Governance turns the control plane from a single-token service into a multi-user, role-based system
with SSO, service tokens, and a tamper-evident audit log. It is **default-off**: with governance off,
the control plane keeps the single static bearer token and none of the endpoints below exist.

Everything here runs in the control plane — it is zero-datapath and never touches the WAF.

## Enable it

```toml
[controlplane.governance]
enabled           = true
session_ttl_hours = 12
cookie_secure     = true        # set false only for local http dev
bootstrap_admin   = "admin"     # created if there are zero users at boot
```

Two environment secrets are required:

| Env var | What it is |
|---|---|
| `WAF_CP_AUDIT_KEY` | 64 hex chars (an Ed25519 seed) that signs the audit chain. **Must persist across restarts** or the chain becomes unverifiable under a new key. |
| `WAF_CP_BOOTSTRAP_ADMIN_PASSWORD` | the initial password for `bootstrap_admin`, used once when there are no users. |

On first boot with no users, the bootstrap admin is created; log in and create the rest. When
governance is on, `/api/*` is gated by either a **session cookie** (a human, with RBAC per role) or the
**bearer token** (a machine/admin principal).

## Roles (RBAC)

Three built-in roles, each a superset of the previous:

| Role | Can do |
|---|---|
| `viewer` | read observability — Overview, Events, Alerts, and the read API |
| `operator` | everything a viewer can, **plus** manage rules (publish/rollback) |
| `admin` | everything, **plus** user & token management, sessions, the audit log, and compliance reports |

The dashboard hides views a role can't use, but the gating is enforced by the **backend** — a viewer
who calls an admin endpoint gets `403` regardless of the UI.

## Users

Admins manage local accounts from the **Users** view (or `GET/POST /api/users`,
`PATCH/DELETE /api/users/{id}`):

- create a user with a username, password, and role;
- change a user's role inline;
- disable/enable an account (disabling revokes its sessions immediately);
- reset a local user's password (revokes their sessions);
- delete an account.

SSO-provisioned users show a source of `oidc` and manage their password at the identity provider, not
here.

## Service tokens

Named, revocable, role-bound tokens for machines (the node agent, CI, scripts) — created under
**Tokens** (`GET/POST /api/tokens`, `DELETE /api/tokens/{id}`, admin). A token's role bounds what it
can do, exactly like a user's. The plaintext is shown **once** at creation — copy it then; it can't be
retrieved later, only revoked.

## Sessions & passwords

- **Your sessions** — the **Account** view lists your active sessions and lets you revoke any but the
  current one (`GET /api/sessions`, `DELETE /api/sessions/{id}`).
- **Change your password** — from Account; this revokes your *other* sessions
  (`POST /api/me/password`).
- **Admin reset** — an admin can reset any local user's password (`POST /api/users/{id}/password`) and
  revoke all of a user's sessions (`DELETE /api/users/{id}/sessions`).

### Login throttle

Brute-force protection locks out a username after too many failed logins in a window:

```toml
[controlplane.governance]
login_max_failures  = 5
login_window_seconds = 60
login_lockout_seconds = 300
```

## SSO via OpenID Connect

Modern SSO uses OIDC (Authorization Code + PKCE). The IdP is discovered from `issuer_url`; login goes
through the browser and ends in a session cookie. A role is mapped from a claim (typically IdP groups);
a user matching no mapping is denied unless `default_role` is set.

```toml
[controlplane.governance.oidc]
issuer_url   = "https://idp.example.com/realms/waf"
client_id    = "waf-cp"
redirect_url = "https://cp.example.com/api/auth/oidc/callback"
role_claim   = "groups"
default_role = "viewer"       # optional; omit to DENY users matching no role_map entry

[[controlplane.governance.oidc.role_map]]
claim = "waf-admins"
role  = "admin"
```

The client secret comes from `WAF_CP_OIDC_CLIENT_SECRET`. When OIDC is configured, the login screen
shows a **Sign in with SSO** button in addition to username/password. SSO users are provisioned
locally with `auth_source = oidc` and never collide with local accounts.

> **SAML.** Native SAML is intentionally not supported. Federate a SAML IdP behind an OIDC broker
> (Keycloak/Dex) and point the control plane at the broker — see the runbook and BOUNDARY for the
> rationale.

## The audit log

Every governance action (logins, user/token/session changes, password changes, rule publishes and
rollbacks) is written to a **signed, hash-chained** audit log. Each record links to the previous by
hash and is signed with the audit key, so any insertion, deletion, or edit breaks the chain.

- **View** — the **Audit** view (admin) shows records newest-first (`GET /api/audit`).
- **Verify** — **Verify chain** recomputes the hash chain and checks every signature
  (`GET /api/audit/verify`), reporting the number of records verified and the signing public key, or
  the exact sequence where the chain broke.

Because the chain is keyed by `WAF_CP_AUDIT_KEY`, keep that seed stable across restarts and back it up —
losing it means past records can no longer be verified under the same public key.

Next: [Compliance & SIEM](07-compliance-and-siem.md).
