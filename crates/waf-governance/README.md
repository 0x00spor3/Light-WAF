# waf-governance (enterprise, Apache-2.0)

Governance for the Light WAF control plane (`ARCHITECTURE_ENTERPRISE.md` §8): **RBAC**, **local
authentication** and a **tamper-evident signed audit log**.

- **Control-plane library, zero-core / zero-datapath.** It is linked by `waf-controlplane`, never by
  the WAF binary, and never touches the request path. It operates on the control plane's Postgres
  (`&PgPool`) and owns its own schema (`store::apply_schema`).
- **v1 scope:** local user accounts (argon2id) + server-side sessions + three fixed RBAC roles
  (`viewer` / `operator` / `admin`) + the signed audit chain.
- **v2 scope:** SSO helpers (OIDC claim→role mapping, verified-JWT payload decode — the OIDC HTTP flow
  lives in the control plane), named service tokens (hashed), OIDC-federated user upsert, session
  management, and an in-memory login brute-force throttle. SAML, a governance UI, automated compliance
  reports and the §7 rule-management write path build on top.

## Modules

| Module | What it provides |
|---|---|
| `rbac` | `Role` (viewer < operator < admin), `Permission`, and the pure `Role::allows` matrix. |
| `password` | argon2id `hash_password` / `verify_password` (PHC strings). |
| `audit` | SHA-256 hash chain + Ed25519 signatures (`ring`); `AuditSigner`, `verify_chain`. |
| `token` | Opaque 256-bit session-id generation. |
| `model` | `User` / `Session` / `AuditRecord` / `NewAudit`. |
| `store` | Postgres query fns over `&PgPool` (users, sessions, `append_audit` with an advisory lock). |

## Audit chain

Each audit record commits to the previous record's hash and is signed:

```
hash      = SHA256(seq ‖ ts_micros ‖ actor ‖ action ‖ target ‖ details ‖ prev_hash)
signature = Ed25519(sign_key, hash)
```

Altering or dropping any record breaks the chain (detectable via `verify_chain` / `GET
/api/audit/verify`); forging a record needs the signing key. The signing seed is supplied out of band
(env `WAF_CP_AUDIT_KEY`) and must persist across restarts so the chain stays verifiable under a stable
public key.

## Tests

Pure unit tests run with no database. The store integration tests are **env-gated** on
`WAF_CP_DATABASE_URL` (skipped when unset), mirroring the rest of the enterprise tier:

```sh
docker run -d --name waf-cp-pg -p 5432:5432 -e POSTGRES_PASSWORD=pw postgres:16
WAF_CP_DATABASE_URL=postgres://postgres:pw@localhost:5432/postgres cargo test -p waf-governance
```
