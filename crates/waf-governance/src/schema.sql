-- SPDX-License-Identifier: BUSL-1.1
-- Governance schema (§8). Owned by `waf-governance` and applied idempotently by the control plane
-- after its own migrations (see `apply_schema`). Idempotent CREATE ... IF NOT EXISTS so it is safe
-- to run on every boot.

-- Operator accounts. `role` is a fixed RBAC role string. `auth_source` is 'local' (argon2 password)
-- or 'oidc' (federated, no local password). Added in v2 via idempotent ALTERs so v1 installs upgrade
-- in place; `password_hash` is nullable so OIDC users need no password.
CREATE TABLE IF NOT EXISTS gov_users (
    id            BIGSERIAL PRIMARY KEY,
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT,
    role          TEXT NOT NULL,
    disabled      BOOLEAN NOT NULL DEFAULT FALSE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE gov_users ADD COLUMN IF NOT EXISTS auth_source TEXT NOT NULL DEFAULT 'local';
ALTER TABLE gov_users ALTER COLUMN password_hash DROP NOT NULL;

-- Server-side sessions. The opaque `id` is carried in an HttpOnly cookie; expiry is enforced here.
CREATE TABLE IF NOT EXISTS gov_sessions (
    id         TEXT PRIMARY KEY,
    user_id    BIGINT NOT NULL REFERENCES gov_users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS gov_sessions_user ON gov_sessions(user_id);

-- Signed, hash-chained audit log of operator/admin actions (distinct from the OPEN decision-log).
-- `seq`/`ts` are ASSIGNED BY THE APPLICATION (not DB defaults) so the record is fully reproducible
-- from its stored columns: hash = SHA256(seq || ts_micros || actor || action || target || details ||
-- prev_hash); signature = Ed25519(hash). `details` is the EXACT canonical JSON string that was
-- hashed (stored as TEXT, not JSONB, so verification round-trips byte-for-byte).
CREATE TABLE IF NOT EXISTS gov_audit_log (
    seq        BIGINT PRIMARY KEY,
    ts         TIMESTAMPTZ NOT NULL,
    actor      TEXT NOT NULL,
    action     TEXT NOT NULL,
    target     TEXT,
    details    TEXT NOT NULL,
    prev_hash  TEXT NOT NULL,
    hash       TEXT NOT NULL,
    signature  TEXT NOT NULL
);

-- Named, revocable API service tokens (v2). Only the SHA-256 of the token is stored; the plaintext is
-- shown once at creation. Each token carries a role → clean per-integration attribution in the audit.
CREATE TABLE IF NOT EXISTS gov_tokens (
    id         BIGSERIAL PRIMARY KEY,
    name       TEXT NOT NULL UNIQUE,
    token_hash TEXT NOT NULL,
    role       TEXT NOT NULL,
    revoked    BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS gov_tokens_hash ON gov_tokens(token_hash);

-- In-flight OIDC login flows (v2): the PKCE verifier + nonce keyed by the opaque `state`, so they
-- survive the browser redirect roundtrip. Consumed (deleted) on callback; stale rows are pruned.
CREATE TABLE IF NOT EXISTS gov_oidc_flows (
    state         TEXT PRIMARY KEY,
    pkce_verifier TEXT NOT NULL,
    nonce         TEXT NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
