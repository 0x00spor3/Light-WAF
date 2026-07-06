// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: BUSL-1.1

//! Postgres persistence for governance (operates on the control plane's `&PgPool`). Runtime queries
//! (no compile-time `query!`), so the crate builds with no database; the integration tests are
//! env-gated on `WAF_CP_DATABASE_URL`.

use std::str::FromStr;

use sqlx::postgres::PgPool;
use time::OffsetDateTime;

use crate::audit::{compute_hash, ts_micros, AuditSigner, GENESIS_PREV};
use crate::error::{Error, Result};
use crate::model::{AuditRecord, NewAudit, ServiceToken, Session, User, UserWithHash};
use crate::rbac::Role;

/// Advisory-lock key that serializes audit-chain appends (keeps the chain strictly linear).
const AUDIT_LOCK_KEY: i64 = 0x7761_665f_6175_6469; // "waf_audi"
/// Advisory-lock key that serializes schema application (concurrent `CREATE ... IF NOT EXISTS` can
/// race in Postgres).
const SCHEMA_LOCK_KEY: i64 = 0x7761_665f_7363_686d; // "waf_schm"

/// The governance schema (owned by this crate; see `schema.sql`).
pub const SCHEMA_SQL: &str = include_str!("schema.sql");

/// Apply the governance schema idempotently. The control plane calls this once at boot, after its
/// own migrations; it is safe to run repeatedly (`CREATE ... IF NOT EXISTS`). Uses the simple query
/// protocol (`raw_sql`) so the whole file — comments + multiple statements — runs in one call.
pub async fn apply_schema(pool: &PgPool) -> Result<()> {
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock($1)").bind(SCHEMA_LOCK_KEY).execute(&mut *tx).await?;
    sqlx::raw_sql(SCHEMA_SQL).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn row_to_user(
    id: i64,
    username: String,
    role: &str,
    disabled: bool,
    auth_source: String,
    created_at: OffsetDateTime,
) -> Result<User> {
    Ok(User { id, username, role: Role::from_str(role)?, disabled, auth_source, created_at })
}

// ── Users ───────────────────────────────────────────────────────────────────────────────────────

/// Number of accounts (used to decide whether to bootstrap the first admin).
pub async fn count_users(pool: &PgPool) -> Result<i64> {
    let (n,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM gov_users").fetch_one(pool).await?;
    Ok(n)
}

/// Create a user; returns the new id. A duplicate username maps to [`Error::Conflict`].
pub async fn create_user(pool: &PgPool, username: &str, password_hash: &str, role: Role) -> Result<i64> {
    let res = sqlx::query_as::<_, (i64,)>(
        "INSERT INTO gov_users (username, password_hash, role) VALUES ($1, $2, $3) RETURNING id",
    )
    .bind(username)
    .bind(password_hash)
    .bind(role.as_str())
    .fetch_one(pool)
    .await;
    match res {
        Ok((id,)) => Ok(id),
        Err(e) if e.as_database_error().and_then(|d| d.code()).as_deref() == Some("23505") => {
            Err(Error::Conflict(format!("username {username:?} already exists")))
        }
        Err(e) => Err(Error::Db(e)),
    }
}

/// Row shape for a full user read: id, username, password_hash (nullable), role, disabled,
/// auth_source, created_at.
type UserHashRow = (i64, String, Option<String>, String, bool, String, OffsetDateTime);

/// Fetch a user with its password hash (login path only). `password_hash` is `None` for OIDC users.
pub async fn get_user_with_hash(pool: &PgPool, username: &str) -> Result<Option<UserWithHash>> {
    let row: Option<UserHashRow> = sqlx::query_as(
        "SELECT id, username, password_hash, role, disabled, auth_source, created_at FROM gov_users WHERE username = $1",
    )
    .bind(username)
    .fetch_optional(pool)
    .await?;
    match row {
        None => Ok(None),
        Some((id, username, password_hash, role, disabled, auth_source, created_at)) => Ok(Some(UserWithHash {
            user: row_to_user(id, username, &role, disabled, auth_source, created_at)?,
            password_hash,
        })),
    }
}

/// All users, ordered by id.
pub async fn list_users(pool: &PgPool) -> Result<Vec<User>> {
    let rows: Vec<(i64, String, String, bool, String, OffsetDateTime)> = sqlx::query_as(
        "SELECT id, username, role, disabled, auth_source, created_at FROM gov_users ORDER BY id",
    )
    .fetch_all(pool)
    .await?;
    rows.into_iter()
        .map(|(id, username, role, disabled, auth_source, created_at)| {
            row_to_user(id, username, &role, disabled, auth_source, created_at)
        })
        .collect()
}

/// Change a user's role. Returns whether a row was updated.
pub async fn set_user_role(pool: &PgPool, id: i64, role: Role) -> Result<bool> {
    let r = sqlx::query("UPDATE gov_users SET role = $2 WHERE id = $1")
        .bind(id)
        .bind(role.as_str())
        .execute(pool)
        .await?;
    Ok(r.rows_affected() > 0)
}

/// Enable/disable a user. Returns whether a row was updated.
pub async fn set_user_disabled(pool: &PgPool, id: i64, disabled: bool) -> Result<bool> {
    let r = sqlx::query("UPDATE gov_users SET disabled = $2 WHERE id = $1")
        .bind(id)
        .bind(disabled)
        .execute(pool)
        .await?;
    Ok(r.rows_affected() > 0)
}

/// Delete a user (cascades to their sessions). Returns whether a row was removed.
pub async fn delete_user(pool: &PgPool, id: i64) -> Result<bool> {
    let r = sqlx::query("DELETE FROM gov_users WHERE id = $1").bind(id).execute(pool).await?;
    Ok(r.rows_affected() > 0)
}

// ── Sessions ──────────────────────────────────────────────────────────────────────────────────

/// Create a session row.
pub async fn create_session(
    pool: &PgPool,
    id: &str,
    user_id: i64,
    expires_at: OffsetDateTime,
) -> Result<()> {
    sqlx::query("INSERT INTO gov_sessions (id, user_id, expires_at) VALUES ($1, $2, $3)")
        .bind(id)
        .bind(user_id)
        .bind(expires_at)
        .execute(pool)
        .await?;
    Ok(())
}

/// Row shape of the session⋈user join (`session id/user_id/created/expires`, then `user`
/// username/role/disabled/auth_source/created).
type SessionJoinRow =
    (String, i64, OffsetDateTime, OffsetDateTime, String, String, bool, String, OffsetDateTime);

/// Resolve a NON-expired session to its `(Session, User)`. Expired or unknown → `None`.
pub async fn get_session_with_user(pool: &PgPool, id: &str) -> Result<Option<(Session, User)>> {
    let row: Option<SessionJoinRow> =
        sqlx::query_as(
            "SELECT s.id, s.user_id, s.created_at, s.expires_at, u.username, u.role, u.disabled, u.auth_source, u.created_at \
             FROM gov_sessions s JOIN gov_users u ON u.id = s.user_id \
             WHERE s.id = $1 AND s.expires_at > now()",
        )
        .bind(id)
        .fetch_optional(pool)
        .await?;
    match row {
        None => Ok(None),
        Some((sid, user_id, s_created, expires_at, username, role, disabled, auth_source, u_created)) => {
            let session = Session { id: sid, user_id, created_at: s_created, expires_at };
            let user = row_to_user(user_id, username, &role, disabled, auth_source, u_created)?;
            Ok(Some((session, user)))
        }
    }
}

/// Delete a session (logout). Returns whether a row was removed.
pub async fn delete_session(pool: &PgPool, id: &str) -> Result<bool> {
    let r = sqlx::query("DELETE FROM gov_sessions WHERE id = $1").bind(id).execute(pool).await?;
    Ok(r.rows_affected() > 0)
}

/// Delete all expired sessions (housekeeping). Returns the count removed.
pub async fn delete_expired_sessions(pool: &PgPool) -> Result<u64> {
    let r = sqlx::query("DELETE FROM gov_sessions WHERE expires_at <= now()").execute(pool).await?;
    Ok(r.rows_affected())
}

/// A user's sessions, newest first (session management, v2).
pub async fn list_sessions_for_user(pool: &PgPool, user_id: i64) -> Result<Vec<Session>> {
    let rows: Vec<(String, i64, OffsetDateTime, OffsetDateTime)> = sqlx::query_as(
        "SELECT id, user_id, created_at, expires_at FROM gov_sessions WHERE user_id = $1 ORDER BY created_at DESC",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(id, user_id, created_at, expires_at)| Session { id, user_id, created_at, expires_at })
        .collect())
}

/// Delete all of a user's sessions (e.g. on disable). Returns the count removed.
pub async fn delete_sessions_for_user(pool: &PgPool, user_id: i64) -> Result<u64> {
    let r = sqlx::query("DELETE FROM gov_sessions WHERE user_id = $1").bind(user_id).execute(pool).await?;
    Ok(r.rows_affected())
}

/// Delete all of a user's sessions EXCEPT `keep_id` (e.g. on password change). Returns the count.
pub async fn delete_other_sessions_for_user(pool: &PgPool, user_id: i64, keep_id: &str) -> Result<u64> {
    let r = sqlx::query("DELETE FROM gov_sessions WHERE user_id = $1 AND id <> $2")
        .bind(user_id)
        .bind(keep_id)
        .execute(pool)
        .await?;
    Ok(r.rows_affected())
}

/// Set (or reset) a user's password hash. Returns whether a row was updated.
pub async fn set_password_hash(pool: &PgPool, user_id: i64, password_hash: &str) -> Result<bool> {
    let r = sqlx::query("UPDATE gov_users SET password_hash = $2, auth_source = 'local' WHERE id = $1")
        .bind(user_id)
        .bind(password_hash)
        .execute(pool)
        .await?;
    Ok(r.rows_affected() > 0)
}

/// Upsert an OIDC-federated user: create on first login, refresh the role each login (the IdP is the
/// source of truth). Refuses to touch a pre-existing LOCAL account of the same username → `Conflict`.
pub async fn upsert_oidc_user(pool: &PgPool, username: &str, role: Role) -> Result<User> {
    let row: Option<(i64, String, String, bool, String, OffsetDateTime)> = sqlx::query_as(
        "INSERT INTO gov_users (username, role, auth_source) VALUES ($1, $2, 'oidc') \
         ON CONFLICT (username) DO UPDATE SET role = EXCLUDED.role \
           WHERE gov_users.auth_source = 'oidc' \
         RETURNING id, username, role, disabled, auth_source, created_at",
    )
    .bind(username)
    .bind(role.as_str())
    .fetch_optional(pool)
    .await?;
    match row {
        Some((id, username, role, disabled, auth_source, created_at)) => {
            row_to_user(id, username, &role, disabled, auth_source, created_at)
        }
        None => Err(Error::Conflict(format!("username {username:?} is a local account"))),
    }
}

// ── Service tokens (v2) ───────────────────────────────────────────────────────────────────────

/// Create a named service token (store only its hash). Duplicate name → [`Error::Conflict`].
pub async fn create_token(pool: &PgPool, name: &str, token_hash: &str, role: Role) -> Result<i64> {
    let res = sqlx::query_as::<_, (i64,)>(
        "INSERT INTO gov_tokens (name, token_hash, role) VALUES ($1, $2, $3) RETURNING id",
    )
    .bind(name)
    .bind(token_hash)
    .bind(role.as_str())
    .fetch_one(pool)
    .await;
    match res {
        Ok((id,)) => Ok(id),
        Err(e) if e.as_database_error().and_then(|d| d.code()).as_deref() == Some("23505") => {
            Err(Error::Conflict(format!("token name {name:?} already exists")))
        }
        Err(e) => Err(Error::Db(e)),
    }
}

/// Resolve a presented token hash to its `(name, role)` if it exists and is not revoked.
pub async fn find_active_token(pool: &PgPool, token_hash: &str) -> Result<Option<(String, Role)>> {
    let row: Option<(String, String)> =
        sqlx::query_as("SELECT name, role FROM gov_tokens WHERE token_hash = $1 AND NOT revoked")
            .bind(token_hash)
            .fetch_optional(pool)
            .await?;
    match row {
        Some((name, role)) => Ok(Some((name, Role::from_str(&role)?))),
        None => Ok(None),
    }
}

/// List all service tokens (metadata only; never the secret).
pub async fn list_tokens(pool: &PgPool) -> Result<Vec<ServiceToken>> {
    let rows: Vec<(i64, String, String, bool, OffsetDateTime)> =
        sqlx::query_as("SELECT id, name, role, revoked, created_at FROM gov_tokens ORDER BY id")
            .fetch_all(pool)
            .await?;
    rows.into_iter()
        .map(|(id, name, role, revoked, created_at)| {
            Ok(ServiceToken { id, name, role: Role::from_str(&role)?, revoked, created_at })
        })
        .collect()
}

/// Revoke a service token. Returns whether a row was updated.
pub async fn revoke_token(pool: &PgPool, id: i64) -> Result<bool> {
    let r = sqlx::query("UPDATE gov_tokens SET revoked = TRUE WHERE id = $1").bind(id).execute(pool).await?;
    Ok(r.rows_affected() > 0)
}

// ── OIDC login flows (v2) ─────────────────────────────────────────────────────────────────────

/// Store an in-flight OIDC flow (PKCE verifier + nonce) keyed by `state`.
pub async fn put_oidc_flow(pool: &PgPool, state: &str, pkce_verifier: &str, nonce: &str) -> Result<()> {
    sqlx::query("INSERT INTO gov_oidc_flows (state, pkce_verifier, nonce) VALUES ($1, $2, $3)")
        .bind(state)
        .bind(pkce_verifier)
        .bind(nonce)
        .execute(pool)
        .await?;
    Ok(())
}

/// Take (delete + return) a flow's `(pkce_verifier, nonce)` by `state`. `None` if unknown.
pub async fn take_oidc_flow(pool: &PgPool, state: &str) -> Result<Option<(String, String)>> {
    let row: Option<(String, String)> =
        sqlx::query_as("DELETE FROM gov_oidc_flows WHERE state = $1 RETURNING pkce_verifier, nonce")
            .bind(state)
            .fetch_optional(pool)
            .await?;
    Ok(row)
}

/// Delete OIDC flows older than `older_than_secs` (stale, abandoned logins). Returns the count.
pub async fn prune_oidc_flows(pool: &PgPool, older_than_secs: i64) -> Result<u64> {
    let r = sqlx::query("DELETE FROM gov_oidc_flows WHERE created_at < now() - make_interval(secs => $1::int)")
        .bind(older_than_secs)
        .execute(pool)
        .await?;
    Ok(r.rows_affected())
}

// ── Audit log ─────────────────────────────────────────────────────────────────────────────────

/// Append one audit record, extending the hash chain and signing it. Serialized cluster-wide via a
/// transaction-scoped Postgres advisory lock so the chain stays strictly linear.
pub async fn append_audit(pool: &PgPool, signer: &AuditSigner, entry: &NewAudit) -> Result<AuditRecord> {
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock($1)").bind(AUDIT_LOCK_KEY).execute(&mut *tx).await?;

    let last: Option<(i64, String)> =
        sqlx::query_as("SELECT seq, hash FROM gov_audit_log ORDER BY seq DESC LIMIT 1")
            .fetch_optional(&mut *tx)
            .await?;
    let (seq, prev_hash) = match last {
        Some((s, h)) => (s + 1, h),
        None => (1, GENESIS_PREV.to_string()),
    };

    let ts = OffsetDateTime::now_utc();
    let hash = compute_hash(
        seq,
        ts_micros(ts),
        &entry.actor,
        &entry.action,
        entry.target.as_deref(),
        &entry.details,
        &prev_hash,
    );
    let signature = signer.sign_hash(&hash);

    sqlx::query(
        "INSERT INTO gov_audit_log (seq, ts, actor, action, target, details, prev_hash, hash, signature) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
    )
    .bind(seq)
    .bind(ts)
    .bind(&entry.actor)
    .bind(&entry.action)
    .bind(&entry.target)
    .bind(&entry.details)
    .bind(&prev_hash)
    .bind(&hash)
    .bind(&signature)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;

    Ok(AuditRecord {
        seq,
        ts,
        actor: entry.actor.clone(),
        action: entry.action.clone(),
        target: entry.target.clone(),
        details: entry.details.clone(),
        prev_hash,
        hash,
        signature,
    })
}

type AuditRow = (i64, OffsetDateTime, String, String, Option<String>, String, String, String, String);

fn row_to_audit(r: AuditRow) -> AuditRecord {
    let (seq, ts, actor, action, target, details, prev_hash, hash, signature) = r;
    AuditRecord { seq, ts, actor, action, target, details, prev_hash, hash, signature }
}

const AUDIT_COLS: &str = "seq, ts, actor, action, target, details, prev_hash, hash, signature";

/// The `limit` most recent audit records, newest first (for display).
pub async fn recent_audit(pool: &PgPool, limit: i64) -> Result<Vec<AuditRecord>> {
    let rows: Vec<AuditRow> =
        sqlx::query_as(&format!("SELECT {AUDIT_COLS} FROM gov_audit_log ORDER BY seq DESC LIMIT $1"))
            .bind(limit)
            .fetch_all(pool)
            .await?;
    Ok(rows.into_iter().map(row_to_audit).collect())
}

/// The full audit log ordered by ascending `seq` (for chain verification).
pub async fn all_audit_ordered(pool: &PgPool) -> Result<Vec<AuditRecord>> {
    let rows: Vec<AuditRow> =
        sqlx::query_as(&format!("SELECT {AUDIT_COLS} FROM gov_audit_log ORDER BY seq ASC"))
            .fetch_all(pool)
            .await?;
    Ok(rows.into_iter().map(row_to_audit).collect())
}

// ── Env-gated integration tests (need a live Postgres; set WAF_CP_DATABASE_URL) ─────────────────
#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::verify_chain;
    use crate::password::hash_password;

    const TEST_SEED: &str = "0303030303030303030303030303030303030303030303030303030303030303";

    async fn connect() -> Option<PgPool> {
        let url = std::env::var("WAF_CP_DATABASE_URL").ok()?;
        let pool = PgPool::connect(&url).await.expect("connect");
        apply_schema(&pool).await.expect("schema");
        Some(pool)
    }

    fn uniq(prefix: &str) -> String {
        format!("{prefix}-{}", OffsetDateTime::now_utc().unix_timestamp_nanos())
    }

    #[tokio::test]
    async fn users_roundtrip_env_gated() {
        let Some(pool) = connect().await else {
            eprintln!("skipping: WAF_CP_DATABASE_URL not set");
            return;
        };
        let name = uniq("user");
        let hash = hash_password("s3cret").unwrap();
        let id = create_user(&pool, &name, &hash, Role::Operator).await.expect("create");

        // Duplicate username → Conflict.
        assert!(matches!(
            create_user(&pool, &name, &hash, Role::Viewer).await,
            Err(Error::Conflict(_))
        ));

        let uwh = get_user_with_hash(&pool, &name).await.expect("get").expect("present");
        assert_eq!(uwh.user.id, id);
        assert_eq!(uwh.user.role, Role::Operator);
        assert_eq!(uwh.user.auth_source, "local");
        let ph = uwh.password_hash.as_deref().expect("local user has a password hash");
        assert!(crate::password::verify_password("s3cret", ph).unwrap());

        assert!(set_user_role(&pool, id, Role::Admin).await.expect("role"));
        assert!(set_user_disabled(&pool, id, true).await.expect("disable"));
        let listed = list_users(&pool).await.expect("list");
        let me = listed.iter().find(|u| u.id == id).expect("in list");
        assert_eq!(me.role, Role::Admin);
        assert!(me.disabled);
        assert!(count_users(&pool).await.expect("count") >= 1);

        assert!(delete_user(&pool, id).await.expect("delete"));
        assert!(get_user_with_hash(&pool, &name).await.expect("get2").is_none());
    }

    #[tokio::test]
    async fn sessions_roundtrip_env_gated() {
        let Some(pool) = connect().await else {
            eprintln!("skipping: WAF_CP_DATABASE_URL not set");
            return;
        };
        let name = uniq("suser");
        let id = create_user(&pool, &name, &hash_password("pw").unwrap(), Role::Viewer).await.unwrap();

        let sid = uniq("sess");
        let expires = OffsetDateTime::now_utc() + time::Duration::hours(1);
        create_session(&pool, &sid, id, expires).await.expect("create session");

        let (session, user) = get_session_with_user(&pool, &sid).await.expect("get").expect("present");
        assert_eq!(session.user_id, id);
        assert_eq!(user.username, name);

        assert!(delete_session(&pool, &sid).await.expect("delete"));
        assert!(get_session_with_user(&pool, &sid).await.expect("get2").is_none());

        // An already-expired session resolves to None.
        let sid2 = uniq("sess-exp");
        let past = OffsetDateTime::now_utc() - time::Duration::hours(1);
        create_session(&pool, &sid2, id, past).await.unwrap();
        assert!(get_session_with_user(&pool, &sid2).await.expect("get3").is_none());
        delete_user(&pool, id).await.unwrap();
    }

    #[tokio::test]
    async fn audit_chain_env_gated() {
        let Some(pool) = connect().await else {
            eprintln!("skipping: WAF_CP_DATABASE_URL not set");
            return;
        };
        // The chain is global (one table) → start from a clean slate for a deterministic check.
        sqlx::query("TRUNCATE gov_audit_log").execute(&pool).await.expect("truncate");
        let signer = AuditSigner::from_hex_seed(TEST_SEED).unwrap();

        for i in 0..4 {
            let entry = NewAudit::new(
                "admin",
                "user.create",
                Some(format!("user-{i}")),
                &serde_json::json!({ "i": i, "role": "viewer" }),
            );
            let rec = append_audit(&pool, &signer, &entry).await.expect("append");
            assert_eq!(rec.seq, i + 1);
        }

        let all = all_audit_ordered(&pool).await.expect("all");
        assert_eq!(all.len(), 4);
        assert_eq!(all[0].prev_hash, GENESIS_PREV);
        verify_chain(&all, signer.public_key_hex()).expect("chain must verify");

        // recent_audit is newest-first.
        let recent = recent_audit(&pool, 2).await.expect("recent");
        assert_eq!(recent.len(), 2);
        assert_eq!(recent[0].seq, 4);

        // Tamper a stored row directly → the chain no longer verifies.
        sqlx::query("UPDATE gov_audit_log SET details = $1 WHERE seq = 2")
            .bind("{\"i\":666}")
            .execute(&pool)
            .await
            .expect("tamper");
        let after = all_audit_ordered(&pool).await.expect("all2");
        let brk = verify_chain(&after, signer.public_key_hex()).expect_err("must detect tamper");
        assert_eq!(brk.seq, 2);
    }

    #[tokio::test]
    async fn v2_store_env_gated() {
        use crate::token::{generate_token, hash_token};
        let Some(pool) = connect().await else {
            eprintln!("skipping: WAF_CP_DATABASE_URL not set");
            return;
        };

        // Service tokens: create → resolve by hash → list → revoke → no longer resolves.
        let tname = uniq("tok");
        let secret = generate_token();
        let hash = hash_token(&secret);
        let tid = create_token(&pool, &tname, &hash, Role::Operator).await.expect("create token");
        assert!(matches!(create_token(&pool, &tname, &hash, Role::Viewer).await, Err(Error::Conflict(_))));
        let (name, role) = find_active_token(&pool, &hash).await.expect("find").expect("active");
        assert_eq!(name, tname);
        assert_eq!(role, Role::Operator);
        assert!(list_tokens(&pool).await.expect("list").iter().any(|t| t.id == tid));
        assert!(revoke_token(&pool, tid).await.expect("revoke"));
        assert!(find_active_token(&pool, &hash).await.expect("find2").is_none(), "revoked token must not resolve");

        // OIDC federated upsert: creates, then a second login refreshes the role.
        let oname = uniq("oidc");
        let u1 = upsert_oidc_user(&pool, &oname, Role::Viewer).await.expect("upsert1");
        assert_eq!(u1.auth_source, "oidc");
        assert_eq!(u1.role, Role::Viewer);
        let u2 = upsert_oidc_user(&pool, &oname, Role::Admin).await.expect("upsert2");
        assert_eq!(u2.id, u1.id, "same user");
        assert_eq!(u2.role, Role::Admin, "role refreshed from the IdP");
        // An OIDC login must NOT hijack a pre-existing local account of the same name.
        let lname = uniq("localu");
        create_user(&pool, &lname, "x", Role::Viewer).await.expect("local user");
        assert!(matches!(upsert_oidc_user(&pool, &lname, Role::Admin).await, Err(Error::Conflict(_))));

        // Sessions: list + revoke-others + revoke-all for a user.
        let uid = create_user(&pool, &uniq("su"), "h", Role::Viewer).await.expect("user");
        let s1 = uniq("s1");
        let s2 = uniq("s2");
        let exp = OffsetDateTime::now_utc() + time::Duration::hours(1);
        create_session(&pool, &s1, uid, exp).await.unwrap();
        create_session(&pool, &s2, uid, exp).await.unwrap();
        assert_eq!(list_sessions_for_user(&pool, uid).await.unwrap().len(), 2);
        assert_eq!(delete_other_sessions_for_user(&pool, uid, &s1).await.unwrap(), 1);
        assert_eq!(list_sessions_for_user(&pool, uid).await.unwrap().len(), 1);
        create_session(&pool, &s2, uid, exp).await.unwrap();
        assert_eq!(delete_sessions_for_user(&pool, uid).await.unwrap(), 2);

        // Password reset.
        let new_hash = crate::password::hash_password("newpw").unwrap();
        assert!(set_password_hash(&pool, uid, &new_hash).await.unwrap());
        let uwh = get_user_with_hash(&pool, &list_users(&pool).await.unwrap().iter().find(|u| u.id == uid).unwrap().username).await.unwrap().unwrap();
        assert!(crate::password::verify_password("newpw", uwh.password_hash.as_deref().unwrap()).unwrap());

        // OIDC flow: put → take (once) → gone.
        let state = uniq("state");
        put_oidc_flow(&pool, &state, "verifier-xyz", "nonce-123").await.expect("put flow");
        let (v, n) = take_oidc_flow(&pool, &state).await.expect("take").expect("present");
        assert_eq!(v, "verifier-xyz");
        assert_eq!(n, "nonce-123");
        assert!(take_oidc_flow(&pool, &state).await.expect("take2").is_none(), "flow consumed once");
        let _ = prune_oidc_flows(&pool, 0).await.expect("prune");
    }
}
