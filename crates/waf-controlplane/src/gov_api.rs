// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: BUSL-1.1

//! Governance HTTP layer (§8): local-auth login/logout, the current-principal endpoint, admin user
//! management and the signed audit-log endpoints — plus the auth+RBAC middleware that gates the read
//! API when governance is enabled.
//!
//! Principals come from EITHER a session cookie (a logged-in human, with their role) OR the static
//! bearer token (a machine/admin principal, `actor = "api-token"`). Each protected route requires a
//! [`Permission`]; the role→permission grant lives in `waf-governance`.

use std::sync::Arc;

use axum::extract::{FromRequestParts, Path, Query, Request, State};
use axum::http::request::Parts;
use axum::http::{header, HeaderMap, StatusCode};
use axum::middleware::{from_fn_with_state, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, patch, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::json;
use time::{Duration, OffsetDateTime};
use tracing::{info, warn};

use waf_governance::audit::{verify_chain, AuditSigner};
use waf_governance::model::NewAudit;
use waf_governance::password::{hash_password, verify_password};
use waf_governance::rbac::{Permission, Role};
use waf_governance::{generate_session_id, generate_token, hash_token, store as gov_store, LoginThrottle};

use crate::compliance::{build_report, sign_report, verify_report_value, ReportInputs};
use crate::config::{ControlPlaneConfig, ENV_AUDIT_KEY, ENV_BOOTSTRAP_ADMIN_PASSWORD};
use crate::error::{Error as CpError, Result as CpResult};
use crate::server::{check_bearer, read_api, AppState};
use crate::store::Store;

const SESSION_COOKIE: &str = "waf_cp_session";

/// Runtime governance state held in [`AppState`] when governance is enabled.
pub struct Governance {
    /// The audit-log signer (its public key is exposed via the verify endpoint).
    pub signer: AuditSigner,
    /// Session lifetime.
    pub session_ttl: Duration,
    /// Whether to mark the session cookie `Secure`.
    pub cookie_secure: bool,
    /// Login brute-force throttle (in-memory, per-process).
    pub throttle: LoginThrottle,
    /// OIDC SSO provider (§8 v2), `Some` when `[controlplane.governance.oidc]` is configured.
    pub oidc: Option<crate::oidc::OidcProvider>,
}

/// How the caller authenticated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthVia {
    Session,
    Token,
}

/// The authenticated caller, inserted into request extensions by the auth middleware.
#[derive(Debug, Clone)]
pub struct Principal {
    pub actor: String,
    pub role: Role,
    pub via: AuthVia,
    /// The user id — `Some` for a session principal, `None` for a token/machine principal.
    pub user_id: Option<i64>,
    /// The current session id — `Some` for a session principal.
    pub session_id: Option<String>,
}

impl<S: Send + Sync> FromRequestParts<S> for Principal {
    type Rejection = Response;
    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<Principal>()
            .cloned()
            .ok_or_else(|| (StatusCode::INTERNAL_SERVER_ERROR, "missing principal").into_response())
    }
}

/// A non-rejecting principal extractor: `Some` when the auth middleware ran and stashed a principal
/// (governance ON), `None` under the plain static bearer (governance OFF — the bearer already gated
/// the route, and is treated as the `api-token` admin). Lets a handler serve both wirings.
#[derive(Debug, Clone)]
pub(crate) struct MaybePrincipal(pub Option<Principal>);

impl MaybePrincipal {
    /// The acting identity for audit/attribution: the principal's actor, or `api-token` (the static
    /// bearer / machine principal used when governance is off).
    pub(crate) fn actor(&self) -> &str {
        self.0.as_ref().map(|p| p.actor.as_str()).unwrap_or("api-token")
    }
}

impl<S: Send + Sync> FromRequestParts<S> for MaybePrincipal {
    type Rejection = std::convert::Infallible;
    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        Ok(MaybePrincipal(parts.extensions.get::<Principal>().cloned()))
    }
}

fn err500(e: impl std::fmt::Display) -> Response {
    (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response()
}

// ── Cookies ───────────────────────────────────────────────────────────────────────────────────

fn session_id_from_cookies(headers: &HeaderMap) -> Option<String> {
    let cookie = headers.get(header::COOKIE)?.to_str().ok()?;
    for part in cookie.split(';') {
        if let Some(v) = part.trim().strip_prefix(&format!("{SESSION_COOKIE}=")) {
            if !v.is_empty() {
                return Some(v.to_string());
            }
        }
    }
    None
}

fn set_cookie(sid: &str, ttl: Duration, secure: bool) -> String {
    let max_age = ttl.whole_seconds().max(0);
    let mut c = format!("{SESSION_COOKIE}={sid}; HttpOnly; SameSite=Strict; Path=/; Max-Age={max_age}");
    if secure {
        c.push_str("; Secure");
    }
    c
}

fn clear_cookie(secure: bool) -> String {
    let mut c = format!("{SESSION_COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0");
    if secure {
        c.push_str("; Secure");
    }
    c
}

// ── Auth middleware (authn + authz) ─────────────────────────────────────────────────────────────

/// Resolve the caller: a session cookie (preferred) → a named service token → the static bearer
/// (→ admin, backward-compat). `None` = unauthenticated.
async fn resolve_principal(state: &AppState, headers: &HeaderMap) -> Option<Principal> {
    let pool = state.store.pool();
    if let Some(sid) = session_id_from_cookies(headers) {
        if let Ok(Some((session, user))) = gov_store::get_session_with_user(pool, &sid).await {
            if !user.disabled {
                return Some(Principal {
                    actor: user.username,
                    role: user.role,
                    via: AuthVia::Session,
                    user_id: Some(user.id),
                    session_id: Some(session.id),
                });
            }
        }
    }
    let presented = headers.get(header::AUTHORIZATION).and_then(|h| h.to_str().ok());
    // A named, revocable service token (attribution = the token's name).
    if let Some(tok) = presented.and_then(|h| h.strip_prefix("Bearer ")) {
        if let Ok(Some((name, role))) = gov_store::find_active_token(pool, &hash_token(tok)).await {
            return Some(Principal {
                actor: name,
                role,
                via: AuthVia::Token,
                user_id: None,
                session_id: None,
            });
        }
    }
    // The static bearer stays valid as an admin/service principal (backward-compat).
    if let Some(token) = &state.api_token {
        if check_bearer(presented, token) {
            return Some(Principal {
                actor: "api-token".into(),
                role: Role::Admin,
                via: AuthVia::Token,
                user_id: None,
                session_id: None,
            });
        }
    }
    None
}

/// Require an authenticated caller granted `perm`; on success stash the [`Principal`] in extensions.
async fn require(state: Arc<AppState>, perm: Permission, mut req: Request, next: Next) -> Response {
    let Some(principal) = resolve_principal(&state, req.headers()).await else {
        return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    };
    if !principal.role.allows(perm) {
        return (StatusCode::FORBIDDEN, "forbidden").into_response();
    }
    req.extensions_mut().insert(principal);
    next.run(req).await
}

async fn require_read(State(s): State<Arc<AppState>>, req: Request, next: Next) -> Response {
    require(s, Permission::ReadObservability, req, next).await
}
async fn require_users(State(s): State<Arc<AppState>>, req: Request, next: Next) -> Response {
    require(s, Permission::ManageUsers, req, next).await
}
async fn require_audit(State(s): State<Arc<AppState>>, req: Request, next: Next) -> Response {
    require(s, Permission::ViewAudit, req, next).await
}
async fn require_tokens(State(s): State<Arc<AppState>>, req: Request, next: Next) -> Response {
    require(s, Permission::ManageTokens, req, next).await
}
pub(crate) async fn require_rules(State(s): State<Arc<AppState>>, req: Request, next: Next) -> Response {
    require(s, Permission::ManageRules, req, next).await
}
async fn require_captures(State(s): State<Arc<AppState>>, req: Request, next: Next) -> Response {
    require(s, Permission::ViewCaptures, req, next).await
}

// ── Audit helper ────────────────────────────────────────────────────────────────────────────────

/// Append an audit record (best-effort: a failure is logged, never fails the primary action — in
/// practice the append only fails if Postgres is down, in which case the action failed too).
pub(crate) async fn audit(state: &AppState, actor: &str, action: &str, target: Option<String>, details: serde_json::Value) {
    if let Some(gov) = &state.governance {
        let entry = NewAudit::new(actor, action, target, &details);
        if let Err(e) = gov_store::append_audit(state.store.pool(), &gov.signer, &entry).await {
            warn!(action, error = %e, "audit append failed");
        }
    }
}

// ── Handlers ──────────────────────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct LoginBody {
    username: String,
    password: String,
}

#[derive(Serialize)]
struct MeResponse {
    actor: String,
    role: Role,
    via: AuthVia,
}

async fn login(State(state): State<Arc<AppState>>, Json(body): Json<LoginBody>) -> Response {
    let gov = state.governance.as_ref().expect("login mounted only when governance is on");
    let pool = state.store.pool();
    let now = OffsetDateTime::now_utc();

    // Brute-force throttle: refuse (429) while the username is locked out.
    if !gov.throttle.allowed(&body.username, now) {
        audit(&state, &body.username, "login.throttled", None, json!({})).await;
        return (StatusCode::TOO_MANY_REQUESTS, "too many failed attempts; try again later").into_response();
    }

    // Uniform failure response (don't reveal whether the username exists); each failure feeds the throttle.
    let fail = |username: &str| {
        gov.throttle.record_failure(username, now);
        (StatusCode::UNAUTHORIZED, "invalid credentials").into_response()
    };

    let uwh = match gov_store::get_user_with_hash(pool, &body.username).await {
        Ok(Some(u)) => u,
        Ok(None) => {
            audit(&state, &body.username, "login.failure", None, json!({"reason": "unknown user"})).await;
            return fail(&body.username);
        }
        Err(e) => return err500(e),
    };
    if uwh.user.disabled {
        audit(&state, &body.username, "login.failure", None, json!({"reason": "disabled"})).await;
        return fail(&body.username);
    }
    // OIDC-federated users have no local password → local login is not available for them.
    let Some(password_hash) = &uwh.password_hash else {
        audit(&state, &body.username, "login.failure", None, json!({"reason": "no local password (oidc)"})).await;
        return fail(&body.username);
    };
    match verify_password(&body.password, password_hash) {
        Ok(true) => {}
        Ok(false) => {
            audit(&state, &body.username, "login.failure", None, json!({"reason": "bad password"})).await;
            return fail(&body.username);
        }
        Err(e) => return err500(e),
    }
    gov.throttle.record_success(&body.username);

    let sid = generate_session_id();
    let expires = OffsetDateTime::now_utc() + gov.session_ttl;
    if let Err(e) = gov_store::create_session(pool, &sid, uwh.user.id, expires).await {
        return err500(e);
    }
    audit(&state, &body.username, "login.success", None, json!({})).await;

    let cookie = set_cookie(&sid, gov.session_ttl, gov.cookie_secure);
    (
        StatusCode::OK,
        [(header::SET_COOKIE, cookie)],
        Json(MeResponse { actor: uwh.user.username, role: uwh.user.role, via: AuthVia::Session }),
    )
        .into_response()
}

async fn logout(State(state): State<Arc<AppState>>, principal: Principal, headers: HeaderMap) -> Response {
    let gov = state.governance.as_ref().expect("logout mounted only when governance is on");
    if let Some(sid) = session_id_from_cookies(&headers) {
        let _ = gov_store::delete_session(state.store.pool(), &sid).await;
    }
    audit(&state, &principal.actor, "logout", None, json!({})).await;
    (StatusCode::OK, [(header::SET_COOKIE, clear_cookie(gov.cookie_secure))], "ok").into_response()
}

async fn me(principal: Principal) -> Json<MeResponse> {
    Json(MeResponse { actor: principal.actor, role: principal.role, via: principal.via })
}

async fn list_users(State(state): State<Arc<AppState>>) -> Response {
    match gov_store::list_users(state.store.pool()).await {
        Ok(users) => Json(users).into_response(),
        Err(e) => err500(e),
    }
}

#[derive(Deserialize)]
struct CreateUserBody {
    username: String,
    password: String,
    role: Role,
}

async fn create_user(
    State(state): State<Arc<AppState>>,
    principal: Principal,
    Json(body): Json<CreateUserBody>,
) -> Response {
    let hash = match hash_password(&body.password) {
        Ok(h) => h,
        Err(e) => return err500(e),
    };
    match gov_store::create_user(state.store.pool(), &body.username, &hash, body.role).await {
        Ok(id) => {
            audit(
                &state,
                &principal.actor,
                "user.create",
                Some(body.username.clone()),
                json!({"role": body.role}),
            )
            .await;
            (StatusCode::CREATED, Json(json!({"id": id}))).into_response()
        }
        Err(waf_governance::Error::Conflict(msg)) => (StatusCode::CONFLICT, msg).into_response(),
        Err(e) => err500(e),
    }
}

#[derive(Deserialize)]
struct UpdateUserBody {
    role: Option<Role>,
    disabled: Option<bool>,
}

async fn update_user(
    State(state): State<Arc<AppState>>,
    principal: Principal,
    Path(id): Path<i64>,
    Json(body): Json<UpdateUserBody>,
) -> Response {
    let pool = state.store.pool();
    let mut changed = false;
    if let Some(role) = body.role {
        match gov_store::set_user_role(pool, id, role).await {
            Ok(c) => changed |= c,
            Err(e) => return err500(e),
        }
    }
    if let Some(disabled) = body.disabled {
        match gov_store::set_user_disabled(pool, id, disabled).await {
            Ok(c) => changed |= c,
            Err(e) => return err500(e),
        }
    }
    if !changed {
        return (StatusCode::NOT_FOUND, "no such user (or nothing to change)").into_response();
    }
    // Disabling a user drops their active sessions immediately (don't wait for expiry).
    if body.disabled == Some(true) {
        let _ = gov_store::delete_sessions_for_user(pool, id).await;
    }
    audit(
        &state,
        &principal.actor,
        "user.update",
        Some(id.to_string()),
        json!({"role": body.role, "disabled": body.disabled}),
    )
    .await;
    (StatusCode::OK, "ok").into_response()
}

async fn delete_user(
    State(state): State<Arc<AppState>>,
    principal: Principal,
    Path(id): Path<i64>,
) -> Response {
    match gov_store::delete_user(state.store.pool(), id).await {
        Ok(true) => {
            audit(&state, &principal.actor, "user.delete", Some(id.to_string()), json!({})).await;
            (StatusCode::OK, "ok").into_response()
        }
        Ok(false) => (StatusCode::NOT_FOUND, "no such user").into_response(),
        Err(e) => err500(e),
    }
}

#[derive(Deserialize)]
struct AuditQuery {
    limit: Option<i64>,
}

async fn list_audit(State(state): State<Arc<AppState>>, Query(q): Query<AuditQuery>) -> Response {
    let limit = q.limit.unwrap_or(100).clamp(1, 1000);
    match gov_store::recent_audit(state.store.pool(), limit).await {
        Ok(records) => Json(records).into_response(),
        Err(e) => err500(e),
    }
}

async fn verify_audit(State(state): State<Arc<AppState>>) -> Response {
    let gov = state.governance.as_ref().expect("mounted only when governance is on");
    let records = match gov_store::all_audit_ordered(state.store.pool()).await {
        Ok(r) => r,
        Err(e) => return err500(e),
    };
    let pubkey = gov.signer.public_key_hex();
    match verify_chain(&records, pubkey) {
        Ok(()) => Json(json!({"ok": true, "count": records.len(), "public_key": pubkey})).into_response(),
        Err(brk) => Json(json!({
            "ok": false,
            "count": records.len(),
            "broken_seq": brk.seq,
            "reason": brk.reason,
            "public_key": pubkey,
        }))
        .into_response(),
    }
}

// ── Compliance reports (§8) ─────────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct ReportQuery {
    /// Period bounds as RFC3339; default = the last 90 days.
    from: Option<String>,
    to: Option<String>,
}

fn parse_rfc3339(s: &str) -> Option<OffsetDateTime> {
    OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339).ok()
}

/// Generate a signed compliance-evidence bundle for `[from, to]` (admin / `ViewAudit`). Assembles the
/// access-control snapshot, the audit-chain integrity attestation + period timeline, WAF effectiveness
/// and fired alerts — each annotated with the SOC2/PCI controls it supports — then signs it.
async fn compliance_report(
    State(state): State<Arc<AppState>>,
    principal: Principal,
    Query(q): Query<ReportQuery>,
) -> Response {
    let gov = state.governance.as_ref().expect("mounted only when governance is on");
    let now = OffsetDateTime::now_utc();
    let to = match q.to.as_deref() {
        Some(s) => match parse_rfc3339(s) {
            Some(t) => t,
            None => return (StatusCode::BAD_REQUEST, "invalid 'to' (want RFC3339)").into_response(),
        },
        None => now,
    };
    let from = match q.from.as_deref() {
        Some(s) => match parse_rfc3339(s) {
            Some(t) => t,
            None => return (StatusCode::BAD_REQUEST, "invalid 'from' (want RFC3339)").into_response(),
        },
        None => now - Duration::days(90),
    };
    if from > to {
        return (StatusCode::BAD_REQUEST, "'from' must be <= 'to'").into_response();
    }

    let pool = state.store.pool();
    macro_rules! q {
        ($e:expr) => {
            match $e.await {
                Ok(v) => v,
                Err(e) => return err500(e),
            }
        };
    }
    let inputs = ReportInputs {
        period_from: from,
        period_to: to,
        generated_at: now,
        generated_by: principal.actor.clone(),
        audit_public_key: gov.signer.public_key_hex().to_string(),
        users: q!(gov_store::list_users(pool)),
        service_tokens: q!(gov_store::list_tokens(pool)),
        active_sessions: q!(gov_store::count_active_sessions(pool)),
        full_audit_chain: q!(gov_store::all_audit_ordered(pool)),
        audit_in_period: q!(gov_store::audit_between(pool, from, to)),
        denied_counts: q!(state.store.decision_counts_between(from, to)),
        top_rules: q!(state.store.top_rules_between(from, to, 20)),
        nodes_covered: q!(state.store.nodes_between(from, to)),
        cumulative_totals: q!(state.store.decision_totals()),
        alerts: q!(state.store.alerts_between(from, to)),
    };
    let signed = sign_report(build_report(&inputs), &gov.signer);
    audit(
        &state,
        &principal.actor,
        "compliance.report.generated",
        None,
        json!({ "from": signed.body.period.from, "to": signed.body.period.to }),
    )
    .await;
    Json(signed).into_response()
}

/// Verify a posted compliance bundle: recompute its content hash and check the signature (the public
/// key is carried in the bundle). No secrets involved; gated with the audit permission for consistency.
async fn compliance_verify(Json(bundle): Json<serde_json::Value>) -> Response {
    Json(json!({ "ok": verify_report_value(&bundle) })).into_response()
}

// ── Service tokens (v2) ─────────────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct CreateTokenBody {
    name: String,
    role: Role,
}

async fn create_token(
    State(state): State<Arc<AppState>>,
    principal: Principal,
    Json(body): Json<CreateTokenBody>,
) -> Response {
    let secret = generate_token();
    let hash = hash_token(&secret);
    match gov_store::create_token(state.store.pool(), &body.name, &hash, body.role).await {
        Ok(id) => {
            audit(&state, &principal.actor, "token.create", Some(body.name.clone()), json!({"role": body.role})).await;
            // The plaintext token is returned ONCE — it is never stored (only its hash) or shown again.
            (StatusCode::CREATED, Json(json!({"id": id, "name": body.name, "role": body.role, "token": secret})))
                .into_response()
        }
        Err(waf_governance::Error::Conflict(msg)) => (StatusCode::CONFLICT, msg).into_response(),
        Err(e) => err500(e),
    }
}

async fn list_tokens(State(state): State<Arc<AppState>>) -> Response {
    match gov_store::list_tokens(state.store.pool()).await {
        Ok(tokens) => Json(tokens).into_response(),
        Err(e) => err500(e),
    }
}

async fn revoke_token(State(state): State<Arc<AppState>>, principal: Principal, Path(id): Path<i64>) -> Response {
    match gov_store::revoke_token(state.store.pool(), id).await {
        Ok(true) => {
            audit(&state, &principal.actor, "token.revoke", Some(id.to_string()), json!({})).await;
            (StatusCode::OK, "ok").into_response()
        }
        Ok(false) => (StatusCode::NOT_FOUND, "no such token").into_response(),
        Err(e) => err500(e),
    }
}

// ── Session management (v2) ───────────────────────────────────────────────────────────────────

fn rfc3339(ts: OffsetDateTime) -> String {
    ts.format(&time::format_description::well_known::Rfc3339).unwrap_or_default()
}

#[derive(Serialize)]
struct SessionInfo {
    id: String,
    created_at: String,
    expires_at: String,
    current: bool,
}

async fn list_sessions(State(state): State<Arc<AppState>>, principal: Principal) -> Response {
    let Some(uid) = principal.user_id else {
        return Json(Vec::<SessionInfo>::new()).into_response(); // token principal has no sessions
    };
    match gov_store::list_sessions_for_user(state.store.pool(), uid).await {
        Ok(sessions) => Json(
            sessions
                .into_iter()
                .map(|s| SessionInfo {
                    current: principal.session_id.as_deref() == Some(&s.id),
                    created_at: rfc3339(s.created_at),
                    expires_at: rfc3339(s.expires_at),
                    id: s.id,
                })
                .collect::<Vec<_>>(),
        )
        .into_response(),
        Err(e) => err500(e),
    }
}

async fn revoke_session(
    State(state): State<Arc<AppState>>,
    principal: Principal,
    Path(id): Path<String>,
) -> Response {
    let Some(uid) = principal.user_id else {
        return (StatusCode::BAD_REQUEST, "not a session principal").into_response();
    };
    // Only allow revoking one's OWN sessions.
    let owned = match gov_store::list_sessions_for_user(state.store.pool(), uid).await {
        Ok(list) => list.iter().any(|s| s.id == id),
        Err(e) => return err500(e),
    };
    if !owned {
        return (StatusCode::NOT_FOUND, "no such session").into_response();
    }
    if let Err(e) = gov_store::delete_session(state.store.pool(), &id).await {
        return err500(e);
    }
    audit(&state, &principal.actor, "session.revoke", Some(id), json!({})).await;
    (StatusCode::OK, "ok").into_response()
}

async fn revoke_user_sessions(
    State(state): State<Arc<AppState>>,
    principal: Principal,
    Path(user_id): Path<i64>,
) -> Response {
    match gov_store::delete_sessions_for_user(state.store.pool(), user_id).await {
        Ok(n) => {
            audit(&state, &principal.actor, "session.revoke_all", Some(user_id.to_string()), json!({"revoked": n})).await;
            Json(json!({"revoked": n})).into_response()
        }
        Err(e) => err500(e),
    }
}

// ── Passwords (v2) ────────────────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct ChangePasswordBody {
    old_password: String,
    new_password: String,
}

async fn change_password(
    State(state): State<Arc<AppState>>,
    principal: Principal,
    Json(body): Json<ChangePasswordBody>,
) -> Response {
    let (Some(uid), Some(sid)) = (principal.user_id, principal.session_id.clone()) else {
        return (StatusCode::BAD_REQUEST, "not a session principal").into_response();
    };
    let pool = state.store.pool();
    let uwh = match gov_store::get_user_with_hash(pool, &principal.actor).await {
        Ok(Some(u)) => u,
        Ok(None) => return (StatusCode::NOT_FOUND, "no such user").into_response(),
        Err(e) => return err500(e),
    };
    let Some(hash) = &uwh.password_hash else {
        return (StatusCode::BAD_REQUEST, "OIDC user has no local password").into_response();
    };
    match verify_password(&body.old_password, hash) {
        Ok(true) => {}
        Ok(false) => return (StatusCode::UNAUTHORIZED, "wrong current password").into_response(),
        Err(e) => return err500(e),
    }
    let new_hash = match hash_password(&body.new_password) {
        Ok(h) => h,
        Err(e) => return err500(e),
    };
    if let Err(e) = gov_store::set_password_hash(pool, uid, &new_hash).await {
        return err500(e);
    }
    // Revoke the user's OTHER sessions (keep the current one).
    let _ = gov_store::delete_other_sessions_for_user(pool, uid, &sid).await;
    audit(&state, &principal.actor, "password.change", None, json!({})).await;
    (StatusCode::OK, "ok").into_response()
}

#[derive(Deserialize)]
struct ResetPasswordBody {
    new_password: String,
}

async fn reset_password(
    State(state): State<Arc<AppState>>,
    principal: Principal,
    Path(id): Path<i64>,
    Json(body): Json<ResetPasswordBody>,
) -> Response {
    let new_hash = match hash_password(&body.new_password) {
        Ok(h) => h,
        Err(e) => return err500(e),
    };
    match gov_store::set_password_hash(state.store.pool(), id, &new_hash).await {
        Ok(true) => {
            // Force re-login: revoke all of the target's sessions.
            let _ = gov_store::delete_sessions_for_user(state.store.pool(), id).await;
            audit(&state, &principal.actor, "password.reset", Some(id.to_string()), json!({})).await;
            (StatusCode::OK, "ok").into_response()
        }
        Ok(false) => (StatusCode::NOT_FOUND, "no such user").into_response(),
        Err(e) => err500(e),
    }
}

// ── OIDC SSO (v2) ─────────────────────────────────────────────────────────────────────────────

/// Start the OIDC login: persist the flow secrets and 302 the browser to the IdP.
async fn oidc_login(State(state): State<Arc<AppState>>) -> Response {
    let gov = state.governance.as_ref().expect("mounted only when governance is on");
    let Some(oidc) = &gov.oidc else {
        return (StatusCode::NOT_FOUND, "oidc is not configured").into_response();
    };
    let start = oidc.authorize();
    if let Err(e) =
        gov_store::put_oidc_flow(state.store.pool(), &start.state, &start.pkce_verifier, &start.nonce).await
    {
        return err500(e);
    }
    (StatusCode::FOUND, [(header::LOCATION, start.authorize_url)]).into_response()
}

#[derive(Deserialize)]
struct OidcCallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

/// OIDC callback: validate `state`, exchange + verify the id_token, map the role, provision the
/// federated user, open a session, and redirect to the app root.
async fn oidc_callback(State(state): State<Arc<AppState>>, Query(q): Query<OidcCallbackQuery>) -> Response {
    let gov = state.governance.as_ref().expect("mounted only when governance is on");
    let Some(oidc) = &gov.oidc else {
        return (StatusCode::NOT_FOUND, "oidc is not configured").into_response();
    };
    if let Some(err) = q.error {
        return (StatusCode::UNAUTHORIZED, format!("idp error: {err}")).into_response();
    }
    let (Some(code), Some(st)) = (q.code, q.state) else {
        return (StatusCode::BAD_REQUEST, "missing code/state").into_response();
    };

    // Consume the flow (this also validates `state` — an unknown/replayed state has no flow).
    let (pkce_verifier, nonce) = match gov_store::take_oidc_flow(state.store.pool(), &st).await {
        Ok(Some(f)) => f,
        Ok(None) => return (StatusCode::BAD_REQUEST, "unknown or expired login state").into_response(),
        Err(e) => return err500(e),
    };

    let identity = match oidc.verify_callback(code, pkce_verifier, nonce).await {
        Ok(id) => id,
        Err(msg) => {
            audit(&state, "oidc", "login.sso.denied", None, json!({"reason": msg})).await;
            return (StatusCode::UNAUTHORIZED, msg).into_response();
        }
    };

    // Provision / refresh the federated user (refuses to hijack a local account of the same name).
    let user = match gov_store::upsert_oidc_user(state.store.pool(), &identity.username, identity.role).await {
        Ok(u) => u,
        Err(waf_governance::Error::Conflict(msg)) => {
            audit(&state, &identity.username, "login.sso.denied", None, json!({"reason": msg})).await;
            return (StatusCode::CONFLICT, msg).into_response();
        }
        Err(e) => return err500(e),
    };
    if user.disabled {
        audit(&state, &identity.username, "login.sso.denied", None, json!({"reason": "disabled"})).await;
        return (StatusCode::FORBIDDEN, "account disabled").into_response();
    }

    let sid = generate_session_id();
    let expires = OffsetDateTime::now_utc() + gov.session_ttl;
    if let Err(e) = gov_store::create_session(state.store.pool(), &sid, user.id, expires).await {
        return err500(e);
    }
    audit(&state, &identity.username, "login.sso", None, json!({"role": identity.role})).await;
    let cookie = set_cookie(&sid, gov.session_ttl, gov.cookie_secure);
    (StatusCode::FOUND, [(header::LOCATION, "/".to_string()), (header::SET_COOKIE, cookie)]).into_response()
}

/// Set up governance (§8) when enabled: apply the schema, load the audit signing key (required — it
/// must persist so the audit chain stays verifiable under a stable public key), and bootstrap the
/// first admin if there are no users. Returns `None` when governance is disabled (backward-compat).
pub async fn setup_governance(config: &ControlPlaneConfig, store: &Store) -> CpResult<Option<Governance>> {
    let g = &config.governance;
    if !g.enabled {
        return Ok(None);
    }
    let pool = store.pool();
    gov_store::apply_schema(pool).await.map_err(|e| CpError::Config(e.to_string()))?;

    let seed = std::env::var(ENV_AUDIT_KEY).map_err(|_| {
        CpError::Config(format!("governance enabled but {ENV_AUDIT_KEY} is not set (64-hex Ed25519 seed)"))
    })?;
    let signer = AuditSigner::from_hex_seed(&seed).map_err(|e| CpError::Config(e.to_string()))?;
    info!(audit_public_key = %signer.public_key_hex(), "governance enabled; audit log signing active");

    // Bootstrap the first admin so a fresh deployment is not locked out.
    if let Some(admin) = &g.bootstrap_admin {
        let count = gov_store::count_users(pool).await.map_err(|e| CpError::Config(e.to_string()))?;
        if count == 0 {
            let password = std::env::var(ENV_BOOTSTRAP_ADMIN_PASSWORD).map_err(|_| {
                CpError::Config(format!(
                    "bootstrap_admin={admin:?} set but {ENV_BOOTSTRAP_ADMIN_PASSWORD} is not set"
                ))
            })?;
            let hash = hash_password(&password).map_err(|e| CpError::Config(e.to_string()))?;
            let id = gov_store::create_user(pool, admin, &hash, Role::Admin)
                .await
                .map_err(|e| CpError::Config(e.to_string()))?;
            let entry = NewAudit::new(
                "system",
                "bootstrap.admin",
                Some(admin.clone()),
                &json!({ "user_id": id, "role": "admin" }),
            );
            let _ = gov_store::append_audit(pool, &signer, &entry).await;
            info!(username = %admin, "bootstrapped initial admin account");
        }
    }

    // Discover the OIDC provider at boot (a bad issuer / unreachable IdP is boot-fatal).
    let oidc = match &g.oidc {
        Some(cfg) => {
            let p = crate::oidc::OidcProvider::discover(cfg).await?;
            info!(issuer = %cfg.issuer_url, "oidc SSO enabled");
            Some(p)
        }
        None => None,
    };

    Ok(Some(Governance {
        signer,
        session_ttl: Duration::hours(g.session_ttl_hours as i64),
        cookie_secure: g.cookie_secure,
        throttle: LoginThrottle::new(g.login_max_failures, g.login_window_seconds, g.login_lockout_seconds),
        oidc,
    }))
}

/// The governed API router (mounted instead of the plain bearer-gated read API when governance is
/// on). `/api/login` is public; everything else is behind auth + RBAC.
pub fn governed_router(state: &Arc<AppState>) -> Router<Arc<AppState>> {
    // Any authenticated caller: read observability + manage their own session/password.
    let read = read_api()
        .route("/api/me", get(me))
        .route("/api/logout", post(logout))
        .route("/api/sessions", get(list_sessions))
        .route("/api/sessions/{id}", delete(revoke_session))
        .route("/api/me/password", post(change_password))
        .route_layer(from_fn_with_state(state.clone(), require_read));

    // Admin: user management (+ per-user session revoke and password reset).
    let users = Router::new()
        .route("/api/users", get(list_users).post(create_user))
        .route("/api/users/{id}", patch(update_user).delete(delete_user))
        .route("/api/users/{id}/sessions", delete(revoke_user_sessions))
        .route("/api/users/{id}/password", post(reset_password))
        .route_layer(from_fn_with_state(state.clone(), require_users));

    // Admin: named service tokens.
    let tokens = Router::new()
        .route("/api/tokens", get(list_tokens).post(create_token))
        .route("/api/tokens/{id}", delete(revoke_token))
        .route_layer(from_fn_with_state(state.clone(), require_tokens));

    let audit_routes = Router::new()
        .route("/api/audit", get(list_audit))
        .route("/api/audit/verify", get(verify_audit))
        .route("/api/compliance/report", get(compliance_report))
        .route("/api/compliance/verify", post(compliance_verify))
        .route_layer(from_fn_with_state(state.clone(), require_audit));

    // Rule management (§7 write-path, v3): version/publish/rollback require ManageRules (+ audit);
    // the agent-facing current/report/convergence routes only require ReadObservability.
    let rules_manage = crate::rule_api::manage_routes()
        .route_layer(from_fn_with_state(state.clone(), require_rules));
    let rules_agent = crate::rule_api::agent_routes()
        .route_layer(from_fn_with_state(state.clone(), require_read));

    // Request-capture drill-down (§C4): viewing a full denied request requires ViewCaptures (above
    // viewer — captures may hold raw secrets) and the view is audited by the handler.
    let captures = crate::server::capture_routes()
        .route_layer(from_fn_with_state(state.clone(), require_captures));

    Router::new()
        .route("/api/login", post(login))
        .route("/api/auth/oidc/login", get(oidc_login))
        .route("/api/auth/oidc/callback", get(oidc_callback))
        .merge(read)
        .merge(users)
        .merge(tokens)
        .merge(audit_routes)
        .merge(rules_manage)
        .merge(rules_agent)
        .merge(captures)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn parses_session_cookie() {
        let mut h = HeaderMap::new();
        h.insert(header::COOKIE, HeaderValue::from_static("foo=1; waf_cp_session=abc123; bar=2"));
        assert_eq!(session_id_from_cookies(&h).as_deref(), Some("abc123"));
    }

    #[test]
    fn no_session_cookie() {
        let mut h = HeaderMap::new();
        h.insert(header::COOKIE, HeaderValue::from_static("foo=1; bar=2"));
        assert!(session_id_from_cookies(&h).is_none());
        assert!(session_id_from_cookies(&HeaderMap::new()).is_none());
    }

    #[test]
    fn cookie_attributes() {
        let c = set_cookie("sid", Duration::hours(12), true);
        assert!(c.contains("waf_cp_session=sid"));
        assert!(c.contains("HttpOnly"));
        assert!(c.contains("SameSite=Strict"));
        assert!(c.contains("Secure"));
        assert!(!set_cookie("sid", Duration::hours(1), false).contains("Secure"));
        assert!(clear_cookie(true).contains("Max-Age=0"));
    }
}
