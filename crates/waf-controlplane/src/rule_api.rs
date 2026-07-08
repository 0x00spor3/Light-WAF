// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: BUSL-1.1

//! Rule-management HTTP layer (§7 write-path, v3): version / publish / rollback the ONE managed
//! SecRule `.conf`, expose the current version + convergence to the per-node agents, and take their
//! status reports.
//!
//! Two route groups with different authorization:
//!   * **manage** (`ManageRules`, + audit) — publish a new version, list/inspect versions, rollback.
//!   * **agent** (`ReadObservability`) — read the current version, report node status, and the
//!     per-node convergence view. Agents authenticate with a §8 service token; rules are not secret.
//!
//! Handlers use `MaybePrincipal` so the SAME routes serve both wirings: governance ON (a resolved
//! principal, gated by RBAC) and governance OFF (the static bearer, attributed to `api-token`).

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::gov_api::{audit, MaybePrincipal};
use crate::server::AppState;

fn err500(e: impl std::fmt::Display) -> Response {
    (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response()
}

/// The management routes (require `ManageRules`): publish / list / inspect / rollback versions.
pub(crate) fn manage_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/rules/versions", get(list_versions).post(publish_version))
        .route("/api/rules/versions/{id}", get(get_version))
        .route("/api/rules/rollback", post(rollback))
}

/// The agent-facing routes (require `ReadObservability`): the current version, node status reports,
/// and the per-node convergence view.
pub(crate) fn agent_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/rules/current", get(current))
        .route("/api/rules/status", post(report_status))
        .route("/api/rules/nodes", get(list_nodes))
}

// ── Manage (ManageRules) ────────────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct PublishBody {
    content: String,
    #[serde(default)]
    note: String,
}

/// Publish a new immutable version and make it current. Attribution = the caller's actor. The
/// content is stored verbatim; the per-node agent pre-validates (seclang parse) before applying and
/// the WAF does validate-then-swap on reload — a server-side dry-run is a declared follow-on.
async fn publish_version(
    State(state): State<Arc<AppState>>,
    principal: MaybePrincipal,
    Json(body): Json<PublishBody>,
) -> Response {
    if body.content.trim().is_empty() {
        return (StatusCode::BAD_REQUEST, "content must not be empty").into_response();
    }
    let actor = principal.actor().to_string();
    match state.store.publish_rule_version(&body.content, &actor, &body.note).await {
        Ok(id) => {
            audit(&state, &actor, "rule.publish", Some(id.to_string()), json!({ "note": body.note })).await;
            (StatusCode::CREATED, Json(json!({ "id": id }))).into_response()
        }
        Err(e) => err500(e),
    }
}

async fn list_versions(State(state): State<Arc<AppState>>) -> Response {
    match state.store.list_rule_versions(200).await {
        Ok(versions) => Json(versions).into_response(),
        Err(e) => err500(e),
    }
}

async fn get_version(State(state): State<Arc<AppState>>, Path(id): Path<i64>) -> Response {
    match state.store.get_rule_version(id).await {
        Ok(Some(v)) => Json(v).into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, "no such version").into_response(),
        Err(e) => err500(e),
    }
}

#[derive(Deserialize)]
struct RollbackBody {
    version: i64,
}

/// Re-point the current pointer to an existing version (rollback). 404 if that version is unknown.
async fn rollback(
    State(state): State<Arc<AppState>>,
    principal: MaybePrincipal,
    Json(body): Json<RollbackBody>,
) -> Response {
    let actor = principal.actor().to_string();
    match state.store.set_current_rule_version(body.version).await {
        Ok(true) => {
            audit(&state, &actor, "rule.rollback", Some(body.version.to_string()), json!({})).await;
            (StatusCode::OK, "ok").into_response()
        }
        Ok(false) => (StatusCode::NOT_FOUND, "no such version").into_response(),
        Err(e) => err500(e),
    }
}

// ── Agent-facing (ReadObservability) ──────────────────────────────────────────────────────────

/// The current live version for a polling agent: `{version, content}`, or `{version: null,
/// content: null}` when nothing has been published yet (the agent then leaves the WAF untouched).
#[derive(Serialize)]
struct CurrentRule {
    version: Option<i64>,
    content: Option<String>,
}

async fn current(State(state): State<Arc<AppState>>) -> Response {
    match state.store.current_rule_version().await {
        Ok(Some(v)) => Json(CurrentRule { version: Some(v.id), content: Some(v.content) }).into_response(),
        Ok(None) => Json(CurrentRule { version: None, content: None }).into_response(),
        Err(e) => err500(e),
    }
}

#[derive(Deserialize)]
struct StatusBody {
    node: String,
    #[serde(default)]
    version: Option<i64>,
    status: String,
    #[serde(default)]
    detail: String,
}

/// An agent reports the version it applied and how the apply went (idempotent upsert). High-frequency
/// convergence signal — not audited.
async fn report_status(State(state): State<Arc<AppState>>, Json(body): Json<StatusBody>) -> Response {
    if body.node.trim().is_empty() {
        return (StatusCode::BAD_REQUEST, "node must not be empty").into_response();
    }
    match state.store.record_node_rule_status(&body.node, body.version, &body.status, &body.detail).await {
        Ok(()) => (StatusCode::OK, "ok").into_response(),
        Err(e) => err500(e),
    }
}

async fn list_nodes(State(state): State<Arc<AppState>>) -> Response {
    match state.store.list_node_rule_status().await {
        Ok(nodes) => Json(nodes).into_response(),
        Err(e) => err500(e),
    }
}
