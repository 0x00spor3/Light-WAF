// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: BUSL-1.1

//! HTTP surface (axum). Ingest endpoint (Phase 2) + the read API (Phase 3): cluster status,
//! decision volumes, latency quantiles, event search and the per-request drill-down.
//!
//! Auth is a single static bearer token (v1) enforced on every route except `/healthz`. RBAC/SSO
//! is §8 (`waf-governance`). A formal OpenAPI spec is a follow-on; routes are documented in README.

use std::sync::Arc;

use axum::extract::{Path, Query, Request, State};
use axum::http::StatusCode;
use axum::middleware::{from_fn_with_state, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use tower_http::services::{ServeDir, ServeFile};

use crate::config::AlertRule;
use crate::ingest::Ingestor;
use crate::prometheus::histogram_quantile;
use crate::store::{EventFilter, Store};

/// Allowed `bucket_seconds` for the events-over-time series — a whitelist, so the endpoint cannot
/// be pushed into an arbitrarily fine/expensive aggregation.
const ALLOWED_BUCKET_SECONDS: [i64; 3] = [60, 300, 3600];
/// Hard cap on the series look-back window (7 days) — a large range on `decision_events` is costly.
const MAX_SERIES_WINDOW_SECONDS: i64 = 7 * 24 * 3600;

/// Shared handler state.
pub struct AppState {
    pub ingestor: Ingestor,
    pub store: Store,
    /// The configured alert rules (v2), exposed read-only via `GET /api/alerts/rules`.
    pub alert_rules: Vec<AlertRule>,
    /// When `Some`, serve the built SPA from this directory (dev override; production embeds it).
    pub ui_dir: Option<String>,
    /// When `Some`, every route except the public ones requires `Authorization: Bearer <token>`.
    pub api_token: Option<String>,
    /// When `Some`, governance (§8) is enabled: the read API is gated by session/RBAC instead of the
    /// plain bearer, and the user-management + audit endpoints are mounted.
    pub governance: Option<crate::gov_api::Governance>,
    /// When `Some`, the SIEM forwarder (§9) is enabled: `(config, live status handle)` for
    /// `GET /api/siem/status`. `None` when SIEM export is off.
    pub siem: Option<(crate::config::SiemConfig, crate::siem_forward::SiemStatusHandle)>,
}

/// The read-observability API routes (no auth layer attached). Shared by the plain-bearer path and,
/// when governance is on, the session/RBAC-gated path (`gov_api`).
pub(crate) fn read_api() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/cluster/status", get(cluster_status))
        .route("/api/decisions/volume", get(decisions_volume))
        .route("/api/decisions/series", get(events_series))
        .route("/api/latency", get(latency))
        .route("/api/events", get(list_events))
        .route("/api/events/{request_id}", get(get_event))
        .route("/api/alerts", get(list_alerts))
        .route("/api/alerts/rules", get(alert_rules))
        .route("/api/siem/status", get(siem_status))
}

/// Build the router. `/healthz` + `/api/version` (+ the static UI, if `ui_dir` is set) are public.
/// Ingest is always bearer-gated (machine credential). The read API is gated by the plain bearer, or
/// — when governance (§8) is enabled — by session/RBAC (and the governance endpoints are mounted).
pub fn app(state: Arc<AppState>) -> Router {
    let ingest = Router::new()
        .route("/ingest/events", post(ingest_events))
        .route_layer(from_fn_with_state(state.clone(), require_bearer));
    let api = if state.governance.is_some() {
        crate::gov_api::governed_router(&state)
    } else {
        // Governance off: the static bearer gates everything (and is the admin-equivalent, so it may
        // manage rules too — the §7 write path is available without governance, same as the read API).
        read_api()
            .merge(crate::rule_api::manage_routes())
            .merge(crate::rule_api::agent_routes())
            .route_layer(from_fn_with_state(state.clone(), require_bearer))
    };
    #[cfg_attr(not(feature = "embed-ui"), allow(unused_mut))]
    let mut router = Router::new()
        .route("/healthz", get(healthz))
        .route("/api/version", get(version))
        .route("/api/auth/config", get(auth_config))
        .merge(ingest)
        .merge(api);
    // Static SPA serving, in priority order:
    //   1. `ui_dir` set  → ServeDir from disk (development override; decoupled from `cargo build`).
    //   2. else + `embed-ui` feature → the UI embedded in the binary (single-binary production).
    //   3. else → no UI routes (API-only; a plain `cargo build` with no frontend is still valid).
    // In all cases any unmatched non-API path falls back to index.html so client-side routing works.
    if let Some(dir) = &state.ui_dir {
        let index = std::path::Path::new(dir).join("index.html");
        router = router.fallback_service(ServeDir::new(dir).fallback(ServeFile::new(index)));
    } else {
        #[cfg(feature = "embed-ui")]
        {
            router = router.fallback(embedded::serve);
        }
    }
    router.with_state(state)
}

/// Embedded single-binary UI (behind the `embed-ui` feature). The `ui/dist` folder is baked into the
/// binary at compile time; a plain build (feature off) has no UI routes and needs no `dist/`.
#[cfg(feature = "embed-ui")]
mod embedded {
    use axum::http::{header, StatusCode, Uri};
    use axum::response::{IntoResponse, Response};
    use rust_embed::RustEmbed;

    #[derive(RustEmbed)]
    #[folder = "ui/dist"]
    struct Assets;

    /// Serve an embedded asset by path; unknown non-file paths fall back to `index.html` (SPA
    /// client-side routing). Content-Type is guessed from the path.
    pub async fn serve(uri: Uri) -> Response {
        let raw = uri.path().trim_start_matches('/');
        let path = if raw.is_empty() { "index.html" } else { raw };
        if let Some(asset) = Assets::get(path) {
            let mime = mime_guess::from_path(path).first_or_octet_stream();
            return ([(header::CONTENT_TYPE, mime.as_ref())], asset.data).into_response();
        }
        // Not a real asset → serve the SPA shell so the router in the browser can handle the route.
        match Assets::get("index.html") {
            Some(asset) => {
                ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], asset.data).into_response()
            }
            None => (StatusCode::NOT_FOUND, "UI not embedded").into_response(),
        }
    }
}

async fn healthz() -> &'static str {
    "ok"
}

#[derive(Serialize)]
struct VersionInfo {
    version: &'static str,
}

/// The backend version (public), so the UI can warn on a UI↔API version drift.
async fn version() -> Json<VersionInfo> {
    Json(VersionInfo { version: env!("CARGO_PKG_VERSION") })
}

#[derive(Serialize)]
struct AuthConfig {
    /// Governance is enabled → the UI logs in with username/password (+ SSO) and a session cookie.
    /// When false, the API uses the static bearer (the UI's token gate).
    governance: bool,
    /// OIDC SSO is configured → the UI can show a "Sign in with SSO" button.
    oidc: bool,
}

/// What login options the backend offers (public), so the UI can pick its auth flow at startup.
async fn auth_config(State(state): State<Arc<AppState>>) -> Json<AuthConfig> {
    Json(AuthConfig {
        governance: state.governance.is_some(),
        oidc: state.governance.as_ref().is_some_and(|g| g.oidc.is_some()),
    })
}

// ── Auth ──────────────────────────────────────────────────────────────────────────────────────

/// Bearer-token gate (no-op when no token is configured — dev). Applied as a `route_layer`.
async fn require_bearer(State(state): State<Arc<AppState>>, req: Request, next: Next) -> Response {
    if let Some(token) = &state.api_token {
        let presented = req.headers().get("authorization").and_then(|h| h.to_str().ok());
        if !check_bearer(presented, token) {
            return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
        }
    }
    next.run(req).await
}

/// Validate an `Authorization` header value against the configured token.
pub(crate) fn check_bearer(header_value: Option<&str>, token: &str) -> bool {
    header_value.and_then(|h| h.strip_prefix("Bearer ")).map(|t| t == token).unwrap_or(false)
}

// ── Ingest (Phase 2) ────────────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct IngestQuery {
    /// Node identity for the batch (the shipper sets it; never the core).
    node: Option<String>,
}

async fn ingest_events(
    State(state): State<Arc<AppState>>,
    Query(q): Query<IngestQuery>,
    body: String,
) -> (StatusCode, String) {
    let node = q.node.unwrap_or_else(|| "unknown".to_string());
    match state.ingestor.ingest_ndjson(&node, &body).await {
        Ok(n) => (StatusCode::OK, format!("stored {n}")),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

// ── Read API (Phase 3) ────────────────────────────────────────────────────────────────────────

#[derive(Serialize)]
struct NodeStatus {
    node: String,
    last_seen: String,
}

#[derive(Serialize)]
struct DecisionVolume {
    decision: String,
    total: i64,
}

#[derive(Serialize)]
struct LatencyStats {
    node: String,
    p50_ms: f64,
    p95_ms: f64,
    p99_ms: f64,
    sample_count: i64,
}

/// Map any store error to a 500 with its message.
fn err500(e: impl std::fmt::Display) -> Response {
    (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response()
}

async fn cluster_status(State(s): State<Arc<AppState>>) -> Response {
    match s.store.cluster_status().await {
        Ok(rows) => Json(
            rows.into_iter()
                .map(|(node, ts)| NodeStatus {
                    node,
                    last_seen: ts
                        .format(&time::format_description::well_known::Rfc3339)
                        .unwrap_or_default(),
                })
                .collect::<Vec<_>>(),
        )
        .into_response(),
        Err(e) => err500(e),
    }
}

async fn decisions_volume(State(s): State<Arc<AppState>>) -> Response {
    match s.store.decision_totals().await {
        Ok(rows) => Json(
            rows.into_iter().map(|(decision, total)| DecisionVolume { decision, total }).collect::<Vec<_>>(),
        )
        .into_response(),
        Err(e) => err500(e),
    }
}

#[derive(Deserialize)]
struct SeriesQuery {
    window_seconds: Option<i64>,
    bucket_seconds: Option<i64>,
}

#[derive(Serialize)]
struct SeriesPoint {
    t: String,
    decision: String,
    count: i64,
}

/// Validate + clamp the series query params (pure, so the whitelist/cap is unit-testable). Returns
/// `(bucket, window)`: `bucket_seconds` must be whitelisted (rejected otherwise); `window_seconds`
/// is clamped server-side to `[bucket, MAX_SERIES_WINDOW_SECONDS]` so a client cannot ask for an
/// arbitrarily wide (expensive) range.
fn resolve_series_params(
    window_seconds: Option<i64>,
    bucket_seconds: Option<i64>,
) -> std::result::Result<(i64, i64), String> {
    let bucket = bucket_seconds.unwrap_or(300);
    if !ALLOWED_BUCKET_SECONDS.contains(&bucket) {
        return Err(format!("bucket_seconds must be one of {ALLOWED_BUCKET_SECONDS:?}"));
    }
    let window = window_seconds.unwrap_or(3600).clamp(bucket, MAX_SERIES_WINDOW_SECONDS);
    Ok((bucket, window))
}

/// Denied-event counts over time (for the UI chart). `bucket_seconds` must be whitelisted and the
/// window is capped server-side — the aggregation is done in SQL, never by shipping raw events.
async fn events_series(State(s): State<Arc<AppState>>, Query(q): Query<SeriesQuery>) -> Response {
    let (bucket, window) = match resolve_series_params(q.window_seconds, q.bucket_seconds) {
        Ok(v) => v,
        Err(msg) => return (StatusCode::BAD_REQUEST, msg).into_response(),
    };
    let since = time::OffsetDateTime::now_utc() - time::Duration::seconds(window);
    match s.store.events_series(since, bucket).await {
        Ok(rows) => Json(
            rows.into_iter()
                .map(|(t, decision, count)| SeriesPoint {
                    t: t.format(&time::format_description::well_known::Rfc3339).unwrap_or_default(),
                    decision,
                    count,
                })
                .collect::<Vec<_>>(),
        )
        .into_response(),
        Err(e) => err500(e),
    }
}

async fn latency(State(s): State<Arc<AppState>>) -> Response {
    let nodes = match s.store.latency_nodes().await {
        Ok(n) => n,
        Err(e) => return err500(e),
    };
    let mut out = Vec::new();
    for node in nodes {
        let buckets = match s.store.latest_latency_buckets(&node).await {
            Ok(b) => b,
            Err(e) => return err500(e),
        };
        let sample_count = buckets.last().map(|b| b.count).unwrap_or(0);
        let q = |p: f64| histogram_quantile(&buckets, p).map(|s| s * 1000.0).unwrap_or(0.0);
        out.push(LatencyStats {
            node,
            p50_ms: q(0.50),
            p95_ms: q(0.95),
            p99_ms: q(0.99),
            sample_count,
        });
    }
    Json(out).into_response()
}

#[derive(Deserialize)]
struct EventQuery {
    rule_id: Option<String>,
    decision: Option<String>,
    client_ip: Option<String>,
    limit: Option<i64>,
}

async fn list_events(State(s): State<Arc<AppState>>, Query(q): Query<EventQuery>) -> Response {
    let filter =
        EventFilter { rule_id: q.rule_id, decision: q.decision, client_ip: q.client_ip };
    let limit = q.limit.unwrap_or(100).clamp(1, 1000);
    match s.store.search_events(&filter, limit).await {
        Ok(events) => Json(events).into_response(),
        Err(e) => err500(e),
    }
}

async fn get_event(State(s): State<Arc<AppState>>, Path(request_id): Path<String>) -> Response {
    match s.store.get_decision_event(&request_id).await {
        Ok(Some(ev)) => Json(ev).into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, "no such request_id").into_response(),
        Err(e) => err500(e),
    }
}

#[derive(Deserialize)]
struct AlertQuery {
    limit: Option<i64>,
}

/// Recent fired alerts, newest first (v2).
async fn list_alerts(State(s): State<Arc<AppState>>, Query(q): Query<AlertQuery>) -> Response {
    let limit = q.limit.unwrap_or(100).clamp(1, 1000);
    match s.store.recent_alerts(limit).await {
        Ok(alerts) => Json(alerts).into_response(),
        Err(e) => err500(e),
    }
}

/// The configured alert rules (so an operator can see what is active).
async fn alert_rules(State(s): State<Arc<AppState>>) -> Response {
    Json(s.alert_rules.clone()).into_response()
}

#[derive(Serialize)]
struct SiemStreamStatus {
    destination: String,
    stream: String,
    cursor: i64,
    head: i64,
    /// `head - cursor` — the export backlog for this (destination, stream). The key operational signal.
    lag: i64,
    last_delivered: u64,
    last_success_at: Option<String>,
    last_error: Option<String>,
    last_error_at: Option<String>,
}

#[derive(Serialize)]
struct SiemStatusResponse {
    enabled: bool,
    streams: Vec<SiemStreamStatus>,
}

fn opt_rfc3339(ts: Option<time::OffsetDateTime>) -> Option<String> {
    ts.map(|t| t.format(&time::format_description::well_known::Rfc3339).unwrap_or_default())
}

/// The SIEM forwarder status (§9): per (destination, stream) cursor + head + lag + last success/error.
/// The auth headers are never exposed. `{enabled:false}` when SIEM export is off.
async fn siem_status(State(s): State<Arc<AppState>>) -> Response {
    let Some((config, status)) = &s.siem else {
        return Json(SiemStatusResponse { enabled: false, streams: Vec::new() }).into_response();
    };
    let mut out = Vec::new();
    for dest in &config.destinations {
        for &stream in &dest.streams {
            let cursor = s.store.siem_get_cursor(&dest.name, stream.as_str()).await.unwrap_or(0);
            let head = crate::siem_forward::stream_head(&s.store, stream).await.unwrap_or(cursor);
            let live = status.lock().unwrap().get(&(dest.name.clone(), stream.as_str().to_string())).cloned();
            out.push(SiemStreamStatus {
                destination: dest.name.clone(),
                stream: stream.as_str().to_string(),
                cursor,
                head,
                lag: (head - cursor).max(0),
                last_delivered: live.as_ref().map(|l| l.last_delivered).unwrap_or(0),
                last_success_at: opt_rfc3339(live.as_ref().and_then(|l| l.last_success_at)),
                last_error: live.as_ref().and_then(|l| l.last_error.clone()),
                last_error_at: opt_rfc3339(live.as_ref().and_then(|l| l.last_error_at)),
            });
        }
    }
    Json(SiemStatusResponse { enabled: true, streams: out }).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bearer_check() {
        assert!(check_bearer(Some("Bearer s3cret"), "s3cret"));
        assert!(!check_bearer(Some("Bearer wrong"), "s3cret"));
        assert!(!check_bearer(Some("s3cret"), "s3cret")); // missing scheme
        assert!(!check_bearer(None, "s3cret"));
    }

    #[test]
    fn series_params_defaults() {
        // No params → default 5-min bucket, 1-hour window.
        assert_eq!(resolve_series_params(None, None).unwrap(), (300, 3600));
    }

    #[test]
    fn series_params_reject_non_whitelisted_bucket() {
        // A bucket outside the whitelist is refused (not silently coerced).
        assert!(resolve_series_params(Some(3600), Some(45)).is_err());
        for b in ALLOWED_BUCKET_SECONDS {
            assert!(resolve_series_params(Some(3600), Some(b)).is_ok());
        }
    }

    #[test]
    fn series_params_window_capped() {
        // A window past the hard cap is clamped down server-side (not trusted from the client).
        let (bucket, window) =
            resolve_series_params(Some(MAX_SERIES_WINDOW_SECONDS * 10), Some(3600)).unwrap();
        assert_eq!(bucket, 3600);
        assert_eq!(window, MAX_SERIES_WINDOW_SECONDS);
    }

    #[test]
    fn series_params_window_floored_at_bucket() {
        // A window narrower than the bucket is clamped up to the bucket (empty range otherwise).
        let (_, window) = resolve_series_params(Some(10), Some(3600)).unwrap();
        assert_eq!(window, 3600);
    }
}
