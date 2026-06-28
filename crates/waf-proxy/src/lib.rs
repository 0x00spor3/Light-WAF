// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

pub mod config;
pub mod metrics;
pub mod tls;

use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::Path;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::task::{Context, Poll};
use std::time::{Instant, SystemTime};

use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::{Body, Bytes, Frame, Incoming};
use hyper::service::service_fn;
use hyper::{HeaderMap, Request, Response, Uri};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use crate::metrics::{Metrics, Outcome};
use tls::TlsCertSource;
use tracing::{debug, error, info, warn};

use waf_core::{
    ClientIpResolver, Config, FailMode, IpSource, Normalized, RateLimitState, RequestContext,
    ResilienceConfig, StateStore, WafModule,
};
use waf_detection::{
    crs::CrsModule,
    graphql::GraphqlModule, grpc::GrpcModule, header_injection::HeaderInjectionModule, ldap::LdapModule,
    lfi_rfi::LfiRfiModule,
    mail::MailModule, nosql::NosqlModule, path_traversal::PathTraversalModule,
    rate_limit::RateLimitModule,
    rce::RceModule, request_smuggling::RequestSmugglingModule, scanner::ScannerModule,
    sqli::SqliModule, ssi::SsiModule, ssrf::SsrfModule, ssti::SstiModule, xss::XssModule,
    xxe::XxeModule, ContentPrefilter,
};
use waf_normalizer::Normalizer;
use waf_pipeline::{NoopLogger, Pipeline, PipelineVerdict};
use waf_wasm::{WasmModule, WasmOptions};

pub type HyperBoxBody = BoxBody<Bytes, hyper::Error>;

/// Headers that must not be forwarded verbatim to the backend (RFC 7230).
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "host", // re-set by hyper from the target URI
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
];

static REQUEST_COUNTER: AtomicU64 = AtomicU64::new(0);

fn next_request_id() -> String {
    let n = REQUEST_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("req-{n:016x}")
}

pub fn full_body(data: impl Into<Bytes>) -> HyperBoxBody {
    Full::new(data.into())
        .map_err(|never| match never {})
        .boxed()
}

/// A buffered body that emits one DATA frame, then one TRAILERS frame. A plain `Full`
/// cannot carry trailers; gRPC puts its status in HTTP/2 trailers (`grpc-status`/
/// `grpc-message`), so relaying them requires this. Used only when trailers are present —
/// the non-gRPC path keeps using `full_body` (byte-identical to before).
struct FramedBody {
    data: Option<Bytes>,
    trailers: Option<HeaderMap>,
}

impl Body for FramedBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        if let Some(d) = self.data.take() {
            return Poll::Ready(Some(Ok(Frame::data(d))));
        }
        if let Some(t) = self.trailers.take() {
            return Poll::Ready(Some(Ok(Frame::trailers(t))));
        }
        Poll::Ready(None)
    }
}

/// Box a buffered body, attaching `trailers` when present. With no trailers this is exactly
/// `full_body` (so the non-gRPC datapath is unchanged); with trailers it is a `FramedBody`.
fn body_with_trailers(data: Bytes, trailers: Option<HeaderMap>) -> HyperBoxBody {
    match trailers {
        None => full_body(data),
        Some(t) => FramedBody { data: Some(data), trailers: Some(t) }
            .map_err(|never| match never {})
            .boxed(),
    }
}

/// Collect a body into `(bytes, trailers)` — the trailer-preserving alternative to
/// `collect().to_bytes()`. Keeps the buffered model (so the body is still inspectable)
/// while not discarding the trailers that follow it (Step-0 invariant).
async fn collect_with_trailers<B>(body: B) -> Result<(Bytes, Option<HeaderMap>), B::Error>
where
    B: Body<Data = Bytes>,
{
    let collected = body.collect().await?;
    let trailers = collected.trailers().cloned();
    Ok((collected.to_bytes(), trailers))
}

/// A gRPC request, by Content-Type (`application/grpc`, `+proto`, `-web`, …). Such requests
/// are forwarded over h2c with their trailers relayed; everything else takes the unchanged
/// h1 path.
fn is_grpc_request(parts: &hyper::http::request::Parts) -> bool {
    parts
        .headers
        .get(hyper::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|ct| ct.trim_start().starts_with("application/grpc"))
        .unwrap_or(false)
}

fn parse_cookies(headers: &[(String, String)]) -> Vec<(String, String)> {
    headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("cookie"))
        .flat_map(|(_, value)| {
            value.split(';').filter_map(|pair| {
                let mut parts = pair.splitn(2, '=');
                let key = parts.next()?.trim().to_string();
                let val = parts.next().unwrap_or("").trim().to_string();
                Some((key, val))
            })
        })
        .collect()
}

fn build_context(
    parts: &hyper::http::request::Parts,
    body: &Bytes,
    client_addr: SocketAddr,
    ip_resolver: &ClientIpResolver,
) -> RequestContext {
    let path = parts.uri.path().to_string();
    let query = parts.uri.query().map(str::to_string);
    let method = parts.method.to_string();
    let http_version = format!("{:?}", parts.version);

    let headers: Vec<(String, String)> = parts
        .headers
        .iter()
        .filter_map(|(name, value)| {
            value.to_str().ok().map(|v| (name.to_string(), v.to_string()))
        })
        .collect();

    let cookies = parse_cookies(&headers);

    let normalized = Normalized::default();

    // Resolve the real client IP ONCE here: rate limiting, logging and future
    // Geo/IP-reputation all read it back from `ctx.client_ip` (single source of
    // truth). A fallback behind a trusted proxy means a spoofing attempt or a
    // misconfigured upstream — log it.
    let request_id = next_request_id();
    let resolved = ip_resolver.resolve(client_addr.ip(), &headers);
    match resolved.source {
        IpSource::FallbackMissingHeader | IpSource::FallbackMalformed => warn!(
            request_id = %request_id,
            peer = %client_addr.ip(),
            source = ?resolved.source,
            "client-IP resolution fell back to peer address"
        ),
        IpSource::DirectPeer | IpSource::TrustedHeader => {}
    }

    RequestContext {
        client_ip: resolved.ip,
        request_id,
        timestamp: SystemTime::now(),
        method,
        path: path.clone(),
        raw_path: path,
        query,
        http_version,
        headers,
        cookies,
        body: body.clone(),
        normalized,
        score: 0,
        score_contributions: vec![],
    }
}

/// Config-derived state, rebuilt as a unit on every hot reload and swapped
/// atomically. A request loads either the entire old or the entire new value —
/// never a mix of recompiled rules and stale thresholds.
struct Reloadable {
    backend: String,
    normalizer: Normalizer,
    pipeline: Pipeline,
    /// Fast-path skip prefilter (Fase 7 / Pillar 3). Built here, in the SAME unit as
    /// `pipeline`, from the same rule sources and the same `paranoia_level` snapshot,
    /// so a reload regenerates both together — they can never drift apart.
    prefilter: ContentPrefilter,
    ip_resolver: ClientIpResolver,
    resilience: ResilienceConfig,
}

/// Process-lifetime state that survives reloads:
/// - `client`: the hyper connection pool (kept warm);
/// - `listen_addr`: the bound address (restart-required if it changes);
/// - `rl_state`: the rate-limiter token buckets (NOT reset by a reload, so a
///   reload cannot be used to clear an attacker's throttle);
/// - `current`: the atomically-swappable `Reloadable`.
struct StaticState {
    client: Client<HttpConnector, HyperBoxBody>,
    /// A SEPARATE h2c (HTTP/2 prior-knowledge) client used ONLY for gRPC targets. Kept
    /// distinct from `client` on purpose: flipping the general client to `http2_only` would
    /// break all existing h1 forwarding — gRPC needs end-to-end h2, the rest stays h1.
    grpc_client: Client<HttpConnector, HyperBoxBody>,
    listen_addr: SocketAddr,
    rl_state: RateLimitState,
    current: RwLock<Arc<Reloadable>>,
    mode: HandlerMode,
    /// Inbound TLS terminator (Phase 12). `Some` ⇒ the listener serves ONLY TLS (h1/h2
    /// by ALPN); `None` ⇒ cleartext (h1 + h2c). Built once at bind; a required-but-broken
    /// cert fails the bind, so there is no runtime path that downgrades to cleartext.
    tls_acceptor: Option<TlsAcceptor>,
    /// Process-lifetime metrics (B1). Survives reloads like the rate-limit store. Recorded
    /// once per request in `handle`; served by the metrics task (`Proxy::metrics_listener`).
    metrics: Arc<Metrics>,
}

/// Which request handler the accept loop dispatches to. `Inspect` is the ONLY mode a
/// configured WAF ever uses (every public `bind*` sets it). `Passthrough` is a
/// `#[doc(hidden)]` bench seam set ONLY by `bind_passthrough` — no `config.toml` field
/// reaches it (that is the line separating a bench seam from a production bypass flag).
/// It exists so the Fase 9 (c) load-test can measure the WAF-overhead delta against the
/// SAME `forward_to_backend` the inspecting path uses.
#[derive(Clone, Copy)]
enum HandlerMode {
    Inspect,
    Passthrough,
}

impl StaticState {
    /// Load the current config snapshot: take the read lock just long enough to
    /// clone the `Arc`, then release it (never held across `.await`). Poisoning is
    /// recovered (`into_inner`) because the only writer holds the lock solely for a
    /// pointer assignment that cannot panic — so the data is never left invalid.
    fn current(&self) -> Arc<Reloadable> {
        self.current
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }
}

/// Handle that can hot-reload a running proxy's configuration. Obtained via
/// `Proxy::reloader()`; cheap to clone (an `Arc`). Used by the SIGHUP task in the
/// binary and directly by tests.
#[derive(Clone)]
pub struct Reloader(Arc<StaticState>);

impl Reloader {
    /// Re-read, validate (reusing Pillar-1 `config::load`) and atomically swap.
    /// On any error the current configuration is KEPT and the error is logged —
    /// a failed reload never degrades a working WAF.
    pub fn reload_from(&self, path: &Path) -> Result<(), config::LoadError> {
        let new_cfg = match config::load(path) {
            Ok(c) => c,
            Err(e) => {
                error!(error = %e, "config reload failed; keeping current configuration");
                return Err(e);
            }
        };

        // Restart-required field: the socket is already bound.
        if new_cfg.proxy.listen != self.0.listen_addr {
            warn!(
                current = %self.0.listen_addr,
                requested = %new_cfg.proxy.listen,
                "proxy.listen change requires a restart; keeping the current bind address"
            );
        }

        // Rebuild ALL config-derived state (rules recompiled, CIDR re-parsed),
        // reusing the shared rate-limit buckets so the throttle state survives.
        let new_reloadable = build_reloadable(&new_cfg, self.0.rl_state.clone(), Vec::new());

        // Atomic swap. The write section is a single pointer assignment that
        // cannot panic, so the lock is never poisoned by this path; recover
        // defensively anyway so a foreign poison can't wedge reloads.
        *self
            .0
            .current
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Arc::new(new_reloadable);
        info!("configuration reloaded");
        Ok(())
    }
}

/// Build an upstream-error response per `on_upstream_error`: 502 (fail_closed,
/// definitive gateway failure) or 503 (fail_open, retryable). Note: "fail_open"
/// here does NOT pass traffic through — there is no origin to reach — it only
/// softens the status to a retryable one. Always logged (critical operational event).
fn upstream_error_response(
    ctx: &RequestContext,
    resilience: &ResilienceConfig,
    detail: &str,
) -> Response<HyperBoxBody> {
    let (status, body) = match resilience.on_upstream_error {
        FailMode::FailClosed => (502, "Bad Gateway"),
        FailMode::FailOpen => (503, "Service Unavailable"),
    };
    warn!(
        request_id = %ctx.request_id,
        client_ip = %ctx.client_ip,
        status = status,
        policy = ?resilience.on_upstream_error,
        detail = detail,
        "upstream error: applying on_upstream_error policy"
    );
    Response::builder().status(status).body(full_body(body)).unwrap()
}

/// Map a denying pipeline verdict to an HTTP response (403 for Block, the
/// carried status — e.g. 429 + `Retry-After` — for Reject). `Allow` → `None`.
fn deny_response(
    ctx: &RequestContext,
    verdict: PipelineVerdict,
) -> Option<(Response<HyperBoxBody>, Outcome)> {
    match verdict {
        PipelineVerdict::Allow => None,
        PipelineVerdict::Block { rule_id, reason } => {
            warn!(
                request_id = %ctx.request_id,
                rule_id = %rule_id,
                reason = %reason,
                score = ctx.score,
                "request blocked"
            );
            Some((
                Response::builder()
                    .status(403)
                    .body(full_body("Forbidden"))
                    .unwrap(),
                Outcome::Blocked,
            ))
        }
        PipelineVerdict::Reject { rule_id, reason, status, retry_after } => {
            warn!(
                request_id = %ctx.request_id,
                rule_id = %rule_id,
                reason = %reason,
                status = status,
                "request rejected"
            );
            // Reason phrase + metric outcome by status: 429 rate-limit, 400 illegal framing
            // (request smuggling). Block (403 detection) is a separate arm above.
            let (body, outcome) = match status {
                429 => ("Too Many Requests", Outcome::RateLimited),
                400 => ("Bad Request", Outcome::BadRequest),
                _ => ("Rejected", Outcome::BadRequest),
            };
            let mut builder = Response::builder().status(status);
            if let Some(secs) = retry_after {
                builder = builder.header("retry-after", secs.to_string());
            }
            Some((builder.body(full_body(body)).unwrap(), outcome))
        }
    }
}

async fn try_forward(
    req: Request<Incoming>,
    state: &StaticState,
    client_addr: SocketAddr,
) -> Result<(Response<HyperBoxBody>, Outcome), Box<dyn std::error::Error + Send + Sync>> {
    // Load the current config snapshot ONCE per request (atomic): the whole
    // request runs against this `Reloadable`, immune to a concurrent reload.
    let rel = state.current();

    let (parts, body) = req.into_parts();
    // Collect the body for inspection AND keep any trailers (gRPC carries `grpc-status` in
    // HTTP/2 trailers); they are relayed to the backend, never inspected.
    let (body_bytes, req_trailers) = collect_with_trailers(body).await?;

    let mut ctx = build_context(&parts, &body_bytes, client_addr, &rel.ip_resolver);

    // Connection-phase modules (rate limiting) run BEFORE normalization, so
    // flood traffic is rejected without paying for Fase 2 parsing.
    let connection_verdict = rel.pipeline.run_connection(&mut ctx);
    if let Some(denied) = deny_response(&ctx, connection_verdict) {
        return Ok(denied);
    }

    // Parser-limit policy (Fase 6 / Pillar 2): on a normalization failure
    // (limits exceeded / malformed input) `fail_closed` → 400; `fail_open` →
    // forward UNINSPECTED (logged loudly), trading inspection for availability.
    let normalized_ok = match rel.normalizer.normalize(&mut ctx) {
        Ok(()) => true,
        Err(e) => match rel.resilience.on_parser_limit {
            FailMode::FailClosed => {
                warn!(
                    request_id = %ctx.request_id,
                    error = %e,
                    policy = ?FailMode::FailClosed,
                    "normalization failed: rejecting (on_parser_limit)"
                );
                return Ok((
                    Response::builder()
                        .status(400)
                        .body(full_body("Bad Request"))
                        .unwrap(),
                    Outcome::BadRequest,
                ));
            }
            FailMode::FailOpen => {
                warn!(
                    request_id = %ctx.request_id,
                    error = %e,
                    policy = ?FailMode::FailOpen,
                    "normalization failed: forwarding UNINSPECTED (on_parser_limit)"
                );
                false
            }
        },
    };

    let path_and_query = parts
        .uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/")
        .to_string();

    info!(
        request_id = %ctx.request_id,
        method = %ctx.method,
        path = %path_and_query,
        client_ip = %ctx.client_ip,
        "→ request"
    );

    // Skip inspection when normalization failed under fail_open (no canonical
    // data to inspect); the request is forwarded uninspected.
    if normalized_ok {
        // Fast-path (Fase 7 / Pillar 3): the prefilter decides whether any content
        // rule *could* match the canonical surface. If not, `run_inspection_gated`
        // skips inspection and returns Allow with an identical decision log. Sound
        // by construction (the scope-aware union is the OR of every active rule);
        // equivalence is proven on the corpus oracle through this same gate.
        let inspect = rel.prefilter.is_candidate(&ctx);
        let inspection_verdict = rel.pipeline.run_inspection_gated(&mut ctx, inspect);
        if let Some(denied) = deny_response(&ctx, inspection_verdict) {
            return Ok(denied);
        }
    }

    forward_to_backend(state, &rel, &parts, &path_and_query, body_bytes, req_trailers, client_addr, &ctx).await
}

/// The SINGLE forwarding path. Both the inspecting handler (`try_forward`) and the
/// `#[doc(hidden)]` passthrough seam (`try_passthrough`) call it, so the (c) load-test's
/// no-WAF leg cannot drift from production forwarding — the §13 duplicate-path risk is
/// removed at the root, not mitigated. Behaviour is unchanged vs the inlined version
/// (proven by the `passthrough_*` integration tests, green before and after the extract).
// Forwarding intrinsically threads many request facets (config snapshot, parts, payload +
// trailers, peer, context); bundling them into a struct would only move the list, not
// shorten the data this single forwarding path needs.
#[allow(clippy::too_many_arguments)]
async fn forward_to_backend(
    state: &StaticState,
    rel: &Reloadable,
    parts: &hyper::http::request::Parts,
    path_and_query: &str,
    body_bytes: Bytes,
    req_trailers: Option<HeaderMap>,
    client_addr: SocketAddr,
    ctx: &RequestContext,
) -> Result<(Response<HyperBoxBody>, Outcome), Box<dyn std::error::Error + Send + Sync>> {
    let backend_uri: Uri = format!("{}{}", rel.backend, path_and_query).parse()?;
    let is_grpc = is_grpc_request(parts);

    let mut builder = Request::builder()
        .method(parts.method.clone())
        .uri(backend_uri);

    for (name, value) in &parts.headers {
        if !HOP_BY_HOP.contains(&name.as_str()) {
            builder = builder.header(name, value);
        }
    }
    // XFF hop record: append the address THIS proxy actually saw (the peer), not
    // the resolved client IP — that would corrupt the forwarded chain semantics.
    builder = builder.header("x-forwarded-for", client_addr.ip().to_string());
    builder = builder.header("x-request-id", ctx.request_id.as_str());
    // gRPC requires `TE: trailers` on the request (stripped above as hop-by-hop) so the
    // backend negotiates trailer delivery — re-add it for gRPC targets only.
    if is_grpc {
        builder = builder.header("te", "trailers");
    }

    // gRPC: relay the request trailers and forward over the dedicated h2c client. Non-gRPC:
    // a plain `Full` body over the existing h1 client — byte-identical to before.
    let (client, fwd_body) = if is_grpc {
        (&state.grpc_client, body_with_trailers(body_bytes, req_trailers))
    } else {
        (&state.client, full_body(body_bytes))
    };
    let fwd_req = builder.body(fwd_body)?;

    // Upstream round-trip under a hard timeout so a stalled origin cannot pin the
    // worker. Connection/timeout failures apply on_upstream_error (502/503),
    // returned here rather than bubbling to the generic 502 in `handle`.
    let upstream = tokio::time::timeout(rel.resilience.upstream_timeout(), async {
        let resp = client.request(fwd_req).await?;
        let (resp_parts, resp_body) = resp.into_parts();
        // Keep the response trailers (gRPC `grpc-status`/`grpc-message`); they are relayed,
        // not inspected. A non-gRPC h1 response has none → `None` → a plain body downstream.
        let (resp_bytes, resp_trailers) = collect_with_trailers(resp_body).await?;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>((resp_parts, resp_bytes, resp_trailers))
    })
    .await;

    let (resp_parts, resp_bytes, resp_trailers) = match upstream {
        Ok(Ok(triple)) => triple,
        Ok(Err(e)) => {
            return Ok((
                upstream_error_response(ctx, &rel.resilience, &e.to_string()),
                Outcome::UpstreamError,
            ))
        }
        Err(_elapsed) => {
            return Ok((
                upstream_error_response(ctx, &rel.resilience, "upstream timeout"),
                Outcome::UpstreamError,
            ))
        }
    };

    info!(
        request_id = %ctx.request_id,
        status = %resp_parts.status,
        score = ctx.score,
        "← response"
    );

    Ok((
        Response::from_parts(resp_parts, body_with_trailers(resp_bytes, resp_trailers)),
        Outcome::Allowed,
    ))
}

/// `#[doc(hidden)]` passthrough seam: build the context and forward, SKIPPING the
/// connection phase, normalization and inspection. The WAF-overhead delta the (c)
/// load-test publishes = (inspecting leg) − (this leg) = normalize + detect, measured
/// against the identical `forward_to_backend`. `build_context` runs in BOTH legs (shared
/// proxy machinery) so it cancels in the delta. Reached only via `bind_passthrough`; no
/// `config.toml` field selects it.
async fn try_passthrough(
    req: Request<Incoming>,
    state: &StaticState,
    client_addr: SocketAddr,
) -> Result<(Response<HyperBoxBody>, Outcome), Box<dyn std::error::Error + Send + Sync>> {
    let rel = state.current();
    let (parts, body) = req.into_parts();
    let (body_bytes, req_trailers) = collect_with_trailers(body).await?;
    let ctx = build_context(&parts, &body_bytes, client_addr, &rel.ip_resolver);
    let path_and_query = parts
        .uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/")
        .to_string();
    forward_to_backend(state, &rel, &parts, &path_and_query, body_bytes, req_trailers, client_addr, &ctx).await
}

async fn handle(
    req: Request<Incoming>,
    state: Arc<StaticState>,
    client_addr: SocketAddr,
) -> Result<Response<HyperBoxBody>, Infallible> {
    // Dispatch on the (config-unreachable) handler mode. `Inspect` is production; the
    // `try_forward` decision path is unchanged. `Passthrough` is the bench seam.
    let start = Instant::now();
    let result = match state.mode {
        HandlerMode::Inspect => try_forward(req, &state, client_addr).await,
        HandlerMode::Passthrough => try_passthrough(req, &state, client_addr).await,
    };
    // Single recording point (pure side effect): the inner path classifies the Outcome;
    // an unexpected error here is the WAF's OWN failure → `internal_error`, distinct from the
    // structured upstream 502/503 already classified inside `forward_to_backend`.
    let (resp, outcome) = match result {
        Ok((resp, outcome)) => (resp, outcome),
        Err(e) => {
            error!(error = %e, client_ip = %client_addr.ip(), "forwarding error");
            let resp = Response::builder()
                .status(502)
                .body(full_body("Bad Gateway"))
                .unwrap();
            (resp, Outcome::InternalError)
        }
    };
    state.metrics.record(outcome, start.elapsed());
    Ok(resp)
}

pub struct Proxy {
    listener: TcpListener,
    state: Arc<StaticState>,
    /// Dedicated `/metrics` listener (`Some` ⇒ `[metrics].enabled`). Bound at `bind` for
    /// fail-fast; the server task is spawned by `run`. NEVER the data port (serving internal
    /// posture there would be an info leak and would be inspected by the WAF itself).
    metrics_listener: Option<TcpListener>,
}

/// Build the enabled built-in modules from config. The rate limiter is given the
/// SHARED bucket store so its throttle state survives a reload.
fn build_modules(config: &Config, rl_state: &RateLimitState) -> Vec<Box<dyn WafModule>> {
    let mut modules: Vec<Box<dyn WafModule>> = vec![Box::new(NoopLogger)];
    // Framing validation runs first among Connection-phase modules: illegal
    // framing is refused before it is even counted against the rate limit.
    if config.modules.request_smuggling.enabled {
        modules.push(Box::new(RequestSmugglingModule::new()));
    }
    if config.rate_limit.enabled {
        modules.push(Box::new(RateLimitModule::with_state(rl_state.clone())));
    }
    if config.modules.sqli.enabled {
        modules.push(Box::new(SqliModule::new()));
    }
    if config.modules.xss.enabled {
        modules.push(Box::new(XssModule::new()));
    }
    if config.modules.path_traversal.enabled {
        modules.push(Box::new(PathTraversalModule::new()));
    }
    if config.modules.rce.enabled {
        modules.push(Box::new(RceModule::new()));
    }
    if config.modules.lfi_rfi.enabled {
        modules.push(Box::new(LfiRfiModule::new()));
    }
    if config.modules.ssrf.enabled {
        modules.push(Box::new(SsrfModule::new()));
    }
    if config.modules.ldap.enabled {
        modules.push(Box::new(LdapModule::new()));
    }
    if config.modules.nosql.enabled {
        modules.push(Box::new(NosqlModule::new()));
    }
    if config.modules.mail.enabled {
        modules.push(Box::new(MailModule::new()));
    }
    if config.modules.ssti.enabled {
        modules.push(Box::new(SstiModule::new()));
    }
    if config.modules.scanner.enabled {
        modules.push(Box::new(ScannerModule::new()));
    }
    if config.modules.ssi.enabled {
        modules.push(Box::new(SsiModule::new()));
    }
    if config.modules.xxe.enabled {
        modules.push(Box::new(XxeModule::new()));
    }
    if config.modules.header_injection.enabled {
        modules.push(Box::new(HeaderInjectionModule::new()));
    }
    if config.modules.graphql.enabled {
        modules.push(Box::new(GraphqlModule::new()));
    }
    if config.modules.grpc.enabled {
        modules.push(Box::new(GrpcModule::new()));
    }
    if config.modules.crs.enabled {
        modules.push(Box::new(load_crs_module(&config.modules.crs.files)));
    }
    if config.modules.wasm.enabled {
        for plugin in &config.modules.wasm.plugins {
            if let Some(m) = load_wasm_plugin(plugin, &config.modules.wasm) {
                modules.push(Box::new(m));
            }
        }
    }
    modules
}

/// Load one Proxy-Wasm plugin. A plugin whose file is unreadable or whose `.wasm` cannot be
/// compiled/instantiated is logged loudly and skipped (fail-open at LOAD, like CRS — the
/// runtime posture is fail-closed per request). The import report is logged so the operator
/// sees the coverage, and a plugin relying on stubbed (semantic) host calls is flagged
/// **DEGRADED** but still loaded — the operator decides (policy D3=A, paletto #4).
fn load_wasm_plugin(
    plugin: &waf_core::WasmPluginConfig,
    cfg: &waf_core::WasmConfig,
) -> Option<WasmModule> {
    let bytes = match std::fs::read(&plugin.path) {
        Ok(b) => b,
        Err(e) => {
            error!(file = %plugin.path, error = %e, "WASM: cannot read plugin (skipped)");
            return None;
        }
    };
    let name = plugin_name(&plugin.path);
    let opts = WasmOptions {
        pool_size: cfg.pool_size,
        fuel_per_request: cfg.fuel_per_request,
        max_memory_bytes: cfg.max_memory_bytes,
        checkout_timeout: std::time::Duration::from_millis(cfg.checkout_timeout_ms),
    };
    let config_bytes = plugin.config.as_deref().unwrap_or("").as_bytes();
    match WasmModule::from_bytes(&name, &bytes, config_bytes, &opts) {
        Ok((module, report)) => {
            // Informational at boot; the loud "degraded" signal is emitted at runtime the
            // first time the plugin actually invokes a stubbed semantic host call.
            info!(plugin = %name, "{}", report.summary());
            Some(module)
        }
        Err(e) => {
            error!(file = %plugin.path, error = %e, "WASM: plugin failed to load (skipped)");
            None
        }
    }
}

/// Derive a short plugin name from its path (file stem), for log correlation and `rule_id`.
fn plugin_name(path: &str) -> String {
    std::path::Path::new(path)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("plugin")
        .to_string()
}

/// Read the configured CRS `seclang` files (in order), concatenate them and build the
/// [`CrsModule`]. An unreadable file is logged loudly and skipped — CRS is an additive
/// detection layer (default off), so a missing import file fails open (consistent with
/// `resilience.on_config_error` = fail-open) rather than taking down the proxy; the boot
/// log makes the gap explicit. The loaded/skipped report and the skipped-rule reasons are
/// logged so the operator sees exactly what coverage they got (policy D3=A).
fn load_crs_module(files: &[String]) -> CrsModule {
    let mut combined = String::new();
    for path in files {
        match std::fs::read_to_string(path) {
            Ok(text) => {
                combined.push_str(&text);
                combined.push('\n');
            }
            Err(e) => error!(file = %path, error = %e, "CRS import: cannot read file (skipped)"),
        }
    }
    let module = CrsModule::from_source(&combined);
    info!(files = files.len(), "{}", module.report());
    if !module.skipped().is_empty() {
        warn!(
            skipped = module.skipped().len(),
            "CRS import: some rules fall outside the supported subset (see debug logs for reasons)"
        );
        for s in module.skipped() {
            debug!(id = ?s.id, line = s.line_no, reason = %s.reason, "CRS import: rule skipped");
        }
    }
    module
}

/// Build the full config-derived state as a unit (rules recompiled, CIDR
/// re-parsed). Used at startup AND on every reload, so reload gets exactly the
/// same construction path — no mixed state. `extra` modules are appended after the
/// built-ins (test seam; they are NOT carried across a reload).
fn build_reloadable(
    config: &Config,
    rl_state: RateLimitState,
    extra: Vec<Box<dyn WafModule>>,
) -> Reloadable {
    let mut modules = build_modules(config, &rl_state);
    modules.extend(extra);
    let pipeline = Pipeline::new(config, modules);

    // PL4 is "empty but legal": warn that a paranoia_level above the highest
    // shipped rule activates no extra rules (forward-compatible).
    if config.waf.paranoia_level > waf_detection::HIGHEST_RULE_PARANOIA {
        warn!(
            paranoia_level = config.waf.paranoia_level,
            highest_rule_paranoia = waf_detection::HIGHEST_RULE_PARANOIA,
            "paranoia_level exceeds the highest existing rule paranoia: no additional rules are activated"
        );
    }
    let ip_resolver = ClientIpResolver::from_config(&config.network);
    if ip_resolver.trusted_count() < config.network.trusted_proxies.len() {
        warn!(
            configured = config.network.trusted_proxies.len(),
            valid = ip_resolver.trusted_count(),
            "some trusted_proxies CIDR entries were invalid and skipped"
        );
    }

    Reloadable {
        backend: config.proxy.backend.trim_end_matches('/').to_string(),
        normalizer: Normalizer::new(&config.limits),
        pipeline,
        // Same construction point + config snapshot as the pipeline above.
        prefilter: ContentPrefilter::new(config.waf.paranoia_level),
        ip_resolver,
        resilience: config.resilience,
    }
}

impl Proxy {
    /// Bind a proxy from config with the default extension surface (built-in
    /// modules, in-memory rate-limit store, file-based TLS cert). For embedding —
    /// injecting a custom store or extra modules — use [`Proxy::builder`].
    pub async fn bind(config: &Config) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        Self::builder(config).build().await
    }

    /// Start configuring a proxy with injectable extension points (the stable
    /// embedding API): extra detection modules and the rate-limit [`StateStore`].
    /// Every seam has a default, so `Proxy::builder(cfg).build()` equals
    /// [`Proxy::bind`].
    pub fn builder(config: &Config) -> ProxyBuilder<'_> {
        ProxyBuilder {
            config,
            modules: Vec::new(),
            state_store: None,
            cert_source: None,
            mode: HandlerMode::Inspect,
        }
    }

    /// Bind with extra detection modules appended after the built-in set.
    ///
    /// Internal seam kept for integration tests (inject a panicking module to verify
    /// Pillar-2 isolation). The stable public equivalent is
    /// `Proxy::builder(cfg).modules(..).build()`.
    #[doc(hidden)]
    pub async fn bind_with_modules(
        config: &Config,
        extra: Vec<Box<dyn WafModule>>,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        Self::bind_inner(config, extra, HandlerMode::Inspect, None, None).await
    }

    /// `#[doc(hidden)]` bench seam: bind a proxy that FORWARDS WITHOUT inspecting (no
    /// connection phase, no normalization, no detection) — the no-WAF leg of the Fase 9
    /// (c) load-test, sharing `forward_to_backend` with the real path. Not a production
    /// surface: no `config.toml` field selects it, only this constructor does.
    #[doc(hidden)]
    pub async fn bind_passthrough(
        config: &Config,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        Self::bind_inner(config, Vec::new(), HandlerMode::Passthrough, None, None).await
    }

    async fn bind_inner(
        config: &Config,
        extra: Vec<Box<dyn WafModule>>,
        mode: HandlerMode,
        state_store: Option<RateLimitState>,
        cert_source: Option<Arc<dyn TlsCertSource>>,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let listener = TcpListener::bind(config.proxy.listen).await?;
        let listen_addr = listener.local_addr()?;
        let client: Client<HttpConnector, HyperBoxBody> =
            Client::builder(TokioExecutor::new()).build(HttpConnector::new());
        // Dedicated h2c client for gRPC backends (prior-knowledge HTTP/2 over cleartext).
        let grpc_client: Client<HttpConnector, HyperBoxBody> =
            Client::builder(TokioExecutor::new()).http2_only(true).build(HttpConnector::new());

        // Build the TLS terminator BEFORE serving: a required cert that cannot be loaded
        // is a fatal boot error (fail-closed), never a silent downgrade to cleartext. An
        // injected cert source (e.g. enterprise ACME/mTLS) replaces the default file source.
        let tls_acceptor = tls::acceptor_from_source(&config.tls, cert_source)
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;
        if tls_acceptor.is_some() {
            info!(listen = %listen_addr, alpn = ?config.tls.alpn, "TLS termination enabled");
        }

        // The rate-limiter bucket store lives here (process lifetime), shared into
        // every (re)built pipeline so reloads never reset the throttle. The
        // tracked-key cap is fixed at boot (the store outlives reloads). An injected
        // store (e.g. enterprise Redis) replaces the default in-memory one.
        let rl_state = state_store
            .unwrap_or_else(|| RateLimitState::in_memory(config.rate_limit.max_tracked_keys));
        let reloadable = build_reloadable(config, rl_state.clone(), extra);

        // Metrics (B1): a dedicated `/metrics` listener bound here for fail-fast (a busy
        // port is a boot error, never a silent miss). Loopback by default; NEVER the data
        // port. Counters live process-wide and survive reloads.
        let metrics = Arc::new(Metrics::new());
        let metrics_listener = if config.metrics.enabled {
            let l = TcpListener::bind(config.metrics.listen).await?;
            info!(listen = %l.local_addr()?, "metrics endpoint enabled (/metrics)");
            Some(l)
        } else {
            None
        };

        Ok(Self {
            listener,
            state: Arc::new(StaticState {
                client,
                grpc_client,
                listen_addr,
                rl_state,
                current: RwLock::new(Arc::new(reloadable)),
                mode,
                tls_acceptor,
                metrics,
            }),
            metrics_listener,
        })
    }

    /// A cheap, cloneable handle to hot-reload this proxy's configuration.
    /// Obtain it before `run()` (which consumes `self`); the binary wires it to
    /// SIGHUP, tests call `reload_from` directly.
    pub fn reloader(&self) -> Reloader {
        Reloader(Arc::clone(&self.state))
    }

    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Address of the metrics endpoint, when `[metrics].enabled` (tests/operability).
    pub fn metrics_addr(&self) -> Option<SocketAddr> {
        self.metrics_listener.as_ref().and_then(|l| l.local_addr().ok())
    }

    pub async fn run(self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Spawn the metrics server (B1) on its dedicated listener, if enabled. It shares the
        // process-wide `Metrics` with the datapath and is wholly separate from data serving.
        if let Some(metrics_listener) = self.metrics_listener {
            let metrics = Arc::clone(&self.state.metrics);
            tokio::spawn(serve_metrics(metrics_listener, metrics));
        }
        loop {
            let (stream, client_addr) = self.listener.accept().await?;
            let state = Arc::clone(&self.state);

            tokio::spawn(async move {
                // When TLS is enabled, complete the handshake first; a handshake error is
                // logged and the connection dropped (non-fatal — the listener stays up).
                // Then serve h1/h2 (TLS by ALPN, cleartext by preface) via the auto Builder.
                // The acceptor is Arc-backed → cheap clone, frees `state` to move into serve.
                match state.tls_acceptor.clone() {
                    Some(acceptor) => match acceptor.accept(stream).await {
                        Ok(tls_stream) => {
                            serve_connection(TokioIo::new(tls_stream), state, client_addr).await;
                        }
                        Err(e) => {
                            warn!(error = %e, client_ip = %client_addr.ip(), "TLS handshake error");
                        }
                    },
                    None => {
                        serve_connection(TokioIo::new(stream), state, client_addr).await;
                    }
                }
            });
        }
    }
}

/// Stable builder for embedding the proxy with custom extension points. Obtain it
/// via [`Proxy::builder`]. Every seam defaults to the built-in behaviour, so a
/// builder with no overrides is identical to [`Proxy::bind`]. The enterprise plugs
/// a distributed rate-limit store or premium modules here **without forking**
/// (BOUNDARY §4).
pub struct ProxyBuilder<'a> {
    config: &'a Config,
    modules: Vec<Box<dyn WafModule>>,
    state_store: Option<RateLimitState>,
    cert_source: Option<Arc<dyn TlsCertSource>>,
    mode: HandlerMode,
}

impl<'a> ProxyBuilder<'a> {
    /// Replace the extra detection modules appended after the built-in set. These
    /// run after the built-ins and are NOT carried across a config reload.
    pub fn modules(mut self, modules: Vec<Box<dyn WafModule>>) -> Self {
        self.modules = modules;
        self
    }

    /// Append a single extra detection module (additive over [`Self::modules`]).
    pub fn add_module(mut self, module: Box<dyn WafModule>) -> Self {
        self.modules.push(module);
        self
    }

    /// Inject the rate-limit [`StateStore`] (e.g. a distributed Redis store). The
    /// store survives config reloads. Defaults to the in-memory token bucket sized
    /// from `[rate_limit].max_tracked_keys`.
    pub fn state_store(mut self, store: Arc<dyn StateStore>) -> Self {
        self.state_store = Some(RateLimitState::with_store(store));
        self
    }

    /// Inject the [`TlsCertSource`] (e.g. enterprise ACME/managed-PKI/mTLS). `[tls].enabled`
    /// and `[tls].alpn` still come from config; the source only governs cert provenance, so
    /// the config `cert_path`/`key_path` are ignored when one is injected. Defaults to the
    /// OPEN `FileCertSource` reading those paths.
    pub fn cert_source(mut self, source: Arc<dyn TlsCertSource>) -> Self {
        self.cert_source = Some(source);
        self
    }

    /// Bind the listener and construct the proxy with the chosen seams.
    pub async fn build(self) -> Result<Proxy, Box<dyn std::error::Error + Send + Sync>> {
        Proxy::bind_inner(self.config, self.modules, self.mode, self.state_store, self.cert_source)
            .await
    }
}

/// Serve one connection with the auto (h1/h2) builder. Generic over the transport so the
/// SAME service runs over a plain `TcpStream` or a `TlsStream` — the protocol negotiation
/// (h1 vs h2/h2c) is entirely inside `auto::Builder`, and `handle()` stays protocol-neutral.
async fn serve_connection<I>(io: I, state: Arc<StaticState>, client_addr: SocketAddr)
where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let svc = service_fn(move |req| {
        let state = Arc::clone(&state);
        handle(req, state, client_addr)
    });
    if let Err(e) = auto::Builder::new(TokioExecutor::new())
        .serve_connection(io, svc)
        .await
    {
        warn!(error = %e, client_ip = %client_addr.ip(), "connection error");
    }
}

/// Serve the `/metrics` endpoint on its dedicated listener (B1). Plain h1; a scraper opens a
/// short connection, GETs `/metrics`, reads the text. Anything that is not `GET /metrics`
/// gets a 404 — no path reflection, no other surface.
async fn serve_metrics(listener: TcpListener, metrics: Arc<Metrics>) {
    loop {
        let Ok((stream, _)) = listener.accept().await else { continue };
        let metrics = Arc::clone(&metrics);
        tokio::spawn(async move {
            let svc = service_fn(move |req: Request<Incoming>| {
                let metrics = Arc::clone(&metrics);
                async move { Ok::<_, Infallible>(metrics_response(&req, &metrics)) }
            });
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(stream), svc)
                .await;
        });
    }
}

/// `GET /metrics` → Prometheus text exposition; anything else → 404.
fn metrics_response(req: &Request<Incoming>, metrics: &Metrics) -> Response<HyperBoxBody> {
    if req.method() == hyper::Method::GET && req.uri().path() == "/metrics" {
        Response::builder()
            .status(200)
            .header("content-type", "text/plain; version=0.0.4; charset=utf-8")
            .body(full_body(metrics.render()))
            .unwrap()
    } else {
        Response::builder().status(404).body(full_body("Not Found")).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use waf_core::WafMode;

    #[test]
    fn hop_by_hop_includes_connection_and_host() {
        assert!(HOP_BY_HOP.contains(&"connection"));
        assert!(HOP_BY_HOP.contains(&"host"));
        assert!(HOP_BY_HOP.contains(&"transfer-encoding"));
    }

    #[test]
    fn hop_by_hop_excludes_regular_headers() {
        assert!(!HOP_BY_HOP.contains(&"content-type"));
        assert!(!HOP_BY_HOP.contains(&"authorization"));
        assert!(!HOP_BY_HOP.contains(&"x-custom-header"));
    }

    #[test]
    fn config_parses_from_toml() {
        let raw = r#"
[proxy]
listen = "127.0.0.1:8080"
backend = "http://localhost:3000"

[waf]
mode = "detection-only"
block_threshold = 10
"#;
        let config: Config = toml::from_str(raw).unwrap();
        assert_eq!(config.proxy.backend, "http://localhost:3000");
        assert_eq!(config.waf.mode, WafMode::DetectionOnly);
        assert_eq!(config.waf.block_threshold, 10);
    }

    #[test]
    fn config_uses_default_block_threshold_when_omitted() {
        let raw = r#"
[proxy]
listen = "127.0.0.1:8080"
backend = "http://localhost:3000"

[waf]
mode = "detection-only"
"#;
        let config: Config = toml::from_str(raw).unwrap();
        assert_eq!(config.waf.block_threshold, 5);
    }

    #[test]
    fn config_parses_network_section() {
        let raw = r#"
[proxy]
listen = "127.0.0.1:8080"
backend = "http://localhost:3000"

[waf]
mode = "blocking"

[network]
trusted_proxies = ["10.0.0.0/8", "::1"]
client_ip_header = "X-Forwarded-For"
trusted_hops = 2
"#;
        let config: Config = toml::from_str(raw).unwrap();
        assert_eq!(config.network.trusted_proxies, vec!["10.0.0.0/8", "::1"]);
        assert_eq!(config.network.client_ip_header, "X-Forwarded-For");
        assert_eq!(config.network.trusted_hops, 2);
    }

    #[test]
    fn config_network_defaults_to_failsafe_when_absent() {
        let raw = r#"
[proxy]
listen = "127.0.0.1:8080"
backend = "http://localhost:3000"

[waf]
mode = "detection-only"
"#;
        let config: Config = toml::from_str(raw).unwrap();
        assert!(config.network.trusted_proxies.is_empty());
        assert_eq!(config.network.trusted_hops, 1);
        assert_eq!(config.network.client_ip_header, "x-forwarded-for".to_string());
    }

    #[test]
    fn config_rejects_unknown_mode() {
        let raw = r#"
[proxy]
listen = "127.0.0.1:8080"
backend = "http://localhost:3000"

[waf]
mode = "unknown-mode"
"#;
        assert!(toml::from_str::<Config>(raw).is_err());
    }

    #[test]
    fn parse_cookies_splits_on_semicolon() {
        let headers = vec![("cookie".to_string(), "session=abc; user=123".to_string())];
        let cookies = parse_cookies(&headers);
        assert_eq!(cookies.len(), 2);
        assert!(cookies.contains(&("session".to_string(), "abc".to_string())));
        assert!(cookies.contains(&("user".to_string(), "123".to_string())));
    }

    #[test]
    fn parse_cookies_handles_missing_value() {
        let headers = vec![("cookie".to_string(), "flag=; token=xyz".to_string())];
        let cookies = parse_cookies(&headers);
        assert!(cookies.contains(&("flag".to_string(), "".to_string())));
        assert!(cookies.contains(&("token".to_string(), "xyz".to_string())));
    }

    #[test]
    fn parse_cookies_handles_empty_header_list() {
        assert!(parse_cookies(&[]).is_empty());
    }

    #[test]
    fn request_id_is_unique_per_call() {
        let id1 = next_request_id();
        let id2 = next_request_id();
        assert_ne!(id1, id2);
        assert!(id1.starts_with("req-"));
    }
}
