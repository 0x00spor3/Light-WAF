pub mod config;

use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::SystemTime;

use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, Uri};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::TcpListener;
use tracing::{error, info, warn};

use waf_core::{
    ClientIpResolver, Config, FailMode, IpSource, Normalized, RequestContext, ResilienceConfig,
    WafModule,
};
use waf_detection::{
    header_injection::HeaderInjectionModule, lfi_rfi::LfiRfiModule,
    path_traversal::PathTraversalModule,
    rate_limit::{RateLimitModule, RateLimitState},
    rce::RceModule, request_smuggling::RequestSmugglingModule, sqli::SqliModule, ssrf::SsrfModule,
    xss::XssModule, ContentPrefilter,
};
use waf_normalizer::Normalizer;
use waf_pipeline::{NoopLogger, Pipeline, PipelineVerdict};

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
    listen_addr: SocketAddr,
    rl_state: RateLimitState,
    current: RwLock<Arc<Reloadable>>,
    mode: HandlerMode,
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
) -> Option<Response<HyperBoxBody>> {
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
            Some(
                Response::builder()
                    .status(403)
                    .body(full_body("Forbidden"))
                    .unwrap(),
            )
        }
        PipelineVerdict::Reject { rule_id, reason, status, retry_after } => {
            warn!(
                request_id = %ctx.request_id,
                rule_id = %rule_id,
                reason = %reason,
                status = status,
                "request rejected"
            );
            // Reason phrase by status: 429 rate-limit, 400 illegal framing
            // (request smuggling). Block (403 detection) is a separate arm above.
            let body = match status {
                429 => "Too Many Requests",
                400 => "Bad Request",
                _ => "Rejected",
            };
            let mut builder = Response::builder().status(status);
            if let Some(secs) = retry_after {
                builder = builder.header("retry-after", secs.to_string());
            }
            Some(builder.body(full_body(body)).unwrap())
        }
    }
}

async fn try_forward(
    req: Request<Incoming>,
    state: &StaticState,
    client_addr: SocketAddr,
) -> Result<Response<HyperBoxBody>, Box<dyn std::error::Error + Send + Sync>> {
    // Load the current config snapshot ONCE per request (atomic): the whole
    // request runs against this `Reloadable`, immune to a concurrent reload.
    let rel = state.current();

    let (parts, body) = req.into_parts();
    let body_bytes = body.collect().await?.to_bytes();

    let mut ctx = build_context(&parts, &body_bytes, client_addr, &rel.ip_resolver);

    // Connection-phase modules (rate limiting) run BEFORE normalization, so
    // flood traffic is rejected without paying for Fase 2 parsing.
    let connection_verdict = rel.pipeline.run_connection(&mut ctx);
    if let Some(resp) = deny_response(&ctx, connection_verdict) {
        return Ok(resp);
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
                return Ok(Response::builder()
                    .status(400)
                    .body(full_body("Bad Request"))
                    .unwrap());
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
        if let Some(resp) = deny_response(&ctx, inspection_verdict) {
            return Ok(resp);
        }
    }

    forward_to_backend(state, &rel, &parts, &path_and_query, body_bytes, client_addr, &ctx).await
}

/// The SINGLE forwarding path. Both the inspecting handler (`try_forward`) and the
/// `#[doc(hidden)]` passthrough seam (`try_passthrough`) call it, so the (c) load-test's
/// no-WAF leg cannot drift from production forwarding — the §13 duplicate-path risk is
/// removed at the root, not mitigated. Behaviour is unchanged vs the inlined version
/// (proven by the `passthrough_*` integration tests, green before and after the extract).
async fn forward_to_backend(
    state: &StaticState,
    rel: &Reloadable,
    parts: &hyper::http::request::Parts,
    path_and_query: &str,
    body_bytes: Bytes,
    client_addr: SocketAddr,
    ctx: &RequestContext,
) -> Result<Response<HyperBoxBody>, Box<dyn std::error::Error + Send + Sync>> {
    let backend_uri: Uri = format!("{}{}", rel.backend, path_and_query).parse()?;

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

    let fwd_req = builder.body(full_body(body_bytes))?;

    // Upstream round-trip under a hard timeout so a stalled origin cannot pin the
    // worker. Connection/timeout failures apply on_upstream_error (502/503),
    // returned here rather than bubbling to the generic 502 in `handle`.
    let upstream = tokio::time::timeout(rel.resilience.upstream_timeout(), async {
        let resp = state.client.request(fwd_req).await?;
        let (resp_parts, resp_body) = resp.into_parts();
        let resp_bytes = resp_body.collect().await?.to_bytes();
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>((resp_parts, resp_bytes))
    })
    .await;

    let (resp_parts, resp_bytes) = match upstream {
        Ok(Ok(pair)) => pair,
        Ok(Err(e)) => return Ok(upstream_error_response(ctx, &rel.resilience, &e.to_string())),
        Err(_elapsed) => {
            return Ok(upstream_error_response(ctx, &rel.resilience, "upstream timeout"))
        }
    };

    info!(
        request_id = %ctx.request_id,
        status = %resp_parts.status,
        score = ctx.score,
        "← response"
    );

    Ok(Response::from_parts(resp_parts, full_body(resp_bytes)))
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
) -> Result<Response<HyperBoxBody>, Box<dyn std::error::Error + Send + Sync>> {
    let rel = state.current();
    let (parts, body) = req.into_parts();
    let body_bytes = body.collect().await?.to_bytes();
    let ctx = build_context(&parts, &body_bytes, client_addr, &rel.ip_resolver);
    let path_and_query = parts
        .uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/")
        .to_string();
    forward_to_backend(state, &rel, &parts, &path_and_query, body_bytes, client_addr, &ctx).await
}

async fn handle(
    req: Request<Incoming>,
    state: Arc<StaticState>,
    client_addr: SocketAddr,
) -> Result<Response<HyperBoxBody>, Infallible> {
    // Dispatch on the (config-unreachable) handler mode. `Inspect` is production; the
    // `try_forward` decision path is unchanged. `Passthrough` is the bench seam.
    let result = match state.mode {
        HandlerMode::Inspect => try_forward(req, &state, client_addr).await,
        HandlerMode::Passthrough => try_passthrough(req, &state, client_addr).await,
    };
    match result {
        Ok(resp) => Ok(resp),
        Err(e) => {
            error!(error = %e, client_ip = %client_addr.ip(), "forwarding error");
            Ok(Response::builder()
                .status(502)
                .body(full_body("Bad Gateway"))
                .unwrap())
        }
    }
}

pub struct Proxy {
    listener: TcpListener,
    state: Arc<StaticState>,
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
    if config.modules.header_injection.enabled {
        modules.push(Box::new(HeaderInjectionModule::new()));
    }
    modules
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
    pub async fn bind(config: &Config) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        Self::bind_with_modules(config, Vec::new()).await
    }

    /// Bind with extra detection modules appended after the built-in set.
    ///
    /// Test/advanced seam: used by integration tests to inject a panicking module
    /// and verify Pillar-2 isolation. Not a stable public embedding API — hidden
    /// from the rendered docs.
    #[doc(hidden)]
    pub async fn bind_with_modules(
        config: &Config,
        extra: Vec<Box<dyn WafModule>>,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        Self::bind_inner(config, extra, HandlerMode::Inspect).await
    }

    /// `#[doc(hidden)]` bench seam: bind a proxy that FORWARDS WITHOUT inspecting (no
    /// connection phase, no normalization, no detection) — the no-WAF leg of the Fase 9
    /// (c) load-test, sharing `forward_to_backend` with the real path. Not a production
    /// surface: no `config.toml` field selects it, only this constructor does.
    #[doc(hidden)]
    pub async fn bind_passthrough(
        config: &Config,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        Self::bind_inner(config, Vec::new(), HandlerMode::Passthrough).await
    }

    async fn bind_inner(
        config: &Config,
        extra: Vec<Box<dyn WafModule>>,
        mode: HandlerMode,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let listener = TcpListener::bind(config.proxy.listen).await?;
        let listen_addr = listener.local_addr()?;
        let client: Client<HttpConnector, HyperBoxBody> =
            Client::builder(TokioExecutor::new()).build(HttpConnector::new());

        // The rate-limiter bucket store lives here (process lifetime), shared into
        // every (re)built pipeline so reloads never reset the throttle.
        let rl_state = RateLimitState::new();
        let reloadable = build_reloadable(config, rl_state.clone(), extra);

        Ok(Self {
            listener,
            state: Arc::new(StaticState {
                client,
                listen_addr,
                rl_state,
                current: RwLock::new(Arc::new(reloadable)),
                mode,
            }),
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

    pub async fn run(self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        loop {
            let (stream, client_addr) = self.listener.accept().await?;
            let state = Arc::clone(&self.state);

            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let svc = service_fn(move |req| {
                    let state = Arc::clone(&state);
                    handle(req, state, client_addr)
                });
                if let Err(e) = http1::Builder::new().serve_connection(io, svc).await {
                    warn!(error = %e, client_ip = %client_addr.ip(), "connection error");
                }
            });
        }
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
