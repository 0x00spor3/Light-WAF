pub mod config;

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
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
    path_traversal::PathTraversalModule, rate_limit::RateLimitModule, rce::RceModule,
    sqli::SqliModule, ssrf::SsrfModule, xss::XssModule,
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

struct AppState {
    client: Client<HttpConnector, HyperBoxBody>,
    backend: String,
    normalizer: Normalizer,
    pipeline: Pipeline,
    ip_resolver: ClientIpResolver,
    resilience: ResilienceConfig,
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
            let mut builder = Response::builder().status(status);
            if let Some(secs) = retry_after {
                builder = builder.header("retry-after", secs.to_string());
            }
            Some(builder.body(full_body("Too Many Requests")).unwrap())
        }
    }
}

async fn try_forward(
    req: Request<Incoming>,
    state: &AppState,
    client_addr: SocketAddr,
) -> Result<Response<HyperBoxBody>, Box<dyn std::error::Error + Send + Sync>> {
    let (parts, body) = req.into_parts();
    let body_bytes = body.collect().await?.to_bytes();

    let mut ctx = build_context(&parts, &body_bytes, client_addr, &state.ip_resolver);

    // Connection-phase modules (rate limiting) run BEFORE normalization, so
    // flood traffic is rejected without paying for Fase 2 parsing.
    let connection_verdict = state.pipeline.run_connection(&mut ctx);
    if let Some(resp) = deny_response(&ctx, connection_verdict) {
        return Ok(resp);
    }

    // Parser-limit policy (Fase 6 / Pillar 2): on a normalization failure
    // (limits exceeded / malformed input) `fail_closed` → 400; `fail_open` →
    // forward UNINSPECTED (logged loudly), trading inspection for availability.
    let normalized_ok = match state.normalizer.normalize(&mut ctx) {
        Ok(()) => true,
        Err(e) => match state.resilience.on_parser_limit {
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
        let inspection_verdict = state.pipeline.run_inspection(&mut ctx);
        if let Some(resp) = deny_response(&ctx, inspection_verdict) {
            return Ok(resp);
        }
    }

    let backend_uri: Uri = format!("{}{}", state.backend, path_and_query).parse()?;

    let mut builder = Request::builder()
        .method(parts.method)
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
    let upstream = tokio::time::timeout(state.resilience.upstream_timeout(), async {
        let resp = state.client.request(fwd_req).await?;
        let (resp_parts, resp_body) = resp.into_parts();
        let resp_bytes = resp_body.collect().await?.to_bytes();
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>((resp_parts, resp_bytes))
    })
    .await;

    let (resp_parts, resp_bytes) = match upstream {
        Ok(Ok(pair)) => pair,
        Ok(Err(e)) => return Ok(upstream_error_response(&ctx, &state.resilience, &e.to_string())),
        Err(_elapsed) => {
            return Ok(upstream_error_response(&ctx, &state.resilience, "upstream timeout"))
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

async fn handle(
    req: Request<Incoming>,
    state: Arc<AppState>,
    client_addr: SocketAddr,
) -> Result<Response<HyperBoxBody>, Infallible> {
    match try_forward(req, &state, client_addr).await {
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
    state: Arc<AppState>,
}

/// Build the enabled built-in modules from config.
fn build_modules(config: &Config) -> Vec<Box<dyn WafModule>> {
    let mut modules: Vec<Box<dyn WafModule>> = vec![Box::new(NoopLogger)];
    if config.rate_limit.enabled {
        modules.push(Box::new(RateLimitModule::new()));
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
        let listener = TcpListener::bind(config.proxy.listen).await?;
        let client: Client<HttpConnector, HyperBoxBody> =
            Client::builder(TokioExecutor::new()).build(HttpConnector::new());
        let backend = config.proxy.backend.trim_end_matches('/').to_string();
        let normalizer = Normalizer::new(&config.limits);

        let mut modules = build_modules(config);
        modules.extend(extra);
        let pipeline = Pipeline::new(config, modules);

        // PL4 is "empty but legal": warn the operator that a paranoia_level above
        // the highest shipped rule activates no extra rules (forward-compatible).
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
        Ok(Self {
            listener,
            state: Arc::new(AppState {
                client,
                backend,
                normalizer,
                pipeline,
                ip_resolver,
                resilience: config.resilience,
            }),
        })
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
