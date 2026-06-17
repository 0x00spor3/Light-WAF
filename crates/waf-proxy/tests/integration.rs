use std::convert::Infallible;

use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::TcpListener;
use waf_core::{
    Config, Decision, FailMode, LimitsConfig, ModulesConfig, NetworkConfig, Phase, ProxyConfig,
    RateLimitAction, RateLimitConfig, RateLimitKey, RequestContext, WafConfig, WafMode, WafModule,
};
use waf_proxy::Proxy;

/// Test module that panics when the request carries an `x-boom` header — used to
/// exercise Pillar-2 panic isolation through the real proxy.
struct BoomModule;

impl WafModule for BoomModule {
    fn id(&self) -> &str {
        "boom"
    }
    fn phase(&self) -> Phase {
        Phase::RequestLine
    }
    fn init(&mut self, _: &Config) {}
    fn inspect(&self, ctx: &RequestContext) -> Decision {
        if ctx.normalized.headers.iter().any(|(k, _)| k == "x-boom") {
            panic!("boom: simulated module defect");
        }
        Decision::Allow
    }
}

type TestBody = BoxBody<Bytes, hyper::Error>;

fn bytes_body(data: impl Into<Bytes>) -> TestBody {
    Full::new(data.into())
        .map_err(|never| match never {})
        .boxed()
}

fn empty_body() -> TestBody {
    Empty::new().map_err(|never| match never {}).boxed()
}

fn test_client() -> Client<HttpConnector, TestBody> {
    Client::builder(TokioExecutor::new()).build(HttpConnector::new())
}

/// Starts an echo backend that responds with `ok:<path_and_query>`.
async fn start_echo_backend() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                http1::Builder::new()
                    .serve_connection(
                        io,
                        service_fn(|req: Request<Incoming>| async move {
                            let pq = req
                                .uri()
                                .path_and_query()
                                .map(|pq| pq.as_str())
                                .unwrap_or("/")
                                .to_string();
                            let body = bytes_body(format!("ok:{pq}"));
                            Ok::<Response<TestBody>, Infallible>(Response::new(body))
                        }),
                    )
                    .await
                    .ok();
            });
        }
    });

    addr
}

fn make_config(backend_addr: std::net::SocketAddr) -> Config {
    Config {
        proxy: ProxyConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            backend: format!("http://{backend_addr}"),
        },
        waf: WafConfig {
            mode: WafMode::DetectionOnly,
            block_threshold: 5,
            paranoia_level: 1,
            severity_scores: Default::default(),
        },
        limits: LimitsConfig::default(),
        modules: ModulesConfig::default(),
        rate_limit: Default::default(),
        network: Default::default(),
        resilience: Default::default(),
    }
}

/// Blocking-mode config with rate limiting at `requests` per 60s, burst = requests.
fn make_config_rate_limited(backend_addr: std::net::SocketAddr, requests: u32) -> Config {
    let mut cfg = make_config(backend_addr);
    cfg.waf.mode = WafMode::Blocking;
    cfg.rate_limit = RateLimitConfig {
        enabled: true,
        key: RateLimitKey::ClientIp,
        requests,
        window_seconds: 60,
        burst: Some(requests),
        action: RateLimitAction::Block,
        score: 5,
        max_tracked_keys: 1000,
    };
    cfg
}

#[tokio::test]
async fn rate_limit_returns_429_after_budget_exhausted() {
    let backend = start_echo_backend().await;
    let proxy = Proxy::bind(&make_config_rate_limited(backend, 1)).await.unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    tokio::spawn(proxy.run());

    let client = test_client();
    let send = |path: &str| {
        client.request(
            Request::builder()
                .method("GET")
                .uri(format!("http://{proxy_addr}{path}"))
                .body(empty_body())
                .unwrap(),
        )
    };

    // First request consumes the single token → forwarded (200).
    let first = send("/a").await.unwrap();
    assert_eq!(first.status(), 200);

    // Second request within the window → 429 with Retry-After.
    let second = send("/b").await.unwrap();
    assert_eq!(second.status(), 429);
    assert!(second.headers().contains_key("retry-after"), "429 must carry Retry-After");
}

#[tokio::test]
async fn distinct_clients_behind_same_lb_get_separate_buckets() {
    // Proves the Issue-2 fix: two clients behind the SAME trusted LB (same peer
    // 127.0.0.1) are keyed on their resolved XFF IP, not the shared proxy IP, so
    // they no longer collide in one rate-limit bucket.
    let backend = start_echo_backend().await;
    let mut cfg = make_config_rate_limited(backend, 1); // burst = 1 per key
    cfg.network = NetworkConfig {
        trusted_proxies: vec!["127.0.0.1".to_string()],
        client_ip_header: "x-forwarded-for".to_string(),
        trusted_hops: 1,
    };
    let proxy = Proxy::bind(&cfg).await.unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    tokio::spawn(proxy.run());

    let client = test_client();
    let send = |xff: &str| {
        client.request(
            Request::builder()
                .method("GET")
                .uri(format!("http://{proxy_addr}/x"))
                .header("x-forwarded-for", xff)
                .body(empty_body())
                .unwrap(),
        )
    };

    // Client A's first request consumes A's single token → 200.
    assert_eq!(send("1.2.3.4").await.unwrap().status(), 200);
    // Client B (different resolved IP) has its OWN bucket → also 200, not 429.
    assert_eq!(send("5.6.7.8").await.unwrap().status(), 200);
    // Client A again → A's bucket is now empty → 429 (per-key, as expected).
    assert_eq!(send("1.2.3.4").await.unwrap().status(), 429);
}

#[tokio::test]
async fn passthrough_forwards_get_request() {
    let backend = start_echo_backend().await;
    let proxy = Proxy::bind(&make_config(backend)).await.unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    tokio::spawn(proxy.run());

    let resp = test_client()
        .request(
            Request::builder()
                .method("GET")
                .uri(format!("http://{proxy_addr}/hello"))
                .body(empty_body())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body = resp.collect().await.unwrap().to_bytes();
    assert_eq!(body.as_ref(), b"ok:/hello");
}

#[tokio::test]
async fn passthrough_forwards_path_and_query() {
    let backend = start_echo_backend().await;
    let proxy = Proxy::bind(&make_config(backend)).await.unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    tokio::spawn(proxy.run());

    let resp = test_client()
        .request(
            Request::builder()
                .method("GET")
                .uri(format!("http://{proxy_addr}/api/v1?foo=bar&x=1"))
                .body(empty_body())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body = resp.collect().await.unwrap().to_bytes();
    assert_eq!(body.as_ref(), b"ok:/api/v1?foo=bar&x=1");
}

#[tokio::test]
async fn passthrough_returns_502_when_backend_down() {
    // Bind a listener, grab its port, then drop it so nothing is accepting.
    let dead_addr = {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let a = l.local_addr().unwrap();
        drop(l);
        a
    };

    let proxy = Proxy::bind(&make_config(dead_addr)).await.unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    tokio::spawn(proxy.run());

    let resp = test_client()
        .request(
            Request::builder()
                .method("GET")
                .uri(format!("http://{proxy_addr}/test"))
                .body(empty_body())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), 502);
}

#[tokio::test]
async fn upstream_down_fail_open_returns_503() {
    // Override on_upstream_error → fail_open: still 5xx (no origin to reach), but
    // 503 retryable instead of 502. Proves the policy override changes behaviour.
    let dead_addr = {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let a = l.local_addr().unwrap();
        drop(l);
        a
    };
    let mut cfg = make_config(dead_addr);
    cfg.resilience.on_upstream_error = FailMode::FailOpen;

    let proxy = Proxy::bind(&cfg).await.unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    tokio::spawn(proxy.run());

    let resp = test_client()
        .request(
            Request::builder()
                .uri(format!("http://{proxy_addr}/x"))
                .body(empty_body())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), 503);
}

#[tokio::test]
async fn panic_in_module_is_isolated_other_clients_unaffected() {
    // A module panics on the request carrying `x-boom`. With the default
    // on_internal_error=fail_open, that request is still served (module skipped),
    // and a concurrent normal client's connection is NOT interrupted.
    let backend = start_echo_backend().await;
    let proxy = Proxy::bind_with_modules(&make_config(backend), vec![Box::new(BoomModule)])
        .await
        .unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    tokio::spawn(proxy.run());

    let client = test_client();
    let boom = client.request(
        Request::builder()
            .uri(format!("http://{proxy_addr}/boom"))
            .header("x-boom", "1")
            .body(empty_body())
            .unwrap(),
    );
    let normal = client.request(
        Request::builder()
            .uri(format!("http://{proxy_addr}/ok"))
            .body(empty_body())
            .unwrap(),
    );

    let (boom_resp, normal_resp) = tokio::join!(boom, normal);
    // Panicking request: fail_open → served, not a dropped connection.
    assert_eq!(boom_resp.unwrap().status(), 200);
    // The other client is completely unaffected.
    assert_eq!(normal_resp.unwrap().status(), 200);
}
