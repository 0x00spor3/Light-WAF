use std::convert::Infallible;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

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
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

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
        tls: Default::default(),
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

// ── Fase 9: resilience e2e — panic-in-module, BOTH fail modes, surviving protection ──
//
// These pin the DEC-5 contract end-to-end. The subtlety the line-299 test misses: the
// content prefilter (Pilastro 3) SKIPS inspection on prc-clean (benign) traffic, so a
// content module only ever runs on *candidate* traffic — "the request was served" alone
// does NOT prove the module ran. So the panicking module increments a shared counter
// before panicking, and the tests assert that counter. Traffic is driven by a real
// prefilter candidate:
//   - a WEAK-signal candidate: `ftp://…` → rfi-remote-url (Notice=2, < threshold 5).
//     Inspection runs (panic fires) but the lone weak rule does NOT block. So the SAME
//     request is SERVED under fail_open (200) and DENIED under fail_closed (403) — that
//     contrast is the "BOTH modes" proof.
//   - a real SQLi payload (Critical ≥ threshold) to show fail_open drops only the broken
//     module, the surviving SQLi module still blocks (one signal dropped ≠ all dropped).

/// Like `BoomModule`, but bumps a shared counter immediately BEFORE panicking, so a test
/// can PROVE the panic fired (vs. the prefilter silently skipping inspection).
struct CountingBoom {
    hits: Arc<AtomicUsize>,
}

impl WafModule for CountingBoom {
    fn id(&self) -> &str {
        "counting_boom"
    }
    fn phase(&self) -> Phase {
        Phase::RequestLine
    }
    fn init(&mut self, _: &Config) {}
    fn inspect(&self, ctx: &RequestContext) -> Decision {
        if ctx.normalized.headers.iter().any(|(k, _)| k == "x-boom") {
            self.hits.fetch_add(1, Ordering::SeqCst);
            panic!("boom: simulated module defect");
        }
        Decision::Allow
    }
}

/// Blocking-mode config at PL3 (all rules active) with an explicit `on_internal_error`.
fn make_config_resilience(backend: std::net::SocketAddr, policy: FailMode) -> Config {
    let mut cfg = make_config(backend);
    cfg.waf.mode = WafMode::Blocking;
    cfg.waf.paranoia_level = 3; // rfi-remote-url is PL3 — keep the weak candidate active
    cfg.resilience.on_internal_error = policy;
    cfg
}

/// GET `?{query}` with the `x-boom` header that trips [`CountingBoom`]. Returns status.
async fn get_with_boom(
    client: &Client<HttpConnector, TestBody>,
    addr: std::net::SocketAddr,
    query: &str,
) -> u16 {
    client
        .request(
            Request::builder()
                .uri(format!("http://{addr}/?{query}"))
                .header("x-boom", "1")
                .body(empty_body())
                .unwrap(),
        )
        .await
        .unwrap()
        .status()
        .as_u16()
}

/// `ftp://host.example/resource`, percent-encoded → rfi-remote-url (Notice=2 < 5): a
/// prefilter CANDIDATE (inspection runs → the panic fires) that does NOT block on its own.
const WEAK_CANDIDATE_QUERY: &str = "include=ftp%3A%2F%2Fhost.example%2Fresource";
/// `1 UNION SELECT a,b FROM users--` → sqli-union-select (Critical ≥ threshold → Block).
const SQLI_QUERY: &str = "q=1%20UNION%20SELECT%20a%2Cb%20FROM%20users--";

#[tokio::test]
async fn fail_open_isolates_panic_and_keeps_surviving_protection() {
    let backend = start_echo_backend().await;
    let hits = Arc::new(AtomicUsize::new(0));
    let cfg = make_config_resilience(backend, FailMode::FailOpen);
    let proxy = Proxy::bind_with_modules(&cfg, vec![Box::new(CountingBoom { hits: Arc::clone(&hits) })])
        .await
        .unwrap();
    let addr = proxy.local_addr().unwrap();
    tokio::spawn(proxy.run());
    let client = test_client();

    // Weak-signal candidate: inspection runs (panic fires → counter == 1), fail_open skips
    // the broken module, and the lone Notice rule is below threshold → request SERVED.
    assert_eq!(
        get_with_boom(&client, addr, WEAK_CANDIDATE_QUERY).await,
        200,
        "fail_open skips the panicking module; a sub-threshold request is served"
    );
    assert_eq!(
        hits.load(Ordering::SeqCst),
        1,
        "the module must actually have panicked (prefilter did not skip inspection)"
    );

    // Same panicking module, but the request now also carries a real SQLi attack. fail_open
    // drops ONLY the broken module; the surviving SQLi module still BLOCKS (403). If
    // fail_open meant 'bypass the WAF' this would be 200 — that is the assertion that bites.
    assert_eq!(
        get_with_boom(&client, addr, SQLI_QUERY).await,
        403,
        "surviving modules still block a real attack after a peer module panics"
    );
    assert_eq!(
        hits.load(Ordering::SeqCst),
        2,
        "the panicking module ran on the attack request too"
    );
}

#[tokio::test]
async fn fail_closed_turns_panic_into_a_deny() {
    let backend = start_echo_backend().await;
    let hits = Arc::new(AtomicUsize::new(0));
    let cfg = make_config_resilience(backend, FailMode::FailClosed);
    let proxy = Proxy::bind_with_modules(&cfg, vec![Box::new(CountingBoom { hits: Arc::clone(&hits) })])
        .await
        .unwrap();
    let addr = proxy.local_addr().unwrap();
    tokio::spawn(proxy.run());
    let client = test_client();

    // The SAME weak-signal candidate that fail_open SERVED (200) above: under fail_closed
    // the panic becomes a synthetic Block → 403. Same request, opposite verdict — that
    // contrast IS the 'BOTH modes' proof. The counter proves the panic actually fired.
    assert_eq!(
        get_with_boom(&client, addr, WEAK_CANDIDATE_QUERY).await,
        403,
        "fail_closed turns an internal panic into a deny"
    );
    assert_eq!(
        hits.load(Ordering::SeqCst),
        1,
        "the module must actually have panicked"
    );
}

// ── Fase 9: resilience e2e — kill-upstream & corrupt-reload ──────────────────────
//
// Both apply the prefilter-candidate requirement (ARCHITECTURE §11): the request that
// must reach inspection is a real candidate (SQLi union → Critical), so the Pilastro-3
// prefilter does not short-circuit the path under test. Both run in BLOCKING mode so
// protection-active (403) is distinguishable from protection-dropped (200) — the existing
// upstream/reload tests run where the status is the same either way and prove less.

#[tokio::test]
async fn upstream_down_waf_still_inspects_and_blocks_attacks() {
    // Kill-upstream (§9 on_upstream_error) is NOT a WAF bypass: inspection runs BEFORE the
    // upstream call (try_forward), so a malicious request is denied by the WAF and never
    // reaches the dead origin. A benign request passes inspection and only then hits the
    // dead upstream → 502. The contrast proves the 403 is inspection, not a blanket error.
    let dead_addr = {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let a = l.local_addr().unwrap();
        drop(l);
        a
    };
    let mut cfg = make_config(dead_addr);
    cfg.waf.mode = WafMode::Blocking;
    let proxy = Proxy::bind(&cfg).await.unwrap();
    let addr = proxy.local_addr().unwrap();
    tokio::spawn(proxy.run());
    let client = test_client();

    // Malicious candidate → blocked by the WAF (403), NOT 502: inspected and denied before
    // the dead upstream is ever tried.
    assert_eq!(
        sqli_status(&client, addr).await,
        403,
        "the WAF must still inspect and block attacks even when the upstream is down"
    );

    // Benign → passes inspection, then the dead upstream yields 502 (fail_closed default).
    let benign = client
        .request(
            Request::builder()
                .uri(format!("http://{addr}/healthz"))
                .body(empty_body())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        benign.status(),
        502,
        "benign traffic passes inspection and reaches the dead upstream → 502"
    );
}

#[tokio::test]
async fn corrupt_reload_keeps_protection_no_unprotected_window() {
    // Corrupt-reload (§9 on_config_error): validate-then-swap. A config that fails
    // validation must be REJECTED and last-good kept — NO window where requests pass
    // unprotected. The corrupt config below (paranoia_level = 0) is invalid (must be
    // 1..=4) AND, if ever applied, would deactivate every rule (paranoia <= 0 matches
    // none) → exactly an unprotected window. Validation must gate the swap.
    let backend = start_echo_backend().await;
    let mut cfg = make_config(backend);
    cfg.waf.mode = WafMode::Blocking;
    cfg.waf.paranoia_level = 3;
    let proxy = Proxy::bind(&cfg).await.unwrap();
    let addr = proxy.local_addr().unwrap();
    let reloader = proxy.reloader();
    tokio::spawn(proxy.run());
    let client = test_client();

    // Baseline: blocking, the SQLi candidate is blocked → 403.
    assert_eq!(sqli_status(&client, addr).await, 403);

    let corrupt = format!(
        "[proxy]\nlisten = \"{addr}\"\nbackend = \"http://{backend}\"\n[waf]\nmode = \"blocking\"\nparanoia_level = 0\n"
    );
    let path = write_cfg("corrupt-pl0", &corrupt);
    assert!(
        reloader.reload_from(&path).is_err(),
        "an invalid config (paranoia_level = 0) must be rejected"
    );

    // No unprotected window: the SAME attack is STILL blocked (403) — last-good kept. If
    // the swap had happened before validation, paranoia 0 would have dropped every rule
    // and this would be 200.
    assert_eq!(
        sqli_status(&client, addr).await,
        403,
        "protection must never drop on a rejected reload (no unprotected window)"
    );
    std::fs::remove_file(&path).ok();
}

// ── request smuggling (Fase 6 / Pillar 4) ───────────────────────────────────────

/// Send a raw HTTP/1.1 request over TCP (full byte control) and return the
/// response status line. Uses `Connection: close` so the server closes the socket.
async fn raw_status_line(addr: std::net::SocketAddr, raw: &str) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
    s.write_all(raw.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).await.unwrap();
    String::from_utf8_lossy(&buf).lines().next().unwrap_or("").to_string()
}

#[tokio::test]
async fn smuggling_te_list_rejected_through_proxy() {
    let backend = start_echo_backend().await;
    let mut cfg = make_config(backend);
    cfg.waf.mode = WafMode::Blocking;
    let proxy = Proxy::bind(&cfg).await.unwrap();
    let addr = proxy.local_addr().unwrap();
    tokio::spawn(proxy.run());

    // `gzip, chunked` is valid to hyper (TE ends in chunked) but refused by the
    // strict request-smuggling module → exercises the full stack to a 400.
    let raw = "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: gzip, chunked\r\nConnection: close\r\n\r\n0\r\n\r\n";
    let status = raw_status_line(addr, raw).await;
    assert!(status.contains("400"), "expected 400, got: {status:?}");

    // A legitimate request passes through.
    let raw_ok = "GET /ok HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n";
    let status_ok = raw_status_line(addr, raw_ok).await;
    assert!(status_ok.contains("200"), "expected 200, got: {status_ok:?}");
}

// ── hot reload (Fase 6 / Pillar 3) ──────────────────────────────────────────────

fn write_cfg(tag: &str, contents: &str) -> PathBuf {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    let mut p = std::env::temp_dir();
    p.push(format!("waf-reload-{tag}-{nanos}.toml"));
    std::fs::write(&p, contents).unwrap();
    p
}

/// Sends a GET that decodes to `1 UNION SELECT a,b FROM users--` → sqli-union-select
/// (Critical, 5) → blocked in blocking mode at threshold 5. Returns the status.
async fn sqli_status(client: &Client<HttpConnector, TestBody>, addr: std::net::SocketAddr) -> u16 {
    client
        .request(
            Request::builder()
                .uri(format!("http://{addr}/?q=1%20UNION%20SELECT%20a%2Cb%20FROM%20users--"))
                .body(empty_body())
                .unwrap(),
        )
        .await
        .unwrap()
        .status()
        .as_u16()
}

#[tokio::test]
async fn reload_valid_activates_new_rules() {
    let backend = start_echo_backend().await;
    // Start in detection-only: SQLi is detected but never blocked.
    let proxy = Proxy::bind(&make_config(backend)).await.unwrap();
    let addr = proxy.local_addr().unwrap();
    let reloader = proxy.reloader();
    tokio::spawn(proxy.run());
    let client = test_client();

    // Before reload: SQLi payload is forwarded (detection-only) → 200.
    assert_eq!(sqli_status(&client, addr).await, 200);

    // Reload to blocking mode (same backend, modules default-enabled).
    let cfg = format!(
        "[proxy]\nlisten = \"{addr}\"\nbackend = \"http://{backend}\"\n[waf]\nmode = \"blocking\"\nblock_threshold = 5\n"
    );
    let path = write_cfg("valid", &cfg);
    reloader.reload_from(&path).expect("valid reload should succeed");

    // After reload: the same payload is blocked → 403. New rules are live.
    assert_eq!(sqli_status(&client, addr).await, 403);
    std::fs::remove_file(&path).ok();
}

#[tokio::test]
async fn reload_invalid_keeps_old_config() {
    let backend = start_echo_backend().await;
    let proxy = Proxy::bind(&make_config(backend)).await.unwrap(); // detection-only
    let addr = proxy.local_addr().unwrap();
    let reloader = proxy.reloader();
    tokio::spawn(proxy.run());
    let client = test_client();

    // Invalid: trusted_hops out of range → validation error.
    let bad = format!(
        "[proxy]\nlisten = \"{addr}\"\nbackend = \"http://{backend}\"\n[waf]\nmode = \"blocking\"\n[network]\ntrusted_hops = 99\n"
    );
    let path = write_cfg("invalid", &bad);
    assert!(reloader.reload_from(&path).is_err(), "invalid config must be rejected");

    // Old config (detection-only) still active: SQLi forwarded → 200, not blocked.
    assert_eq!(sqli_status(&client, addr).await, 200);
    std::fs::remove_file(&path).ok();
}

#[tokio::test]
async fn reload_under_concurrent_load_has_no_race() {
    let backend = start_echo_backend().await;
    let proxy = Proxy::bind(&make_config(backend)).await.unwrap();
    let addr = proxy.local_addr().unwrap();
    let reloader = proxy.reloader();
    tokio::spawn(proxy.run());

    let cfg = format!(
        "[proxy]\nlisten = \"{addr}\"\nbackend = \"http://{backend}\"\n[waf]\nmode = \"detection-only\"\n"
    );
    let path = write_cfg("load", &cfg);

    let client = test_client();
    // Fire many concurrent requests...
    let mut handles = Vec::new();
    for _ in 0..40 {
        let c = client.clone();
        handles.push(tokio::spawn(async move {
            c.request(
                Request::builder()
                    .uri(format!("http://{addr}/x"))
                    .body(empty_body())
                    .unwrap(),
            )
            .await
        }));
    }
    // ...while reloading repeatedly. No panic/race; every request still completes.
    for _ in 0..10 {
        reloader.reload_from(&path).expect("reload should succeed");
    }
    for h in handles {
        let resp = h.await.unwrap().unwrap();
        assert_eq!(resp.status(), 200);
    }
    std::fs::remove_file(&path).ok();
}

#[tokio::test]
async fn reload_listen_change_is_ignored_old_kept() {
    let backend = start_echo_backend().await;
    let proxy = Proxy::bind(&make_config(backend)).await.unwrap();
    let addr = proxy.local_addr().unwrap();
    let reloader = proxy.reloader();
    tokio::spawn(proxy.run());
    let client = test_client();

    // Request a DIFFERENT bind address: restart-required → warned + ignored.
    let cfg = format!(
        "[proxy]\nlisten = \"127.0.0.1:9\"\nbackend = \"http://{backend}\"\n[waf]\nmode = \"detection-only\"\n"
    );
    let path = write_cfg("listen", &cfg);
    reloader.reload_from(&path).expect("reload should still succeed");

    // Proxy keeps serving on the ORIGINAL address.
    let resp = client
        .request(Request::builder().uri(format!("http://{addr}/x")).body(empty_body()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    std::fs::remove_file(&path).ok();
}

#[tokio::test]
async fn reload_does_not_reset_rate_limit_buckets() {
    let backend = start_echo_backend().await;
    let proxy = Proxy::bind(&make_config_rate_limited(backend, 1)).await.unwrap();
    let addr = proxy.local_addr().unwrap();
    let reloader = proxy.reloader();
    tokio::spawn(proxy.run());
    let client = test_client();
    let send = |path: &str| {
        client.request(
            Request::builder().uri(format!("http://{addr}{path}")).body(empty_body()).unwrap(),
        )
    };

    // Exhaust the single-token budget.
    assert_eq!(send("/a").await.unwrap().status(), 200);
    assert_eq!(send("/b").await.unwrap().status(), 429);

    // Reload (same rate-limit config). If buckets reset, the next request would be
    // 200 again — an exploitable bypass. They must SURVIVE the swap.
    let cfg = format!(
        "[proxy]\nlisten = \"{addr}\"\nbackend = \"http://{backend}\"\n[waf]\nmode = \"blocking\"\n[rate_limit]\nenabled = true\nrequests = 1\nwindow_seconds = 60\nburst = 1\n"
    );
    let path = write_cfg("rl", &cfg);
    reloader.reload_from(&path).expect("reload should succeed");

    assert_eq!(send("/c").await.unwrap().status(), 429, "bucket must survive reload");
    std::fs::remove_file(&path).ok();
}
