// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

//! Fase 9 / (c) — e2e load-overhead smoke: WAF-in-path vs passthrough delta.
//! `cargo run --release -p waf-proxy --example load_overhead`.
//!
//! This is the INFORMATIONAL e2e overhead (DEC 2 leg (b)), NOT the contract: the number
//! is polluted by loopback TCP + the echo upstream, so it is far larger and noisier than
//! the isolated ~2 µs of (a). The contract stays the isolated inspection bench (a)/(d).
//!
//! Legs share ONE `forward_to_backend` (the 1b extract-method): the WAF leg is the real
//! proxy (detection-only, so a candidate is inspected then FORWARDED → 200), the
//! passthrough leg is `Proxy::bind_passthrough` (build_context → forward, no
//! connection/normalize/inspect). Delta = normalize + detect, measured against identical
//! forwarding → cannot drift (§13).
//!
//! Measurement model: the smoke uses a CLOSED-LOOP UNLOADED probe (send → await →
//! record, back-to-back), because coordinated omission — the thing open-loop guards
//! against — only bites at SATURATION, which is oha's job on the curve, not the smoke's.
//! For an UNLOADED overhead delta, closed-loop is the cleanest (no queuing, no Windows
//! sub-ms timer artefacts, minimal in-process contention). The smoke's job is only to
//! confirm the delta is REAL and the harness honest before the oha open-loop curve.
//!
//! Guards (the (a)-smoke analogs applied to e2e):
//!   - CANDIDATE proof (HARD, noise-immune): against a BLOCKING WAF the candidate must
//!     403 (it reached inspection) and the benign must 200. This is the §13 bite that
//!     does NOT depend on µs resolution — it proves structurally that the load exercises
//!     the WAF, not the prefilter skip.
//!   - LATENCY delta (REPORTED): WAF − passthrough, and the cleaner WAF-candidate −
//!     WAF-benign (pure inspection on ONE instance). Reported with an honest verdict: if
//!     the ~µs inspection signal sits below this box's e2e noise floor, that is itself the
//!     finding (DEC-C2: the e2e number is polluted → the contract stays the isolated (a)
//!     bench). The harness does not fake a delta the environment cannot resolve.

use std::net::SocketAddr;
use std::time::Instant;

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
    Config, LimitsConfig, ModulesConfig, NetworkConfig, ProxyConfig, RateLimitConfig,
    WafConfig, WafMode,
};
use waf_proxy::Proxy;

type ReqBody = BoxBody<Bytes, hyper::Error>;

const SAMPLES: usize = 30_000;
const WARMUP: usize = 2_000;

/// ssrf-cloud-metadata (Critical) — a prefilter CANDIDATE that runs full inspection.
const CANDIDATE: &str = "url=http%3A%2F%2F169.254.169.254%2Flatest%2Fmeta-data%2F";
/// Benign — prefilter-clean, inspection is skipped.
const BENIGN: &str = "q=hello";

fn empty_body() -> ReqBody {
    Empty::new().map_err(|never| match never {}).boxed()
}

fn full_body(b: &'static [u8]) -> ReqBody {
    Full::new(Bytes::from_static(b)).map_err(|never| match never {}).boxed()
}

/// Echo upstream: replies 200 "ok" immediately (a no-op, so the delta isolates the WAF,
/// not a real app's latency).
async fn start_echo() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else { break };
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let svc = service_fn(|_req: Request<Incoming>| async {
                    Ok::<_, hyper::Error>(Response::new(full_body(b"ok")))
                });
                let _ = http1::Builder::new().serve_connection(io, svc).await;
            });
        }
    });
    addr
}

fn cfg(backend: SocketAddr, mode: WafMode) -> Config {
    Config {
        proxy: ProxyConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            backend: format!("http://{backend}"),
        },
        waf: WafConfig { mode, block_threshold: 5, paranoia_level: 3, severity_scores: Default::default() },
        limits: LimitsConfig::default(),
        modules: ModulesConfig::default(),
        rate_limit: RateLimitConfig::default(),
        network: NetworkConfig::default(),
        resilience: Default::default(),
        tls: Default::default(),
    }
}

async fn one_status(client: &Client<HttpConnector, ReqBody>, addr: SocketAddr, query: &str) -> u16 {
    client
        .request(Request::builder().uri(format!("http://{addr}/?{query}")).body(empty_body()).unwrap())
        .await
        .unwrap()
        .status()
        .as_u16()
}

/// Closed-loop UNLOADED probe: send → await → record, back-to-back, `SAMPLES` times.
/// One request in flight at a time → no queuing, no pacer, minimal contention; the
/// cleanest way to resolve a small systematic overhead delta. Returns sorted e2e
/// latencies (ns) of the successful requests.
async fn probe(client: &Client<HttpConnector, ReqBody>, addr: SocketAddr, query: &str) -> Vec<u64> {
    let uri = format!("http://{addr}/?{query}");
    let mut lat = Vec::with_capacity(SAMPLES);
    let mut errors = 0usize;
    for _ in 0..SAMPLES {
        let t = Instant::now();
        let ok = client
            .request(Request::builder().uri(uri.clone()).body(empty_body()).unwrap())
            .await
            .map(|r| r.status().is_success())
            .unwrap_or(false);
        if ok {
            lat.push(t.elapsed().as_nanos() as u64);
        } else {
            errors += 1;
        }
    }
    if errors > 0 {
        eprintln!("  warning: {errors} failed requests on {query}");
    }
    lat.sort_unstable();
    lat
}

fn pct(sorted: &[u64], p: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let rank = (p / 100.0 * sorted.len() as f64).ceil() as usize;
    sorted[rank.saturating_sub(1).min(sorted.len() - 1)]
}

#[tokio::main]
async fn main() {
    let backend = start_echo().await;
    let client: Client<HttpConnector, ReqBody> =
        Client::builder(TokioExecutor::new()).build(HttpConnector::new());

    // ── Guard 1: CANDIDATE proof against a BLOCKING WAF ─────────────────────────────
    let blocking = Proxy::bind(&cfg(backend, WafMode::Blocking)).await.unwrap();
    let block_addr = blocking.local_addr().unwrap();
    tokio::spawn(blocking.run());
    let cand_status = one_status(&client, block_addr, CANDIDATE).await;
    let benign_status = one_status(&client, block_addr, BENIGN).await;
    println!("candidacy proof (blocking WAF): candidate→{cand_status} (expect 403), benign→{benign_status} (expect 200)");
    assert_eq!(cand_status, 403, "candidate must reach inspection (blocked in blocking mode)");
    assert_eq!(benign_status, 200, "benign must not trigger");

    // ── Load legs: detection-only WAF (inspect then forward) vs passthrough ─────────
    let waf = Proxy::bind(&cfg(backend, WafMode::DetectionOnly)).await.unwrap();
    let waf_addr = waf.local_addr().unwrap();
    tokio::spawn(waf.run());
    let pass = Proxy::bind_passthrough(&cfg(backend, WafMode::DetectionOnly)).await.unwrap();
    let pass_addr = pass.local_addr().unwrap();
    tokio::spawn(pass.run());

    // Warm the connection pools so pool setup is not in the samples.
    for _ in 0..WARMUP {
        let _ = one_status(&client, waf_addr, CANDIDATE).await;
        let _ = one_status(&client, pass_addr, CANDIDATE).await;
    }

    let waf_cand = probe(&client, waf_addr, CANDIDATE).await;
    let pass_cand = probe(&client, pass_addr, CANDIDATE).await;
    let waf_benign = probe(&client, waf_addr, BENIGN).await;

    let row = |name: &str, s: &[u64]| {
        println!("  {name:<22} p50 {:>7} ns   p99 {:>8} ns   (n={})", pct(s, 50.0), pct(s, 99.0), s.len());
    };
    println!("\n== e2e latency, closed-loop unloaded (loopback + echo; INFORMATIONAL, not the contract) ==");
    row("WAF / candidate", &waf_cand);
    row("passthrough / cand", &pass_cand);
    row("WAF / benign", &waf_benign);

    let p50 = |s: &[u64]| pct(s, 50.0) as i64;
    let overhead_delta = p50(&waf_cand) - p50(&pass_cand); // WAF path vs passthrough path
    let inspect_delta = p50(&waf_cand) - p50(&waf_benign); // pure inspection: full vs prefilter-skip
    let noise = (pct(&waf_cand, 99.0) - pct(&waf_cand, 50.0)) as i64; // p99−p50 ≈ jitter scale
    println!("\nWAF latency delta (median):");
    println!("  WAF − passthrough (candidate) : {overhead_delta:+} ns   (proxy-path + normalize + detect, noise-laden)");
    println!("  WAF cand − WAF benign         : {inspect_delta:+} ns   (pure inspection; expected ~+2–3µs)");
    println!("  e2e jitter scale (p99−p50)    : ~{noise} ns");

    // ── Guard 2: honest resolution verdict (REPORTED, not faked) ────────────────────
    // The inspection signal is ~µs. Compare it to this box's e2e jitter. If |signal| <<
    // jitter (e.g. the pure-inspection delta is even negative), the signal is below the
    // noise floor — that is DEC-C2's pollution made concrete, NOT a green to fabricate.
    // The noise-immune proof that the WAF works is the candidacy guard above.
    if inspect_delta.abs() < noise {
        println!("\nVERDICT: the pure-inspection signal (~µs) is BELOW this box's e2e noise floor — the delta ({inspect_delta:+} ns) is within jitter (~{noise} ns), and can come out negative purely from noise.");
        println!("This is the expected in-process outcome and exactly DEC-C2: e2e is loopback/upstream-dominated, so this number CANNOT be the contract.");
        println!("→ Contract stays the isolated ~2µs bench (a)/(d). A trustworthy e2e overhead curve needs oha on a QUIET, separate-process box (the deployment caveat, like git/CI on (d)).");
    } else {
        println!("\nVERDICT: pure-inspection delta {inspect_delta:+} ns resolves ABOVE jitter (~{noise} ns) — clean enough to read on this box.");
    }
    println!("\nThe hard guarantee that holds regardless of resolution: the candidacy guard (candidate→403, benign→200) proves the WAF really inspects — the §13 bite, noise-immune.");
}
