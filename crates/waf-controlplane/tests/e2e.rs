// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: BUSL-1.1

//! End-to-end bite-test for the control plane (§7, Phase 4): a REAL WAF node's telemetry flows all
//! the way to the drill-down.
//!
//!   real Proxy (blocking + metrics) → blocked SQLi request → the WAF's own JSON decision-log
//!   → control-plane Ingestor → Postgres → `search_events` reconstructs the verdict + breakdown;
//!   and the WAF's real `/metrics` → the Prometheus parser → the `blocked` counter.
//!
//! Env-gated on `WAF_CP_DATABASE_URL` (skipped when unset). Its own test binary because it installs
//! a process-global tracing subscriber to capture the WAF logs.

use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tracing_subscriber::fmt::MakeWriter;
use waf_controlplane::prometheus::parse_requests_total;
use waf_controlplane::store::EventFilter;
use waf_controlplane::{Ingestor, Store};
use waf_core::{Config, WafMode};
use waf_proxy::Proxy;

/// A `MakeWriter` capturing every subscriber write into a shared buffer.
#[derive(Clone)]
struct BufWriter(Arc<Mutex<Vec<u8>>>);

impl io::Write for BufWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl<'a> MakeWriter<'a> for BufWriter {
    type Writer = BufWriter;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// Minimal always-200 backend (axum is already a dependency).
async fn start_backend() -> SocketAddr {
    let app = axum::Router::new().fallback(|| async { "ok" });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    addr
}

#[tokio::test]
async fn e2e_real_waf_to_drilldown_env_gated() {
    let Ok(url) = std::env::var("WAF_CP_DATABASE_URL") else {
        eprintln!("skipping: WAF_CP_DATABASE_URL not set");
        return;
    };
    let _ = rustls::crypto::ring::default_provider().install_default();

    // Capture the WAF's JSON decision-log at INFO (so both `→ request` and `request blocked` land).
    let buf = Arc::new(Mutex::new(Vec::<u8>::new()));
    let subscriber = tracing_subscriber::fmt()
        .json()
        .with_writer(BufWriter(Arc::clone(&buf)))
        .with_max_level(tracing::Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("no other global subscriber");

    // A REAL WAF node: blocking mode + metrics endpoint enabled.
    let backend = start_backend().await;
    let mut cfg = Config::default();
    cfg.proxy.listen = "127.0.0.1:0".parse().unwrap();
    cfg.proxy.backend = format!("http://{backend}");
    cfg.waf.mode = WafMode::Blocking;
    cfg.metrics.enabled = true;
    cfg.metrics.listen = "127.0.0.1:0".parse().unwrap();
    let proxy = Proxy::bind(&cfg).await.unwrap();
    let waf_addr = proxy.local_addr().unwrap();
    let metrics_addr = proxy.metrics_addr().expect("metrics enabled");
    tokio::spawn(proxy.run());

    // Drive a blocked SQLi request through the real datapath.
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://{waf_addr}/?q=1%20UNION%20SELECT%20a%2Cb%20FROM%20users--"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 403, "SQLi must be blocked");

    // Let the serving task flush its log lines.
    tokio::time::sleep(Duration::from_millis(150)).await;

    // Feed the WAF's OWN captured decision-log through the control plane. A unique node isolates
    // this run from any prior rows in a shared test database.
    let node = format!("e2e-{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos());
    let store = Store::connect(&url).await.expect("connect");
    store.migrate().await.expect("migrate");
    let ingestor = Ingestor::new(store.clone());
    let logs = String::from_utf8_lossy(&buf.lock().unwrap()).to_string();
    let stored = ingestor.ingest_ndjson(&node, &logs).await.expect("ingest");
    assert!(stored >= 1, "the blocked request must produce at least one decision event");

    // The drill-down reconstructs the verdict FROM the real WAF's log: correct request context
    // (joined from `→ request`) + the per-rule SQLi/Critical breakdown.
    let blocked =
        store.search_events(&EventFilter { decision: Some("blocked".into()), ..Default::default() }, 100).await.unwrap();
    let ev = blocked
        .iter()
        .find(|e| e.node == node && !e.contributions.is_empty())
        .expect("a blocked event with a per-rule breakdown from this run");
    assert_eq!(ev.method.as_deref(), Some("GET"), "request method joined from the → request line");
    assert!(ev.client_ip.is_some(), "client_ip joined from the → request line");
    assert!(
        ev.contributions.iter().any(|c| c.severity.as_deref() == Some("critical")),
        "the reconstructed breakdown must include a Critical contribution; got {:?}",
        ev.contributions
    );

    // The WAF's REAL /metrics, parsed by the control plane, shows the blocked request.
    let text = client.get(format!("http://{metrics_addr}/metrics")).send().await.unwrap().text().await.unwrap();
    let counts = parse_requests_total(&text);
    let blocked_count = counts.iter().find(|c| c.decision == "blocked").map(|c| c.count).unwrap_or(0);
    assert!(blocked_count >= 1, "the WAF /metrics must report a blocked request; got {counts:?}");
}
