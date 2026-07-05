// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

//! Decision-log enrichment (core 0.4): a denied request logs the per-rule `score_contributions`
//! breakdown as a JSON field. This is the ingestion ABI the enterprise control-plane §7 drill-down
//! reconstructs a blocked verdict from — so it is bite-tested on the REAL serving path (a live
//! blocked request through the proxy), not just the serde shape (that lives in waf-core).
//!
//! This test installs a process-global JSON subscriber that captures into a buffer, so it lives in
//! its OWN test binary (never `integration.rs`) to avoid a global-default conflict.

use std::convert::Infallible;
use std::io;
use std::sync::{Arc, Mutex};

use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Empty};
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::TcpListener;
use tracing_subscriber::fmt::MakeWriter;
use waf_core::{Config, WafMode};
use waf_proxy::Proxy;

type TestBody = BoxBody<Bytes, hyper::Error>;

/// A `MakeWriter` that appends every subscriber write into a shared buffer, so the test can read
/// back the emitted JSON log lines.
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

fn empty_body() -> TestBody {
    Empty::new().map_err(|never| match never {}).boxed()
}

fn test_client() -> Client<HttpConnector, TestBody> {
    Client::builder(TokioExecutor::new()).build(HttpConnector::new())
}

/// Minimal echo backend (mirrors the one in `integration.rs`; kept local so this binary is
/// self-contained).
async fn start_echo_backend() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else { break };
            tokio::spawn(async move {
                let svc = service_fn(|_req: Request<Incoming>| async {
                    Ok::<_, Infallible>(Response::new(http_body_util::Full::new(Bytes::from_static(
                        b"ok",
                    ))))
                });
                let _ = http1::Builder::new().serve_connection(TokioIo::new(stream), svc).await;
            });
        }
    });
    addr
}

fn blocking_config(backend: std::net::SocketAddr) -> Config {
    let mut c = Config::default();
    c.proxy.listen = "127.0.0.1:0".parse().unwrap();
    c.proxy.backend = format!("http://{backend}");
    c.waf.mode = WafMode::Blocking;
    c
}

#[tokio::test]
async fn blocked_request_logs_score_contributions_field() {
    // Install a process-global JSON subscriber capturing into `buf`. `set_global_default` applies
    // across the spawned serving tasks (a thread-local guard would not reach them).
    let buf = Arc::new(Mutex::new(Vec::<u8>::new()));
    let subscriber = tracing_subscriber::fmt()
        .json()
        .with_writer(BufWriter(Arc::clone(&buf)))
        .with_max_level(tracing::Level::WARN)
        .finish();
    tracing::subscriber::set_global_default(subscriber)
        .expect("no other global subscriber in this test binary");

    let backend = start_echo_backend().await;
    let proxy = Proxy::bind(&blocking_config(backend)).await.unwrap();
    let addr = proxy.local_addr().unwrap();
    tokio::spawn(proxy.run());
    let client = test_client();

    // A SQLi payload → `sqli-union-select` (Critical, 5) → blocked (403) in blocking mode.
    let resp = client
        .request(
            Request::builder()
                .uri(format!("http://{addr}/?q=1%20UNION%20SELECT%20a%2Cb%20FROM%20users--"))
                .body(empty_body())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "SQLi must be blocked in blocking mode");

    // Give the spawned serving task a moment to emit the log line.
    for _ in 0..50 {
        if String::from_utf8_lossy(&buf.lock().unwrap()).contains("request blocked") {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }

    let logs = String::from_utf8_lossy(&buf.lock().unwrap()).to_string();
    let blocked_line = logs
        .lines()
        .find(|l| l.contains("request blocked"))
        .expect("a 'request blocked' JSON log line must be emitted");

    // The enriched field is present (control-plane ingestion ABI)...
    assert!(
        blocked_line.contains("score_contributions"),
        "decision-log must carry the score_contributions field; got: {blocked_line}"
    );
    // ...and its content is the real per-rule breakdown (the SQLi module + a Critical severity),
    // parseable by the downstream drill-down.
    let parsed: serde_json::Value = serde_json::from_str(blocked_line).unwrap();
    let contributions = parsed
        .get("fields")
        .and_then(|f| f.get("score_contributions"))
        .or_else(|| parsed.get("score_contributions"))
        .and_then(|v| v.as_str())
        .expect("score_contributions must be a JSON-string field");
    let items: Vec<waf_core::ScoreContribution> =
        serde_json::from_str(contributions).expect("contributions must reconstruct into the typed model");
    assert!(
        items.iter().any(|c| c.module == "sqli" && c.severity == Some(waf_core::Severity::Critical)),
        "the breakdown must include the SQLi Critical contribution; got: {contributions}"
    );
}
