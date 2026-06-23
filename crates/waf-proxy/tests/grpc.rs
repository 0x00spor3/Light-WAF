// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

//! Phase-gRPC end-to-end through the REAL proxy: a unary h2c round-trip is forwarded with
//! its trailers relayed BOTH ways (request trailer reaches the backend; the backend's
//! `grpc-status` reaches the client), and a SQLi smuggled inside a protobuf field is
//! BLOCKED (403) — proving the forwarding datapath (dedicated h2c client + trailer relay)
//! works and inspection applies to gRPC.

use std::convert::Infallible;
use std::pin::Pin;
use std::task::{Context, Poll};

use http_body_util::{BodyExt, Empty};
use hyper::body::{Body, Bytes, Frame, Incoming};
use hyper::header::{HeaderMap, HeaderName, HeaderValue};
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::{TcpListener, TcpStream};

use waf_core::{
    Config, GrpcConfig, LimitsConfig, ModulesConfig, ProxyConfig, WafConfig, WafMode,
};
use waf_proxy::Proxy;

// ── protobuf / gRPC framing ──────────────────────────────────────────────────────

fn varint(mut v: u64, out: &mut Vec<u8>) {
    loop {
        let mut b = (v & 0x7f) as u8;
        v >>= 7;
        if v != 0 {
            b |= 0x80;
        }
        out.push(b);
        if v == 0 {
            break;
        }
    }
}

fn len_field(field: u64, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    varint((field << 3) | 2, &mut out);
    varint(data.len() as u64, &mut out);
    out.extend_from_slice(data);
    out
}

fn frame(msg: &[u8]) -> Bytes {
    let mut out = vec![0u8];
    out.extend_from_slice(&(msg.len() as u32).to_be_bytes());
    out.extend_from_slice(msg);
    Bytes::from(out)
}

// ── a data-frame-then-trailers body ──────────────────────────────────────────────

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

fn hv(s: &str) -> HeaderValue {
    HeaderValue::from_str(s).unwrap()
}

async fn collect(body: Incoming) -> (Bytes, Option<HeaderMap>) {
    let c = body.collect().await.unwrap();
    let t = c.trailers().cloned();
    (c.to_bytes(), t)
}

// ── h2c gRPC backend ─────────────────────────────────────────────────────────────

/// Echoes the request trailer `x-req-trailer` into a response trailer and sets a
/// `grpc-status: 0` trailer + an `ok:<bytes-len>` body.
async fn start_grpc_backend() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let svc = service_fn(|req: Request<Incoming>| async move {
                    let (data, tr) = collect(req.into_body()).await;
                    let echoed = tr
                        .as_ref()
                        .and_then(|t| t.get("x-req-trailer"))
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("<none>")
                        .to_string();
                    let mut out_tr = HeaderMap::new();
                    out_tr.insert(HeaderName::from_static("grpc-status"), hv("0"));
                    out_tr.insert(HeaderName::from_static("x-echo-req-trailer"), hv(&echoed));
                    let body = FramedBody {
                        data: Some(Bytes::from(format!("ok:{}", data.len()))),
                        trailers: Some(out_tr),
                    };
                    let mut resp = Response::new(body);
                    resp.headers_mut().insert(HeaderName::from_static("content-type"), hv("application/grpc"));
                    Ok::<_, Infallible>(resp)
                });
                hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(stream), svc)
                    .await
                    .ok();
            });
        }
    });
    addr
}

// ── proxy + client ───────────────────────────────────────────────────────────────

fn grpc_config(backend: std::net::SocketAddr) -> Config {
    Config {
        proxy: ProxyConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            backend: format!("http://{backend}"),
        },
        waf: WafConfig {
            mode: WafMode::Blocking,
            block_threshold: 5,
            paranoia_level: 1,
            severity_scores: Default::default(),
        },
        limits: LimitsConfig::default(),
        modules: ModulesConfig {
            grpc: GrpcConfig { enabled: true, ..Default::default() },
            ..Default::default()
        },
        rate_limit: Default::default(),
        network: Default::default(),
        resilience: Default::default(),
        tls: Default::default(),
    }
}

/// Send a unary gRPC request (body + optional request trailer) to the proxy over h2c.
/// Returns `(status, response_body, response_trailers)`.
async fn grpc_call(
    proxy: std::net::SocketAddr,
    body: Bytes,
    req_trailer: Option<&str>,
) -> (u16, Bytes, Option<HeaderMap>) {
    let tcp = TcpStream::connect(proxy).await.unwrap();
    let (mut sender, conn) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tcp)).await.unwrap();
    tokio::spawn(async move { let _ = conn.await; });

    let trailers = req_trailer.map(|v| {
        let mut t = HeaderMap::new();
        t.insert(HeaderName::from_static("x-req-trailer"), hv(v));
        t
    });
    let req = Request::builder()
        .method("POST")
        .uri("/grpc.Svc/Call")
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .body(FramedBody { data: Some(body), trailers })
        .unwrap();

    let resp = sender.send_request(req).await.unwrap();
    let status = resp.status().as_u16();
    let (data, tr) = collect(resp.into_body()).await;
    (status, data, tr)
}

async fn start_proxy(backend: std::net::SocketAddr) -> std::net::SocketAddr {
    let proxy = Proxy::bind(&grpc_config(backend)).await.unwrap();
    let addr = proxy.local_addr().unwrap();
    tokio::spawn(proxy.run());
    addr
}

// ── tests ───────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn benign_unary_forwarded_with_trailers_both_ways() {
    let backend = start_grpc_backend().await;
    let proxy = start_proxy(backend).await;

    let body = frame(&len_field(1, b"hello gRPC"));
    let (status, data, trailers) = grpc_call(proxy, body, Some("trailer-from-client")).await;

    assert_eq!(status, 200);
    assert!(data.starts_with(b"ok:"), "response body relayed: {data:?}");

    let tr = trailers.expect("gRPC response must carry trailers");
    // backend→client: grpc-status relayed.
    assert_eq!(tr.get("grpc-status").unwrap(), "0");
    // client→backend: the request trailer reached the backend (echoed back).
    assert_eq!(tr.get("x-echo-req-trailer").unwrap(), "trailer-from-client");
}

#[tokio::test]
async fn sqli_in_grpc_field_is_blocked() {
    let backend = start_grpc_backend().await;
    let proxy = start_proxy(backend).await;

    let sqli = "1 UNION SELECT a,b FROM users--";
    let body = frame(&len_field(1, sqli.as_bytes()));
    let (status, _data, _tr) = grpc_call(proxy, body, None).await;

    assert_eq!(status, 403, "SQLi inside a protobuf field must be blocked before forwarding");
}

/// keep the import set honest.
#[allow(dead_code)]
fn _empty() -> Empty<Bytes> {
    Empty::new()
}
