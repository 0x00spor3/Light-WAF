//! Phase 12 TLS termination — end-to-end matrix through the REAL proxy.
//!
//! Covers the protocol matrix (h1-cleartext is already covered by `integration.rs`):
//! h2-over-TLS and h1-over-TLS benign requests are forwarded; **the cardinal bite** — a SQLi
//! over h2-over-TLS is still BLOCKED (403), proving inspection is protocol-agnostic; h2c
//! (cleartext HTTP/2) is served when TLS is off. Plus the fail-safes: ALPN `http/1.1` over
//! TLS serves h1 cleanly (negotiation, not h2-forcing); an untrusted-cert handshake fails
//! WITHOUT taking the listener down; and a cleartext request to a TLS port is rejected (no
//! silent downgrade).

use std::convert::Infallible;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName};
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;

use waf_core::{
    Config, LimitsConfig, ModulesConfig, ProxyConfig, TlsConfig, WafConfig, WafMode,
};
use waf_proxy::tls::{acceptor_from_config, build_server_config, FileCertSource};
use waf_proxy::Proxy;

type TestBody = BoxBody<Bytes, hyper::Error>;

fn empty_body() -> TestBody {
    Empty::new().map_err(|never| match never {}).boxed()
}

fn provider() -> Arc<tokio_rustls::rustls::crypto::CryptoProvider> {
    Arc::new(tokio_rustls::rustls::crypto::ring::default_provider())
}

/// `1 UNION SELECT a,b FROM users--` — sqli-union-select (Critical ≥ threshold → Block).
const SQLI_PATH: &str = "/?q=1%20UNION%20SELECT%20a%2Cb%20FROM%20users--";

// ── fixtures ────────────────────────────────────────────────────────────────────

/// Self-signed cert for `localhost`: PEM files for the server + the DER for the client
/// to trust. Returns `(cert_path, key_path, cert_der)`.
fn cert_fixture() -> (PathBuf, PathBuf, CertificateDer<'static>) {
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let der = ck.cert.der().clone();
    let dir = std::env::temp_dir();
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    let cert_path = dir.join(format!("waf-tls-{nanos}-cert.pem"));
    let key_path = dir.join(format!("waf-tls-{nanos}-key.pem"));
    std::fs::write(&cert_path, ck.cert.pem()).unwrap();
    std::fs::write(&key_path, ck.key_pair.serialize_pem()).unwrap();
    (cert_path, key_path, der)
}

/// Cleartext echo backend: `ok:<path_and_query>`.
async fn start_echo_backend() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                http1::Builder::new()
                    .serve_connection(
                        TokioIo::new(stream),
                        service_fn(|req: Request<Incoming>| async move {
                            let pq = req.uri().path_and_query().map(|p| p.as_str()).unwrap_or("/").to_string();
                            Ok::<_, Infallible>(Response::new(Full::new(Bytes::from(format!("ok:{pq}")))))
                        }),
                    )
                    .await
                    .ok();
            });
        }
    });
    addr
}

fn base_config(backend: std::net::SocketAddr) -> Config {
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
        modules: ModulesConfig::default(),
        rate_limit: Default::default(),
        network: Default::default(),
        resilience: Default::default(),
        tls: Default::default(),
    }
}

fn tls_config(backend: std::net::SocketAddr, cert: &Path, key: &Path) -> Config {
    let mut c = base_config(backend);
    c.tls = TlsConfig {
        enabled: true,
        cert_path: cert.to_string_lossy().into_owned(),
        key_path: key.to_string_lossy().into_owned(),
        alpn: vec!["h2".to_string(), "http/1.1".to_string()],
    };
    c
}

// ── TLS client ──────────────────────────────────────────────────────────────────

/// Connect to `addr` over TLS offering `alpn`, trusting `trust` (when `Some`), and GET
/// `path`. Returns `(negotiated_alpn, status)` or `Err` (e.g. handshake failure).
async fn tls_get(
    addr: std::net::SocketAddr,
    trust: Option<CertificateDer<'static>>,
    alpn: &[&[u8]],
    path: &str,
) -> Result<(Vec<u8>, u16), String> {
    let mut roots = RootCertStore::empty();
    if let Some(c) = trust {
        roots.add(c).unwrap();
    }
    let mut cfg = ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();

    let connector = TlsConnector::from(Arc::new(cfg));
    let tcp = TcpStream::connect(addr).await.map_err(|e| e.to_string())?;
    let tls = connector
        .connect(ServerName::try_from("localhost").unwrap(), tcp)
        .await
        .map_err(|e| e.to_string())?;
    let negotiated = tls.get_ref().1.alpn_protocol().map(|p| p.to_vec()).unwrap_or_default();

    let req = Request::builder().method("GET").uri(path).body(empty_body()).unwrap();
    let status = if negotiated == b"h2" {
        let (mut s, conn) = hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tls))
            .await
            .map_err(|e| e.to_string())?;
        tokio::spawn(async move { let _ = conn.await; });
        s.send_request(req).await.map_err(|e| e.to_string())?.status().as_u16()
    } else {
        let (mut s, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls)).await.map_err(|e| e.to_string())?;
        tokio::spawn(async move { let _ = conn.await; });
        s.send_request(req).await.map_err(|e| e.to_string())?.status().as_u16()
    };
    Ok((negotiated, status))
}

async fn start_tls_proxy() -> (std::net::SocketAddr, CertificateDer<'static>, PathBuf, PathBuf) {
    let backend = start_echo_backend().await;
    let (cert_path, key_path, der) = cert_fixture();
    let proxy = Proxy::bind(&tls_config(backend, &cert_path, &key_path)).await.unwrap();
    let addr = proxy.local_addr().unwrap();
    tokio::spawn(proxy.run());
    (addr, der, cert_path, key_path)
}

fn cleanup(cert: PathBuf, key: PathBuf) {
    std::fs::remove_file(cert).ok();
    std::fs::remove_file(key).ok();
}

// ── protocol matrix ───────────────────────────────────────────────────────────

#[tokio::test]
async fn h2_over_tls_benign_is_forwarded() {
    let (addr, der, cert, key) = start_tls_proxy().await;
    let (alpn, status) = tls_get(addr, Some(der), &[b"h2"], "/hello").await.unwrap();
    assert_eq!(alpn, b"h2", "must negotiate h2");
    assert_eq!(status, 200);
    cleanup(cert, key);
}

#[tokio::test]
async fn h1_over_tls_benign_is_forwarded() {
    // Fail-safe (a): ALPN offers only http/1.1 → server negotiates h1, does NOT force h2.
    let (addr, der, cert, key) = start_tls_proxy().await;
    let (alpn, status) = tls_get(addr, Some(der), &[b"http/1.1"], "/hello").await.unwrap();
    assert_eq!(alpn, b"http/1.1", "must negotiate http/1.1");
    assert_eq!(status, 200);
    cleanup(cert, key);
}

#[tokio::test]
async fn sqli_blocked_over_h2_tls() {
    // THE CARDINAL BITE: inspection is protocol-agnostic — a SQLi tunnelled inside
    // h2-over-TLS is blocked exactly like over cleartext h1.
    let (addr, der, cert, key) = start_tls_proxy().await;
    let (alpn, status) = tls_get(addr, Some(der), &[b"h2"], SQLI_PATH).await.unwrap();
    assert_eq!(alpn, b"h2");
    assert_eq!(status, 403, "SQLi over h2-over-TLS must be blocked");
    cleanup(cert, key);
}

#[tokio::test]
async fn sqli_blocked_over_h1_tls() {
    let (addr, der, cert, key) = start_tls_proxy().await;
    let (_, status) = tls_get(addr, Some(der), &[b"http/1.1"], SQLI_PATH).await.unwrap();
    assert_eq!(status, 403, "SQLi over h1-over-TLS must be blocked");
    cleanup(cert, key);
}

// ── fail-safes ──────────────────────────────────────────────────────────────────

#[tokio::test]
async fn untrusted_cert_handshake_fails_but_listener_survives() {
    // Fail-safe (b): a client that does not trust the self-signed cert fails the
    // handshake — and the listener stays up (a subsequent TRUSTED request succeeds).
    let (addr, der, cert, key) = start_tls_proxy().await;

    let untrusted = tls_get(addr, None, &[b"h2"], "/x").await;
    assert!(untrusted.is_err(), "handshake with an untrusted cert must fail");

    let (_, status) = tls_get(addr, Some(der), &[b"h2"], "/x").await.unwrap();
    assert_eq!(status, 200, "the listener must still serve after a failed handshake");
    cleanup(cert, key);
}

#[tokio::test]
async fn cleartext_request_to_tls_port_is_rejected() {
    // No silent downgrade: a plain-HTTP request to the TLS listener must NOT be served
    // as cleartext (the rustls server cannot parse it as a ClientHello → connection error).
    let (addr, _der, cert, key) = start_tls_proxy().await;
    let client: Client<HttpConnector, TestBody> =
        Client::builder(TokioExecutor::new()).build(HttpConnector::new());
    let res = client
        .request(Request::builder().uri(format!("http://{addr}/x")).body(empty_body()).unwrap())
        .await;
    assert!(res.is_err(), "cleartext to a TLS port must fail, never fall back to plaintext");
    cleanup(cert, key);
}

#[tokio::test]
async fn h2c_cleartext_served_when_tls_off() {
    // The 4th protocol: with TLS off, the auto Builder still serves h2c (prior-knowledge
    // HTTP/2 over cleartext).
    let backend = start_echo_backend().await;
    let proxy = Proxy::bind(&base_config(backend)).await.unwrap();
    let addr = proxy.local_addr().unwrap();
    tokio::spawn(proxy.run());

    let tcp = TcpStream::connect(addr).await.unwrap();
    let (mut s, conn) = hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tcp))
        .await
        .unwrap();
    tokio::spawn(async move { let _ = conn.await; });
    let resp = s
        .send_request(Request::builder().method("GET").uri("/hello").body(empty_body()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
}

// ── unit: the cert seam ─────────────────────────────────────────────────────────

#[test]
fn acceptor_disabled_is_none() {
    assert!(acceptor_from_config(&TlsConfig::default()).unwrap().is_none());
}

#[test]
fn acceptor_missing_cert_file_is_fatal_error() {
    // enabled + unreadable cert → Err (fail-closed boot, no cleartext fallback).
    let tls = TlsConfig {
        enabled: true,
        cert_path: "/no/such/cert.pem".to_string(),
        key_path: "/no/such/key.pem".to_string(),
        alpn: vec!["h2".to_string()],
    };
    assert!(acceptor_from_config(&tls).is_err());
}

#[test]
fn server_config_sets_alpn_from_config() {
    let (cert, key, _der) = cert_fixture();
    let source = FileCertSource::new(&cert, &key);
    let alpn = vec!["h2".to_string(), "http/1.1".to_string()];
    let cfg = build_server_config(&source, &alpn).unwrap();
    assert_eq!(cfg.alpn_protocols, vec![b"h2".to_vec(), b"http/1.1".to_vec()]);
    cleanup(cert, key);
}
