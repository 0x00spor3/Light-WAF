// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

//! B2 — CRS/ModSecurity rule import, end-to-end through the REAL proxy.
//!
//! Loads a `seclang` file from config and verifies the imported rules act on the datapath.
//! The CARDINAL BITE (paletto #2): a request that the NATIVE content prefilter would skip
//! as benign — its token matches no built-in pattern — is still caught by an imported CRS
//! rule, proving the `structural()` module runs on the fast-path skip route (the Phase-11
//! lesson). Also checks that an UNSUPPORTED rule in the file does not break loading (D3=A).

use std::convert::Infallible;
use std::io::Write;

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
use waf_core::{Config, WafMode};
use waf_proxy::Proxy;

type TestBody = BoxBody<Bytes, hyper::Error>;

fn empty_body() -> TestBody {
    Empty::new().map_err(|never| match never {}).boxed()
}

fn test_client() -> Client<HttpConnector, TestBody> {
    Client::builder(TokioExecutor::new()).build(HttpConnector::new())
}

async fn start_echo_backend() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                http1::Builder::new()
                    .serve_connection(
                        TokioIo::new(stream),
                        service_fn(|_req: Request<Incoming>| async move {
                            Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(b"ok"))))
                        }),
                    )
                    .await
                    .ok();
            });
        }
    });
    addr
}

/// A self-deleting temp file holding the CRS `seclang` source for a test.
struct TempConf {
    path: std::path::PathBuf,
}

impl TempConf {
    fn new(contents: &str) -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("waf_crs_test_{nanos}.conf"));
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(contents.as_bytes()).unwrap();
        Self { path }
    }
    fn path_str(&self) -> String {
        self.path.to_string_lossy().into_owned()
    }
}

impl Drop for TempConf {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Blocking WAF with the CRS module pointed at `conf_path`.
fn crs_config(backend: std::net::SocketAddr, conf_path: String) -> Config {
    let mut c = Config::default();
    c.proxy.listen = "127.0.0.1:0".parse().unwrap();
    c.proxy.backend = format!("http://{backend}");
    c.waf.mode = WafMode::Blocking;
    c.modules.crs.enabled = true;
    c.modules.crs.files = vec![conf_path];
    c
}

async fn get_status(client: &Client<HttpConnector, TestBody>, url: String) -> u16 {
    client
        .request(Request::builder().method("GET").uri(url).body(empty_body()).unwrap())
        .await
        .unwrap()
        .status()
        .as_u16()
}

/// The imported rules: one supported Critical rule on a token NO native module matches,
/// and one UNSUPPORTED rule (`@detectSQLi`) that must be skipped without breaking loading.
const RULES: &str = r#"
# A custom high-confidence rule (Critical → blocks on its own at the default threshold).
SecRule ARGS "@rx (?i)bespokecrstoken" "id:9001,phase:2,severity:CRITICAL,block,msg:'custom token'"
# Outside the v1 subset → skipped at load, must not stop rule 9001 from working.
SecRule ARGS "@detectSQLi" "id:9002,phase:2,severity:CRITICAL,block"
"#;

#[tokio::test]
async fn imported_crs_rule_blocks_and_unsupported_is_tolerated() {
    let backend = start_echo_backend().await;
    let conf = TempConf::new(RULES);
    let proxy = Proxy::bind(&crs_config(backend, conf.path_str())).await.unwrap();
    let addr = proxy.local_addr().unwrap();
    tokio::spawn(proxy.run());
    let client = test_client();

    // CARDINAL BITE (#2): `bespokecrstoken` matches no built-in pattern → the native content
    // prefilter would declare the request benign and skip content inspection. The CRS rule
    // still fires because the module is `structural()` → 403.
    assert_eq!(
        get_status(&client, format!("http://{addr}/?q=bespokecrstoken")).await,
        403,
        "imported CRS rule must block via the structural() path"
    );

    // A genuinely benign request (no CRS rule, no native rule) → forwarded → 200. Proves the
    // CRS layer is not blocking everything, and that the unsupported rule 9002 did not abort
    // the load (the proxy booted and serves).
    assert_eq!(get_status(&client, format!("http://{addr}/?q=hello")).await, 200);
}

#[tokio::test]
async fn crs_disabled_by_default_does_not_block() {
    let backend = start_echo_backend().await;
    let conf = TempConf::new(RULES);
    let mut cfg = crs_config(backend, conf.path_str());
    cfg.modules.crs.enabled = false; // default-off posture
    let proxy = Proxy::bind(&cfg).await.unwrap();
    let addr = proxy.local_addr().unwrap();
    tokio::spawn(proxy.run());
    let client = test_client();

    // With CRS off, the same token is forwarded (no native rule matches it) → 200.
    assert_eq!(get_status(&client, format!("http://{addr}/?q=bespokecrstoken")).await, 200);
}
