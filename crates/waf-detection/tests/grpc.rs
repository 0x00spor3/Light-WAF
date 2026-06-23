// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

//! gRPC structural module — caps on the framed protobuf body. Builds binary gRPC bodies
//! by hand and drives `GrpcModule::inspect` directly (the normalizer is exercised
//! separately). The protobuf field CONTENT path (leaf → §6 → content modules) is NOT this
//! module's job and is tested elsewhere.

use waf_core::{
    Bytes, CompressedPolicy, Config, Decision, GrpcConfig, LimitsConfig, ModulesConfig, Normalized,
    ParsedBody, ProxyConfig, RequestContext, WafConfig, WafMode, WafModule,
};

use waf_detection::grpc::GrpcModule;
use waf_detection::sqli::SqliModule;
use waf_normalizer::Normalizer;

// ── protobuf / gRPC encoders ────────────────────────────────────────────────────

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

fn varint_field(field: u64, value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    varint(field << 3, &mut out);
    varint(value, &mut out);
    out
}

/// One uncompressed gRPC frame around `msg` (flag = `compressed`).
fn frame(msg: &[u8], compressed: bool) -> Vec<u8> {
    let mut out = vec![u8::from(compressed)];
    out.extend_from_slice(&(msg.len() as u32).to_be_bytes());
    out.extend_from_slice(msg);
    out
}

/// `depth` nested NON-UTF-8 sub-messages (each wraps a varint → forces recursion).
fn nested(depth: u32) -> Vec<u8> {
    let mut inner = varint_field(2, 300);
    inner.extend_from_slice(&len_field(15, b"leaf"));
    for _ in 0..depth {
        let mut wrap = varint_field(2, 300);
        wrap.extend_from_slice(&len_field(1, &inner));
        inner = wrap;
    }
    inner
}

// ── harness ─────────────────────────────────────────────────────────────────────

fn config(grpc: GrpcConfig) -> Config {
    Config {
        proxy: ProxyConfig {
            listen: "127.0.0.1:8080".parse().unwrap(),
            backend: "http://localhost:3000".to_string(),
        },
        waf: WafConfig {
            mode: WafMode::Blocking,
            block_threshold: 5,
            paranoia_level: 1,
            severity_scores: Default::default(),
        },
        limits: LimitsConfig::default(),
        modules: ModulesConfig { grpc, ..Default::default() },
        rate_limit: Default::default(),
        network: Default::default(),
        resilience: Default::default(),
        tls: Default::default(),
    }
}

fn module(grpc: GrpcConfig) -> GrpcModule {
    let mut m = GrpcModule::new();
    m.init(&config(grpc));
    m
}

fn enabled() -> GrpcConfig {
    GrpcConfig { enabled: true, ..Default::default() }
}

/// A POST carrying `body` with the given `content_type` and optional extra headers, as the
/// normalizer would present it (Raw body for a binary gRPC payload).
fn ctx(content_type: &str, body: Vec<u8>, extra: &[(&str, &str)]) -> RequestContext {
    let mut headers = vec![("content-type".to_string(), content_type.to_string())];
    for (k, v) in extra {
        headers.push((k.to_string(), v.to_string()));
    }
    let mut c = RequestContext {
        client_ip: "127.0.0.1".parse().unwrap(),
        request_id: "t".to_string(),
        timestamp: std::time::SystemTime::now(),
        method: "POST".to_string(),
        path: "/grpc.Svc/Call".to_string(),
        raw_path: "/grpc.Svc/Call".to_string(),
        query: None,
        http_version: "HTTP/2.0".to_string(),
        headers: vec![],
        cookies: vec![],
        body: Bytes::new(),
        normalized: Normalized::default(),
        score: 0,
        score_contributions: vec![],
    };
    c.normalized.headers = headers;
    c.normalized.body = ParsedBody::Raw(Bytes::from(body));
    c
}

fn is_reject(d: &Decision) -> bool {
    matches!(d, Decision::Reject { status: 400, rule_id, .. } if rule_id == "grpc")
}

// ── tests ───────────────────────────────────────────────────────────────────────

#[test]
fn benign_unary_is_allowed() {
    let body = frame(&len_field(1, b"hello world"), false);
    assert!(matches!(module(enabled()).inspect(&ctx("application/grpc", body, &[])), Decision::Allow));
}

#[test]
fn disabled_module_allows_everything() {
    let body = frame(&nested(100), false); // would be a depth-bomb if enabled
    let m = module(GrpcConfig { enabled: false, ..Default::default() });
    assert!(matches!(m.inspect(&ctx("application/grpc", body, &[])), Decision::Allow));
}

#[test]
fn non_grpc_content_type_is_ignored() {
    let body = frame(&nested(100), false);
    assert!(matches!(module(enabled()).inspect(&ctx("application/json", body, &[])), Decision::Allow));
}

#[test]
fn oversize_message_is_rejected() {
    let big = vec![b'a'; 2048];
    let body = frame(&len_field(1, &big), false);
    let m = module(GrpcConfig { max_message_bytes: 1024, ..enabled() });
    assert!(is_reject(&m.inspect(&ctx("application/grpc", body, &[]))));
}

#[test]
fn depth_bomb_is_rejected() {
    let body = frame(&nested(40), false);
    let m = module(GrpcConfig { max_depth: 8, ..enabled() });
    assert!(is_reject(&m.inspect(&ctx("application/grpc", body, &[]))));
}

#[test]
fn field_bomb_is_rejected() {
    let mut msg = Vec::new();
    for n in 1..=50u64 {
        msg.extend_from_slice(&varint_field(n, 1));
    }
    let m = module(GrpcConfig { max_fields: 10, ..enabled() });
    assert!(is_reject(&m.inspect(&ctx("application/grpc", frame(&msg, false), &[]))));
}

#[test]
fn malformed_framing_is_rejected() {
    // A frame whose declared length exceeds the bytes present.
    let body = vec![0, 0, 0, 0, 200, 0x0a, 0x01];
    assert!(is_reject(&module(enabled()).inspect(&ctx("application/grpc", body, &[]))));
}

#[test]
fn compressed_flag_default_rejects() {
    let body = frame(&len_field(1, b"secret"), true); // per-message compressed flag
    assert!(is_reject(&module(enabled()).inspect(&ctx("application/grpc", body, &[]))));
}

#[test]
fn compressed_header_default_rejects() {
    let body = frame(&len_field(1, b"hello"), false);
    let d = module(enabled()).inspect(&ctx("application/grpc", body, &[("grpc-encoding", "gzip")]));
    assert!(is_reject(&d));
}

#[test]
fn compressed_passthrough_allows() {
    let body = frame(&len_field(1, b"secret"), true);
    let m = module(GrpcConfig { on_compressed: CompressedPolicy::Passthrough, ..enabled() });
    assert!(matches!(m.inspect(&ctx("application/grpc", body, &[])), Decision::Allow));
}

#[test]
fn identity_encoding_is_inspected_normally() {
    // `grpc-encoding: identity` must NOT be treated as compressed (absent == identity too).
    let body = frame(&len_field(1, b"hello"), false);
    let d = module(enabled()).inspect(&ctx("application/grpc", body, &[("grpc-encoding", "identity")]));
    assert!(matches!(d, Decision::Allow));
}

// ── §6 content path (Step 3): protobuf field → derived channel → content modules ──

/// Build a raw gRPC request and run the REAL normalizer (so `derived_decoded` is populated
/// from the protobuf fields, the way production does).
fn normalized_grpc_ctx(body: Vec<u8>) -> RequestContext {
    let mut c = RequestContext {
        client_ip: "127.0.0.1".parse().unwrap(),
        request_id: "t".to_string(),
        timestamp: std::time::SystemTime::now(),
        method: "POST".to_string(),
        path: "/grpc.Svc/Call".to_string(),
        raw_path: "/grpc.Svc/Call".to_string(),
        query: None,
        http_version: "HTTP/2.0".to_string(),
        headers: vec![("content-type".to_string(), "application/grpc".to_string())],
        cookies: vec![],
        body: Bytes::from(body),
        normalized: Normalized::default(),
        score: 0,
        score_contributions: vec![],
    };
    Normalizer::new(&LimitsConfig::default()).normalize(&mut c).unwrap();
    c
}

#[test]
fn sqli_in_grpc_field_is_caught_by_content_module_not_grpc_module() {
    // Paletto B: a SQLi smuggled inside a protobuf string field is a CONTENT catch — it must
    // be credited to §6 (the sqli module fires via the derived channel), NOT to the
    // structural grpc module (which sees a small, well-formed message → Allow).
    let sqli = "1 UNION SELECT a,b FROM users--";
    let ctx = normalized_grpc_ctx(frame(&len_field(1, sqli.as_bytes()), false));

    // §6: the field reached the derived channel...
    assert!(
        ctx.normalized.derived_decoded.iter().any(|d| d.contains("UNION SELECT")),
        "protobuf leaf must reach the derived channel: {:?}",
        ctx.normalized.derived_decoded
    );

    // ...so the CONTENT module fires.
    let mut sqli_m = SqliModule::new();
    sqli_m.init(&config(enabled()));
    assert!(
        matches!(sqli_m.inspect(&ctx), Decision::Scores(_)),
        "sqli must fire on the gRPC field content"
    );

    // The structural grpc module must NOT claim this catch.
    assert!(
        matches!(module(enabled()).inspect(&ctx), Decision::Allow),
        "the structural grpc module must not fire on a benign-shaped message"
    );
}
