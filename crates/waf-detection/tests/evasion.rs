// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

//! F-1 evasion module: locks the frozen design decisions (2026-07-16).
//!
//! The module scores two normalizer flags. These tests build the context through the
//! REAL normalizer (so the flags are set authentically) and assert the PATH-only
//! scoping that keeps `evasion-null-byte` from double-counting `pt-null-byte`.

use waf_core::{
    Bytes, Config, Decision, LimitsConfig, Normalized, RequestContext, Severity, WafModule,
};
use waf_detection::evasion::EvasionModule;
use waf_normalizer::Normalizer;

fn base_ctx() -> RequestContext {
    RequestContext {
        client_ip: "127.0.0.1".parse().unwrap(),
        request_id: "t".to_string(),
        timestamp: std::time::SystemTime::now(),
        method: "GET".to_string(),
        path: "/".to_string(),
        raw_path: "/".to_string(),
        query: None,
        http_version: "HTTP/1.1".to_string(),
        headers: vec![],
        cookies: vec![],
        body: Bytes::new(),
        normalized: Normalized::default(),
        score: 0,
        score_contributions: vec![],
    }
}

/// Run the real normalizer over a prepared raw context so the flags get set.
fn normalized(ctx: RequestContext) -> RequestContext {
    let mut ctx = ctx;
    Normalizer::new(&LimitsConfig::default())
        .normalize(&mut ctx)
        .expect("normalization failed");
    ctx
}

fn with_raw_path(p: &str) -> RequestContext {
    let mut c = base_ctx();
    c.raw_path = p.to_string();
    c
}

fn with_raw_query(q: &str) -> RequestContext {
    let mut c = base_ctx();
    c.query = Some(q.to_string());
    c
}

fn module() -> EvasionModule {
    let mut m = EvasionModule::new();
    m.init(&Config::default());
    m
}

fn severity_of(d: &Decision, rule_id: &str) -> Option<Severity> {
    match d {
        Decision::Scores(items) => items.iter().find(|i| i.rule_id == rule_id).map(|i| i.severity),
        _ => None,
    }
}

fn fires(d: &Decision, rule_id: &str) -> bool {
    severity_of(d, rule_id).is_some()
}

// ── F-1 positive: the disclosure vector ─────────────────────────────────────────

#[test]
fn double_encoded_null_byte_path_fires_critical_and_double_encoding() {
    // `%2500` double-decodes to a NUL the normalizer strips → Critical trace; the two
    // percent layers also set `double_encoding_detected` → Warning. Both fire.
    let ctx = normalized(with_raw_path("/ftp/package.json.bak%2500.md"));
    let d = module().inspect(&ctx);
    assert_eq!(severity_of(&d, "evasion-null-byte"), Some(Severity::Critical), "got: {d:?}");
    assert_eq!(severity_of(&d, "evasion-double-encoding"), Some(Severity::Warning), "got: {d:?}");
}

#[test]
fn single_encoded_null_byte_in_path_fires_null_byte_only() {
    // A single `%00` in the path is still a stripped NUL (evasion), but NOT double
    // encoded → null-byte fires, double-encoding does not.
    let ctx = normalized(with_raw_path("/etc/passwd%00.png"));
    let d = module().inspect(&ctx);
    assert!(fires(&d, "evasion-null-byte"), "got: {d:?}");
    assert!(!fires(&d, "evasion-double-encoding"), "got: {d:?}");
}

// ── Decision A: PATH-scoped → no double-count with `pt-null-byte` ────────────────

#[test]
fn null_byte_in_query_does_not_fire_evasion() {
    // `%00` in a QUERY value decodes to a NUL that SURVIVES (query is not NUL-stripped),
    // so `pt-null-byte` already covers it. The evasion flag is path-scoped → it must
    // stay silent here, otherwise the same NUL would be counted twice.
    let ctx = normalized(with_raw_query("f=%00"));
    let d = module().inspect(&ctx);
    assert!(!fires(&d, "evasion-null-byte"), "path-scoped flag leaked to query: {d:?}");
}

#[test]
fn binary_nul_in_multipart_upload_does_not_fire_null_byte() {
    // FP guard #1 (the decisive one): a legitimate binary upload carrying a real 0x00
    // in the part CONTENT must not trip the path-scoped flag. Path is clean.
    const BOUNDARY: &str = "----evasionFpGuard";
    let body = format!(
        "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.bin\"\r\n\
         Content-Type: application/octet-stream\r\n\r\nPK\x03\x04\0\0binary\r\n--{BOUNDARY}--\r\n"
    );
    let mut c = base_ctx();
    c.method = "POST".to_string();
    c.raw_path = "/upload".to_string();
    c.headers = vec![(
        "content-type".to_string(),
        format!("multipart/form-data; boundary={BOUNDARY}"),
    )];
    c.body = Bytes::from(body.into_bytes());
    let d = module().inspect(&normalized(c));
    assert!(!fires(&d, "evasion-null-byte"), "upload NUL tripped the path flag: {d:?}");
}

// ── double-encoding standalone (Warning, contributory) ───────────────────────────

#[test]
fn double_encoded_query_fires_double_encoding_warning_only() {
    // `%252e%252e` = double-encoded `..`, no NUL → Warning only, never null-byte.
    let ctx = normalized(with_raw_query("p=%252e%252e%252fetc"));
    let d = module().inspect(&ctx);
    assert_eq!(severity_of(&d, "evasion-double-encoding"), Some(Severity::Warning), "got: {d:?}");
    assert!(!fires(&d, "evasion-null-byte"), "got: {d:?}");
}

// ── benign: nothing fires ────────────────────────────────────────────────────────

#[test]
fn benign_request_is_clean() {
    let mut c = base_ctx();
    c.raw_path = "/api/v1/users".to_string();
    c.query = Some("page=2&sort=name".to_string());
    assert!(matches!(module().inspect(&normalized(c)), Decision::Allow), "benign request scored");
}
