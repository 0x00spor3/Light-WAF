// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

//! NoSQL module — G-3 operator-in-key detection + FP guards (pentest #2, 2026-07-16).

use waf_core::{
    Bytes, Config, Decision, Normalized, ParsedBody, RequestContext, Severity, WafModule,
};
use waf_detection::nosql::NosqlModule;

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

fn module() -> NosqlModule {
    let mut m = NosqlModule::new();
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

fn with_query_name(name: &str) -> RequestContext {
    let mut c = base_ctx();
    c.normalized.query_params = vec![(name.to_string(), "null".to_string())];
    c
}
fn with_json_keys(pairs: &[(&str, &str)]) -> RequestContext {
    let mut c = base_ctx();
    c.normalized.body = ParsedBody::JsonFlattened(
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
    );
    c
}

// ── G-3 positives ────────────────────────────────────────────────────────────────

#[test]
fn operator_in_query_param_name_fires_critical() {
    // `?q[$ne]=null` → param NAME carries the operator (value channel never sees it).
    let d = module().inspect(&with_query_name("q[$ne]"));
    assert_eq!(severity_of(&d, "nosql-operator-key"), Some(Severity::Critical), "got: {d:?}");
}

#[test]
fn operator_in_json_key_fires_critical() {
    // `{"email":{"$gt":""}}` flattens to a key carrying `$gt` — auth-bypass on Mongo.
    let d = module().inspect(&with_json_keys(&[("email.$gt", ""), ("password.$gt", "")]));
    assert!(fires(&d, "nosql-operator-key"), "got: {d:?}");
}

#[test]
fn operator_in_form_key_fires() {
    let mut c = base_ctx();
    c.normalized.body = ParsedBody::FormUrlEncoded(vec![("user[$ne]".to_string(), "x".to_string())]);
    assert!(fires(&module().inspect(&c), "nosql-operator-key"), "form key operator");
}

#[test]
fn emitted_once_across_multiple_keys() {
    let d = module().inspect(&with_json_keys(&[("a.$gt", ""), ("b.$ne", ""), ("c.$in", "")]));
    if let Decision::Scores(items) = &d {
        let n = items.iter().filter(|i| i.rule_id == "nosql-operator-key").count();
        assert_eq!(n, 1, "must emit once: {items:?}");
    } else {
        panic!("expected Scores, got {d:?}");
    }
}

// ── G-3 FP guards ────────────────────────────────────────────────────────────────

#[test]
fn json_schema_dollar_keys_are_clean() {
    // JSON-Schema documents legitimately use `$ref`/`$id`/`$schema`/`$defs`/`$comment`.
    let d = module().inspect(&with_json_keys(&[
        ("$schema", "https://json-schema.org/draft/2020-12/schema"),
        ("$ref", "#/definitions/x"),
        ("$id", "urn:x"),
        ("$comment", "note"),
    ]));
    assert!(!fires(&d, "nosql-operator-key"), "false positive on JSON-Schema keys: {d:?}");
}

#[test]
fn currency_and_normal_names_are_clean() {
    assert!(!fires(&module().inspect(&with_query_name("price")), "nosql-operator-key"));
    assert!(!fires(&module().inspect(&with_json_keys(&[("total", "$100")])), "nosql-operator-key"));
    // `$gt` as a VALUE (not a key) must not raise the KEY-position Critical.
    assert!(!fires(&module().inspect(&with_json_keys(&[("note", "3 $gt 2")])), "nosql-operator-key"));
}
