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

// ── E-4: prototype pollution in KEY position (EXTREME follow-on) ──────────────────

#[test]
fn proto_pollution_underscore_key_fires_critical() {
    // `{"__proto__":{"isAdmin":true}}` flattens to key `__proto__.isAdmin`.
    let d = module().inspect(&with_json_keys(&[("__proto__.isAdmin", "true")]));
    assert_eq!(severity_of(&d, "proto-pollution-key"), Some(Severity::Critical), "got: {d:?}");
}

#[test]
fn proto_pollution_constructor_prototype_key_fires() {
    // `{"constructor":{"prototype":{"polluted":"x"}}}` → key `constructor.prototype.polluted`.
    let d = module().inspect(&with_json_keys(&[("constructor.prototype.polluted", "x")]));
    assert!(fires(&d, "proto-pollution-key"), "got: {d:?}");
}

#[test]
fn proto_pollution_form_bracket_key_fires() {
    let mut c = base_ctx();
    c.normalized.body = ParsedBody::FormUrlEncoded(vec![("__proto__[isAdmin]".to_string(), "true".to_string())]);
    assert!(fires(&module().inspect(&c), "proto-pollution-key"), "form __proto__ bracket key");
}

#[test]
fn proto_pollution_emitted_once() {
    let d = module().inspect(&with_json_keys(&[("__proto__.a", "1"), ("__proto__.b", "2")]));
    if let Decision::Scores(items) = &d {
        let n = items.iter().filter(|i| i.rule_id == "proto-pollution-key").count();
        assert_eq!(n, 1, "must emit once: {items:?}");
    } else {
        panic!("expected Scores, got {d:?}");
    }
}

#[test]
fn proto_pollution_fp_guards_stay_clean() {
    // Legit field names that merely contain the words — not the pollution segments.
    assert!(!fires(&module().inspect(&with_json_keys(&[("constructorName", "Acme")])), "proto-pollution-key"));
    assert!(!fires(&module().inspect(&with_json_keys(&[("prototype", "v2")])), "proto-pollution-key"));
    assert!(!fires(&module().inspect(&with_json_keys(&[("constructor", "Acme")])), "proto-pollution-key"));
    // `__proto__` as a VALUE (key is benign) must not raise the KEY-position Critical.
    assert!(!fires(&module().inspect(&with_json_keys(&[("note", "about obj.__proto__.x pollution")])), "proto-pollution-key"));
}
