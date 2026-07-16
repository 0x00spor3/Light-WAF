// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

//! SSTI module — F-2 ERB/EJS/JSP arithmetic rule + its FP guards (2026-07-16).

use waf_core::{Bytes, Config, Decision, Normalized, RequestContext, Severity, WafModule};
use waf_detection::ssti::SstiModule;

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

fn with_query(name: &str, value: &str) -> RequestContext {
    let mut c = base_ctx();
    c.normalized.query_params = vec![(name.to_string(), value.to_string())];
    c
}

fn module() -> SstiModule {
    let mut m = SstiModule::new();
    m.init(&Config::default()); // PL defaults; ERB rule is paranoia 1
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

// ── positives ────────────────────────────────────────────────────────────────

#[test]
fn erb_expression_arithmetic_fires_critical() {
    let d = module().inspect(&with_query("q", "<%=7*7%>"));
    assert_eq!(severity_of(&d, "ssti-erb-jsp-arithmetic"), Some(Severity::Critical), "got: {d:?}");
}

#[test]
fn erb_scriptlet_with_spaces_fires() {
    let d = module().inspect(&with_query("q", "aaa<% 16 * 8787 %>bbb"));
    assert!(fires(&d, "ssti-erb-jsp-arithmetic"), "got: {d:?}");
}

#[test]
fn erb_trim_form_fires() {
    let d = module().inspect(&with_query("q", "<%- 2*2 -%>"));
    assert!(fires(&d, "ssti-erb-jsp-arithmetic"), "got: {d:?}");
}

// ── FP guards (must stay clean) ──────────────────────────────────────────────

#[test]
fn erb_comment_does_not_fire() {
    // `<%--` — a `-` follows `<%`, no adjacent digit-op-digit.
    let d = module().inspect(&with_query("tpl", "<%-- build 2024 rev 7 --%>"));
    assert!(!fires(&d, "ssti-erb-jsp-arithmetic"), "false positive on ERB comment: {d:?}");
}

#[test]
fn erb_template_var_does_not_fire() {
    let d = module().inspect(&with_query("tpl", "<%= user.name %>"));
    assert!(!fires(&d, "ssti-erb-jsp-arithmetic"), "false positive on ERB output tag: {d:?}");
}

#[test]
fn html_percent_prose_does_not_fire() {
    // A technical snippet that mentions percentages but is not a template delimiter.
    let d = module().inspect(&with_query("note", "discount was 7% then 7 off"));
    assert!(!fires(&d, "ssti-erb-jsp-arithmetic"), "false positive on prose: {d:?}");
}
