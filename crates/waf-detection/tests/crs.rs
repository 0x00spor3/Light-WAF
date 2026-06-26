// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

//! End-to-end evaluator tests for the CRS import module: operators, the `t:` pipeline on
//! the RAW request (paletto #1 — including the double-decode control), targets, chains and
//! the fast/slow split. The module reads raw `RequestContext` fields, NOT the §6 surface,
//! so these build the context directly (no normalizer involved).

use waf_core::{Bytes, Decision, Normalized, RequestContext, Severity, WafModule};
use waf_detection::crs::CrsModule;

// ── helpers ───────────────────────────────────────────────────────────────────

fn ctx() -> RequestContext {
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

fn with_query(q: &str) -> RequestContext {
    let mut c = ctx();
    c.query = Some(q.to_string());
    c
}

fn fired(d: &Decision, rule_id: &str) -> bool {
    matches!(d, Decision::Scores(items) if items.iter().any(|i| i.rule_id == rule_id))
}

fn is_allow(d: &Decision) -> bool {
    matches!(d, Decision::Allow)
}

// ── basic matching ──────────────────────────────────────────────────────────────

#[test]
fn rx_on_args_matches_query() {
    let m = CrsModule::from_source(r#"SecRule ARGS "@rx (?i)union\s+select" "id:1,phase:2,severity:CRITICAL""#);
    let d = m.inspect(&with_query("q=UNION%20SELECT"));
    assert!(fired(&d, "crs-1"), "{d:?}");
    if let Decision::Scores(items) = &d {
        assert_eq!(items[0].severity, Severity::Critical);
    }
}

#[test]
fn no_match_is_allow() {
    let m = CrsModule::from_source(r#"SecRule ARGS "@rx evil" "id:1,phase:2""#);
    assert!(is_allow(&m.inspect(&with_query("q=hello"))));
}

// ── paletto #1: t: pipeline runs on the RAW value, single-decode baseline ─────────

#[test]
fn implicit_single_url_decode_of_args() {
    // ARGS get ModSec's implicit single decode → `%75nion` becomes `union` with NO t:.
    let m = CrsModule::from_source(r#"SecRule ARGS "@rx union" "id:1,phase:2""#);
    assert!(fired(&m.inspect(&with_query("q=%75nion")), "crs-1"));
}

#[test]
fn double_decode_control_requires_declared_transform() {
    // `%2575nion`: implicit single decode → `%75nion`. The rule WITHOUT t:urlDecode must
    // NOT match `union` (we do not pre-canonicalize like §6); WITH t:urlDecode it decodes
    // the second level and matches. This is the paletto #1 invariant, both directions.
    let without = CrsModule::from_source(r#"SecRule ARGS "@rx ^union$" "id:1,phase:2""#);
    assert!(is_allow(&without.inspect(&with_query("q=%2575nion"))), "must not double-decode");

    let with = CrsModule::from_source(r#"SecRule ARGS "@rx ^union$" "id:2,phase:2,t:urlDecode""#);
    assert!(fired(&with.inspect(&with_query("q=%2575nion")), "crs-2"), "t:urlDecode should reach `union`");
}

#[test]
fn lowercase_transform() {
    let m = CrsModule::from_source(r#"SecRule ARGS "@rx ^union$" "id:1,phase:2,t:lowercase""#);
    assert!(fired(&m.inspect(&with_query("q=UNION")), "crs-1"));
}

// ── targets ─────────────────────────────────────────────────────────────────────

#[test]
fn header_target_with_selector() {
    let m = CrsModule::from_source(r#"SecRule REQUEST_HEADERS:User-Agent "@rx (?i)sqlmap" "id:1,phase:2""#);
    let mut c = ctx();
    c.headers = vec![("User-Agent".to_string(), "sqlmap/1.0".to_string())];
    assert!(fired(&m.inspect(&c), "crs-1"));
}

#[test]
fn cookie_target_url_decoded() {
    let m = CrsModule::from_source(r#"SecRule REQUEST_COOKIES "@rx ../etc" "id:1,phase:2""#);
    let mut c = ctx();
    c.cookies = vec![("sid".to_string(), "..%2fetc".to_string())];
    assert!(fired(&m.inspect(&c), "crs-1"));
}

#[test]
fn request_uri_target() {
    let m = CrsModule::from_source(r#"SecRule REQUEST_URI "@rx (?i)/admin" "id:1,phase:2""#);
    let mut c = ctx();
    c.path = "/Admin/login".to_string();
    assert!(fired(&m.inspect(&c), "crs-1"));
}

#[test]
fn args_names_target() {
    let m = CrsModule::from_source(r#"SecRule ARGS_NAMES "@rx (?i)^cmd$" "id:1,phase:2""#);
    assert!(fired(&m.inspect(&with_query("cmd=ls")), "crs-1"));
    // The VALUE `cmd` is in ARGS, not ARGS_NAMES → a rule on ARGS_NAMES sees the NAME.
    assert!(is_allow(&m.inspect(&with_query("x=cmd"))));
}

#[test]
fn exclusion_drops_named_arg() {
    let m = CrsModule::from_source(r#"SecRule ARGS|!ARGS:safe "@rx evil" "id:1,phase:2""#);
    // `evil` only in the excluded `safe` arg → no match.
    assert!(is_allow(&m.inspect(&with_query("safe=evil"))));
    // `evil` in another arg → matches.
    assert!(fired(&m.inspect(&with_query("x=evil")), "crs-1"));
}

// ── chains ──────────────────────────────────────────────────────────────────────

#[test]
fn chain_requires_all_links() {
    let src = r#"
SecRule REQUEST_METHOD "@streq POST" "id:1,phase:2,chain,severity:ERROR"
    SecRule ARGS "@rx (?i)evil" "t:lowercase"
"#;
    let m = CrsModule::from_source(src);
    // GET with evil arg → head (method POST) fails → no fire.
    assert!(is_allow(&m.inspect(&with_query("x=EVIL"))));
    // POST with evil arg → both links match.
    let mut c = with_query("x=EVIL");
    c.method = "POST".to_string();
    assert!(fired(&m.inspect(&c), "crs-1"));
}

// ── operators ───────────────────────────────────────────────────────────────────

#[test]
fn pm_operator_any_phrase_case_insensitive() {
    let m = CrsModule::from_source(r#"SecRule ARGS "@pm wget curl nc" "id:1,phase:2""#);
    assert!(fired(&m.inspect(&with_query("c=CURL http://x")), "crs-1"));
    assert!(is_allow(&m.inspect(&with_query("c=hello"))));
}

#[test]
fn streq_and_contains() {
    let m = CrsModule::from_source(r#"SecRule REQUEST_METHOD "@streq TRACE" "id:1,phase:2""#);
    let mut c = ctx();
    c.method = "TRACE".to_string();
    assert!(fired(&m.inspect(&c), "crs-1"));
}

// ── fast/slow split + multiple matches ────────────────────────────────────────────

#[test]
fn two_fast_rules_same_bucket_both_fire() {
    // Same (vars, t:) → one bucket / one RegexSet pass → both rules reported.
    let src = r#"
SecRule ARGS "@rx union" "id:1,phase:2,severity:CRITICAL"
SecRule ARGS "@rx select" "id:2,phase:2,severity:WARNING"
"#;
    let m = CrsModule::from_source(src);
    let d = m.inspect(&with_query("q=union select"));
    assert!(fired(&d, "crs-1"));
    assert!(fired(&d, "crs-2"));
}

// ── skip reporting (D3=A) ─────────────────────────────────────────────────────────

#[test]
fn unsupported_rules_are_skipped_and_counted() {
    let src = r#"
SecRule ARGS "@rx ok" "id:1,phase:2"
SecRule ARGS "@detectSQLi" "id:2,phase:2"
SecRule REQUEST_BODY "@rx x" "id:3,phase:4"
"#;
    let m = CrsModule::from_source(src);
    assert_eq!(m.loaded_count(), 1);
    assert_eq!(m.skipped().len(), 2);
    assert!(m.report().contains("1 rules loaded"));
    assert!(m.report().contains("2 skipped"));
}

#[test]
fn invalid_regex_is_skipped_not_panicked() {
    let m = CrsModule::from_source(r#"SecRule ARGS "@rx (unclosed" "id:1,phase:2""#);
    assert_eq!(m.loaded_count(), 0);
    assert_eq!(m.skipped().len(), 1);
    assert!(m.skipped()[0].reason.contains("invalid @rx"));
}

// ── module contract ──────────────────────────────────────────────────────────────

#[test]
fn module_is_structural() {
    // Must run even when the native content fast-path would skip (paletto #2).
    let m = CrsModule::from_source(r#"SecRule ARGS "@rx x" "id:1,phase:2""#);
    assert!(m.structural());
    assert_eq!(m.id(), "crs");
}
