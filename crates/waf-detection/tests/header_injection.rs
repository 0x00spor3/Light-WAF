use waf_core::{
    Bytes, Config, Decision, LimitsConfig, ModulesConfig, Normalized, ParsedBody, ProxyConfig,
    RequestContext, Severity, WafConfig, WafMode, WafModule,
};
use waf_normalizer::Normalizer;
use waf_pipeline::{Pipeline, PipelineVerdict};

use waf_detection::header_injection::HeaderInjectionModule;
use waf_detection::sqli::SqliModule;

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
    }
}

fn scores_contains(d: &Decision, rule_id: &str) -> bool {
    matches!(d, Decision::Scores(items) if items.iter().any(|i| i.rule_id == rule_id))
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

fn make_hdr() -> HeaderInjectionModule {
    let mut m = HeaderInjectionModule::new();
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

fn with_headers(headers: &[(&str, &str)]) -> RequestContext {
    let mut c = base_ctx();
    c.normalized.headers = headers
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    c
}

fn normalized_query_ctx(query: &str) -> RequestContext {
    let mut c = base_ctx();
    c.query = Some(query.to_string());
    Normalizer::new(&LimitsConfig::default())
        .normalize(&mut c)
        .expect("normalization failed");
    c
}

// ── detection ─────────────────────────────────────────────────────────────────

#[test]
fn hdr_crlf_set_cookie_injection_detected_via_normalizer() {
    // %0d%0a -> CRLF; then "Set-Cookie:" — classic response splitting.
    let c = normalized_query_ctx("x=foo%0d%0aSet-Cookie:%20sid=evil");
    let m = make_hdr();
    assert!(
        scores_contains(&m.inspect(&c), "hdr-crlf-header-injection"),
        "params: {:?}",
        c.normalized.query_params
    );
}

#[test]
fn hdr_crlf_location_injection_detected() {
    // Location: is a primary response-splitting target — must match.
    let c = normalized_query_ctx("next=%0d%0aLocation:%20http://evil");
    let m = make_hdr();
    assert!(scores_contains(&m.inspect(&c), "hdr-crlf-header-injection"));
}

#[test]
fn hdr_crlf_injection_in_form_body_detected() {
    let m = make_hdr();
    let ctx = with_form_body(&[("comment", "hi\r\nSet-Cookie: admin=1")]);
    assert!(scores_contains(&m.inspect(&ctx), "hdr-crlf-header-injection"));
}

#[test]
fn hdr_bare_crlf_in_query_is_control_char_only_not_critical() {
    // a\r\nb has a bare CRLF but NO header token after it: only the PL2
    // control-char rule fires, NOT the Critical header-injection rule.
    let c = normalized_query_ctx("x=a%0d%0ab");
    let m = make_hdr();
    let d = m.inspect(&c);
    assert!(scores_contains(&d, "hdr-crlf-control-char"), "got: {d:?}");
    assert!(!scores_contains(&d, "hdr-crlf-header-injection"), "must not be Critical: {d:?}");
}

#[test]
fn hdr_host_injection_absolute_uri_detected() {
    let m = make_hdr();
    assert!(scores_contains(&m.inspect(&with_headers(&[("host", "http://evil.com")])), "hdr-host-injection"));
    assert!(scores_contains(&m.inspect(&with_headers(&[("host", "victim.com@evil.com")])), "hdr-host-injection"));
    assert!(scores_contains(
        &m.inspect(&with_headers(&[("x-forwarded-host", "evil.com/path")])),
        "hdr-host-injection"
    ));
}

#[test]
fn hdr_defense_in_depth_header_value_crlf() {
    // hyper normally rejects CR/LF in header values at parse time; if such a
    // value ever reaches us, the All-scope rule still catches it.
    let m = make_hdr();
    let ctx = with_headers(&[("x-custom", "v\r\nSet-Cookie: x=1")]);
    assert!(scores_contains(&m.inspect(&ctx), "hdr-crlf-header-injection"));
}

// ── no false positives ────────────────────────────────────────────────────────

#[test]
fn hdr_no_false_positives_on_legit_input() {
    let m = make_hdr(); // PL3 — every rule active
    // Legit headers, query and host values without CRLF / absolute-URI host.
    let ctx_headers = with_headers(&[
        ("host", "example.com:443"),
        ("host", "[2001:db8::1]:8080"),     // full IPv6 host — must NOT trip host-injection
        ("user-agent", "Mozilla/5.0 (X11; Linux)"),
        ("accept", "text/html,application/json"),
        ("referer", "https://example.com/page"), // referer is not a host header
    ]);
    assert!(matches!(m.inspect(&ctx_headers), Decision::Allow), "host/header FP: {:?}", m.inspect(&ctx_headers));

    let ctx_query = with_query(&[
        ("q", "hello world"),
        ("name", "Alice Smith"),
        ("url", "https://example.com/a/b"),
    ]);
    assert!(matches!(m.inspect(&ctx_query), Decision::Allow));
}

#[test]
fn hdr_multiline_textarea_body_safe_below_pl3_and_non_blocking_at_pl3() {
    // A legit multiline textarea (CRLF in body) must NOT fire at PL1/PL2, and at
    // PL3 trips only the Notice rule (2) — never blocking on its own.
    let body = with_form_body(&[("message", "line one\r\nline two\r\nregards")]);

    let mut pl2 = HeaderInjectionModule::new();
    pl2.init(&config_with_paranoia(2));
    assert!(matches!(pl2.inspect(&body), Decision::Allow), "textarea must be safe at PL2");

    // At PL3, score it but verify it does not block alone through the pipeline.
    let mut config = config_with_paranoia(3);
    config.waf.mode = WafMode::Blocking;
    config.waf.block_threshold = 5;
    let pipeline = Pipeline::new(&config, vec![Box::new(HeaderInjectionModule::new())]);
    let mut ctx = with_form_body(&[("message", "line one\r\nline two\r\nregards")]);
    let verdict = pipeline.run(&mut ctx);
    assert!(matches!(verdict, PipelineVerdict::Allow), "textarea Notice must not block alone");
    assert_eq!(ctx.score, 2);
}

// ── paranoia level ────────────────────────────────────────────────────────────

#[test]
fn hdr_paranoia_gates_control_char_host_and_body() {
    let bare_crlf_query = normalized_query_ctx("x=a%0d%0ab");
    let host = with_headers(&[("host", "http://evil.com")]);
    let crlf_body = with_form_body(&[("m", "a\r\nb")]);

    let mut pl1 = HeaderInjectionModule::new();
    pl1.init(&config_with_paranoia(1));
    assert!(matches!(pl1.inspect(&bare_crlf_query), Decision::Allow), "control-char off at PL1");
    assert!(matches!(pl1.inspect(&host), Decision::Allow), "host-injection off at PL1");
    assert!(matches!(pl1.inspect(&crlf_body), Decision::Allow), "crlf-in-body off at PL1");

    let mut pl2 = HeaderInjectionModule::new();
    pl2.init(&config_with_paranoia(2));
    assert!(scores_contains(&pl2.inspect(&bare_crlf_query), "hdr-crlf-control-char"), "control-char on at PL2");
    assert!(scores_contains(&pl2.inspect(&host), "hdr-host-injection"), "host-injection on at PL2");
    assert!(matches!(pl2.inspect(&crlf_body), Decision::Allow), "crlf-in-body still off at PL2");

    let mut pl3 = HeaderInjectionModule::new();
    pl3.init(&config_with_paranoia(3));
    assert!(scores_contains(&pl3.inspect(&crlf_body), "hdr-crlf-in-body"), "crlf-in-body on at PL3");
}

#[test]
fn hdr_header_injection_active_at_pl1() {
    let mut pl1 = HeaderInjectionModule::new();
    pl1.init(&config_with_paranoia(1));
    let c = normalized_query_ctx("x=%0d%0aSet-Cookie:%20a=b");
    assert!(scores_contains(&pl1.inspect(&c), "hdr-crlf-header-injection"));
}

// ── init behavior ─────────────────────────────────────────────────────────────

#[test]
fn hdr_returns_allow_before_init() {
    let m = HeaderInjectionModule::new();
    let c = normalized_query_ctx("x=%0d%0aSet-Cookie:%20a=b");
    assert!(matches!(m.inspect(&c), Decision::Allow));
}

#[test]
fn hdr_emits_critical_severity_for_header_injection() {
    let m = make_hdr();
    let c = normalized_query_ctx("x=%0d%0aSet-Cookie:%20a=b");
    match m.inspect(&c) {
        Decision::Scores(items) => {
            let it = items.iter().find(|i| i.rule_id == "hdr-crlf-header-injection").unwrap();
            assert_eq!(it.severity, Severity::Critical);
        }
        other => panic!("expected Scores, got {other:?}"),
    }
}

// ── pipeline integration / cumulative scoring ──────────────────────────────────

#[test]
fn hdr_contributes_to_cumulative_score_with_sqli() {
    let config = base_config(); // DetectionOnly runs every module
    let modules: Vec<Box<dyn WafModule>> = vec![
        Box::new(SqliModule::new()),
        Box::new(HeaderInjectionModule::new()),
    ];
    let pipeline = Pipeline::new(&config, modules);

    let mut ctx = with_query(&[
        ("q", "1 UNION SELECT 1,2"),
        ("x", "foo\r\nSet-Cookie: a=b"),
    ]);
    let verdict = pipeline.run(&mut ctx);

    assert!(matches!(verdict, PipelineVerdict::Allow)); // detection-only
    assert!(ctx.score_contributions.iter().any(|c| c.module == "sqli"));
    assert!(ctx.score_contributions.iter().any(|c| c.module == "header_injection"));
}

#[test]
fn hdr_blocks_in_blocking_mode() {
    let mut config = base_config();
    config.waf.mode = WafMode::Blocking;
    config.waf.block_threshold = 5;
    let pipeline = Pipeline::new(&config, vec![Box::new(HeaderInjectionModule::new())]);
    let mut ctx = with_query(&[("x", "foo\r\nSet-Cookie: sid=evil")]); // Critical 5
    assert!(matches!(pipeline.run(&mut ctx), PipelineVerdict::Block { .. }));
}
