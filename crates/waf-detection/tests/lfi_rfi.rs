// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

use waf_core::{
    Bytes, Config, Decision, LimitsConfig, ModulesConfig, Normalized, ProxyConfig,
    RequestContext, Severity, WafConfig, WafMode, WafModule,
};
use waf_normalizer::Normalizer;
use waf_pipeline::{Pipeline, PipelineVerdict};

use waf_detection::lfi_rfi::LfiRfiModule;
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
        tls: Default::default(),
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

fn make_lfi() -> LfiRfiModule {
    let mut m = LfiRfiModule::new();
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

fn normalized_query_ctx(query: &str) -> RequestContext {
    let mut c = base_ctx();
    c.query = Some(query.to_string());
    Normalizer::new(&LimitsConfig::default())
        .normalize(&mut c)
        .expect("normalization failed");
    c
}

fn normalized_cookie_ctx(cookie_header: &str) -> RequestContext {
    let mut c = base_ctx();
    c.headers = vec![("cookie".to_string(), cookie_header.to_string())];
    Normalizer::new(&LimitsConfig::default())
        .normalize(&mut c)
        .expect("normalization failed");
    c
}

// ── detection ─────────────────────────────────────────────────────────────────

#[test]
fn lfi_php_filter_chain_detected() {
    let m = make_lfi();
    let d = m.inspect(&with_query(&[("page", "php://filter/convert.base64-encode/resource=index.php")]));
    assert!(scores_contains(&d, "lfi-stream-wrapper"), "got: {d:?}");
    assert!(scores_contains(&d, "lfi-filter-chain"), "got: {d:?}");
}

#[test]
fn lfi_php_input_wrapper_detected() {
    let m = make_lfi();
    assert!(scores_contains(&m.inspect(&with_query(&[("p", "php://input")])), "lfi-stream-wrapper"));
}

#[test]
fn lfi_file_wrapper_detected() {
    let m = make_lfi();
    assert!(scores_contains(&m.inspect(&with_query(&[("p", "file:///etc/passwd")])), "lfi-stream-wrapper"));
}

#[test]
fn lfi_expect_wrapper_detected() {
    let m = make_lfi();
    assert!(scores_contains(&m.inspect(&with_query(&[("p", "expect://whoami")])), "lfi-stream-wrapper"));
}

#[test]
fn lfi_data_base64_detected() {
    let m = make_lfi();
    let d = m.inspect(&with_query(&[("p", "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==")]));
    assert!(scores_contains(&d, "lfi-stream-wrapper"), "got: {d:?}"); // data://
    assert!(scores_contains(&d, "lfi-data-base64"), "got: {d:?}");    // ;base64,
}

#[test]
fn lfi_encoded_wrapper_detected_via_normalizer() {
    // php%3a%2f%2finput -> php://input after percent-decode.
    let c = normalized_query_ctx("p=php%3a%2f%2finput");
    let m = make_lfi();
    assert!(
        scores_contains(&m.inspect(&c), "lfi-stream-wrapper"),
        "params: {:?}",
        c.normalized.query_params
    );
}

#[test]
fn lfi_encoded_wrapper_in_cookie_detected_via_normalizer() {
    // Regression for the Fase 2 cookie-decode fix: an encoded wrapper in a COOKIE
    // (php%3a%2f%2f → php://) is now canonicalized like query/body and fires.
    let c = normalized_cookie_ctx("x=php%3a%2f%2finput");
    let m = make_lfi();
    assert!(
        scores_contains(&m.inspect(&c), "lfi-stream-wrapper"),
        "cookies: {:?}",
        c.normalized.cookies
    );
}

#[test]
fn rfi_remote_script_detected() {
    let m = make_lfi();
    let d = m.inspect(&with_query(&[("page", "http://evil.example/shell.php")]));
    assert!(scores_contains(&d, "rfi-remote-script"), "got: {d:?}");
    assert!(scores_contains(&d, "rfi-remote-url"), "got: {d:?}"); // PL3 also active
}

// ── no false positives ────────────────────────────────────────────────────────

#[test]
fn lfi_no_false_positives_on_legit_input() {
    let m = make_lfi(); // PL3 — every rule active
    let legit = [
        ("page", "index.php"),          // filename, no wrapper scheme
        ("view", "home"),
        ("lang", "en_US"),
        ("file", "report.pdf"),
        ("action", "convert temperature"), // not convert.base64
        ("topic", "data analysis"),         // not data:...;base64,
        ("section", "file management"),     // not file://
        ("id", "12345"),
    ];
    for (k, v) in &legit {
        let ctx = with_query(&[(k, v)]);
        let d = m.inspect(&ctx);
        assert!(matches!(d, Decision::Allow), "false positive on {k}={v}: {d:?}");
    }
}

#[test]
fn rfi_bare_url_param_does_not_block_alone() {
    // A legit redirect/link param trips only the Notice rfi-remote-url (2),
    // below the threshold (5), so the request is not blocked.
    let mut config = base_config();
    config.waf.mode = WafMode::Blocking;
    config.waf.block_threshold = 5;
    let pipeline = Pipeline::new(&config, vec![Box::new(LfiRfiModule::new())]);

    let mut ctx = with_query(&[("next", "https://cdn.example.com/style.css")]);
    let verdict = pipeline.run(&mut ctx);
    assert!(matches!(verdict, PipelineVerdict::Allow), "bare URL must not block alone");
    assert_eq!(ctx.score, 2, "single Notice rfi-remote-url contribution expected");
}

// ── paranoia level ────────────────────────────────────────────────────────────

#[test]
fn lfi_paranoia_gates_rfi_rules() {
    let remote_script = with_query(&[("p", "https://x.example/shell.php")]);

    let mut pl1 = LfiRfiModule::new();
    pl1.init(&config_with_paranoia(1));
    // No PL1 rule matches a plain http URL (wrappers are php/file/... only).
    assert!(matches!(pl1.inspect(&remote_script), Decision::Allow), "remote script off at PL1");

    let mut pl2 = LfiRfiModule::new();
    pl2.init(&config_with_paranoia(2));
    assert!(scores_contains(&pl2.inspect(&remote_script), "rfi-remote-script"), "on at PL2");
    assert!(!scores_contains(&pl2.inspect(&remote_script), "rfi-remote-url"), "bare-url still off at PL2");

    let mut pl3 = LfiRfiModule::new();
    pl3.init(&config_with_paranoia(3));
    assert!(scores_contains(&pl3.inspect(&remote_script), "rfi-remote-url"), "bare-url on at PL3");
}

#[test]
fn lfi_wrappers_active_at_pl1() {
    let mut pl1 = LfiRfiModule::new();
    pl1.init(&config_with_paranoia(1));
    assert!(scores_contains(&pl1.inspect(&with_query(&[("p", "php://input")])), "lfi-stream-wrapper"));
}

// ── init behavior ─────────────────────────────────────────────────────────────

#[test]
fn lfi_returns_allow_before_init() {
    let m = LfiRfiModule::new();
    assert!(matches!(m.inspect(&with_query(&[("p", "php://input")])), Decision::Allow));
}

#[test]
fn lfi_emits_critical_severity_for_wrapper() {
    let m = make_lfi();
    match m.inspect(&with_query(&[("p", "php://input")])) {
        Decision::Scores(items) => {
            let it = items.iter().find(|i| i.rule_id == "lfi-stream-wrapper").unwrap();
            assert_eq!(it.severity, Severity::Critical);
        }
        other => panic!("expected Scores, got {other:?}"),
    }
}

// ── pipeline integration / cumulative scoring ──────────────────────────────────

#[test]
fn lfi_contributes_to_cumulative_score_with_sqli() {
    let config = base_config(); // DetectionOnly runs every module

    let modules: Vec<Box<dyn WafModule>> = vec![
        Box::new(SqliModule::new()),
        Box::new(LfiRfiModule::new()),
    ];
    let pipeline = Pipeline::new(&config, modules);

    // SQLi union-select + php:// wrapper in two params.
    let mut ctx = with_query(&[
        ("q", "1 UNION SELECT 1,2"),
        ("page", "php://filter/convert.base64-encode/resource=x"),
    ]);
    let verdict = pipeline.run(&mut ctx);

    assert!(matches!(verdict, PipelineVerdict::Allow)); // detection-only
    assert!(ctx.score_contributions.iter().any(|c| c.module == "sqli"));
    assert!(ctx.score_contributions.iter().any(|c| c.module == "lfi_rfi"));
}

#[test]
fn lfi_blocks_in_blocking_mode() {
    let mut config = base_config();
    config.waf.mode = WafMode::Blocking;
    config.waf.block_threshold = 5;
    let pipeline = Pipeline::new(&config, vec![Box::new(LfiRfiModule::new())]);
    // wrapper (5) + filter-chain (5) = 10 >= 5
    let mut ctx = with_query(&[("p", "php://filter/convert.base64-encode/resource=index.php")]);
    assert!(matches!(pipeline.run(&mut ctx), PipelineVerdict::Block { .. }));
}
