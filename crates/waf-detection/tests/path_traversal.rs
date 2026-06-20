use waf_core::{
    Bytes, Config, Decision, LimitsConfig, ModulesConfig, Normalized, ProxyConfig,
    RequestContext, Severity, WafConfig, WafMode, WafModule,
};
use waf_normalizer::Normalizer;
use waf_pipeline::{Pipeline, PipelineVerdict};

use waf_detection::path_traversal::PathTraversalModule;
use waf_detection::sqli::SqliModule;
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

fn make_pt() -> PathTraversalModule {
    let mut m = PathTraversalModule::new();
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

/// Run the real normalizer over a raw path + query, returning the populated ctx.
fn normalized_ctx(raw_path: &str, query: Option<&str>) -> RequestContext {
    let mut c = base_ctx();
    c.raw_path = raw_path.to_string();
    c.query = query.map(str::to_string);
    Normalizer::new(&LimitsConfig::default())
        .normalize(&mut c)
        .expect("normalization failed");
    c
}

// ── detection ─────────────────────────────────────────────────────────────────

#[test]
fn pt_dotdot_and_target_detected_in_query() {
    let m = make_pt();
    let d = m.inspect(&with_query(&[("file", "../../etc/passwd")]));
    assert!(scores_contains(&d, "pt-dotdot-traversal"), "got: {d:?}");
    assert!(scores_contains(&d, "pt-sensitive-unix"), "got: {d:?}");
}

#[test]
fn pt_encoded_traversal_detected_via_normalizer() {
    // %2e%2e%2f -> ../ after percent-decode; target stays /etc/passwd.
    let c = normalized_ctx("/", Some("file=%2e%2e%2f%2e%2e%2fetc%2fpasswd"));
    let m = make_pt();
    let d = m.inspect(&c);
    assert!(
        scores_contains(&d, "pt-dotdot-traversal"),
        "params: {:?}, got: {d:?}",
        c.normalized.query_params
    );
    assert!(scores_contains(&d, "pt-sensitive-unix"), "got: {d:?}");
}

#[test]
fn pt_double_encoded_traversal_detected_via_normalizer() {
    // %252e%252e%252f -> %2e%2e%2f -> ../ after the normalizer's second pass.
    // A SINGLE resolved `../` no longer trips pt-dotdot-traversal (which now
    // requires `{2,}` consecutive segments, 10b-cont) — the double-decode is
    // still proven caught via the sensitive target `/etc/passwd` it reaches.
    let c = normalized_ctx("/", Some("p=%252e%252e%252fetc%252fpasswd"));
    assert!(c.normalized.double_encoding_detected, "expected double-encoding flag");
    let m = make_pt();
    assert!(
        scores_contains(&m.inspect(&c), "pt-sensitive-unix"),
        "params: {:?}",
        c.normalized.query_params
    );
}

#[test]
fn pt_backslash_windows_target_detected() {
    let m = make_pt();
    let d = m.inspect(&with_query(&[("f", r"..\..\windows\win.ini")]));
    assert!(scores_contains(&d, "pt-dotdot-traversal"), "got: {d:?}");
    assert!(scores_contains(&d, "pt-sensitive-windows"), "got: {d:?}");
}

#[test]
fn pt_target_in_resolved_path_detected_but_not_dotdot() {
    // The normalizer resolves `..`, so the path traversal sequence is gone from
    // normalized.path, but the sensitive target /etc/passwd remains.
    let c = normalized_ctx("/app/../../etc/passwd", None);
    assert_eq!(c.normalized.path, "/etc/passwd");
    let m = make_pt();
    let d = m.inspect(&c);
    assert!(scores_contains(&d, "pt-sensitive-unix"), "got: {d:?}");
    assert!(!scores_contains(&d, "pt-dotdot-traversal"), "resolved path must not match dotdot: {d:?}");
}

#[test]
fn pt_null_byte_detected_in_query_via_normalizer() {
    // %00 is decoded to a real NUL byte in query values (unlike the path).
    let c = normalized_ctx("/", Some("file=image.jpg%00.php"));
    let m = make_pt();
    assert!(
        scores_contains(&m.inspect(&c), "pt-null-byte"),
        "params: {:?}",
        c.normalized.query_params
    );
}

#[test]
fn pt_unc_path_detected() {
    let m = make_pt();
    let d = m.inspect(&with_query(&[("share", r"\\fileserver\secret\data")]));
    assert!(scores_contains(&d, "pt-unc-path"), "got: {d:?}");
}

// ── no false positives ────────────────────────────────────────────────────────

#[test]
fn pt_no_false_positives_on_legit_input() {
    let m = make_pt();
    let legit = [
        ("path", "/api/v1/users"),
        ("file", "report.pdf"),
        ("dir", "/home/user/docs"),
        ("version", "1.2.3"),
        ("theme", "system32_dark"),   // anchored system32 rule must not fire
        ("note", "a..b"),             // dots without a separator
        ("q", "etcetera passwords"),  // "etc"/"passwd" substrings, no /etc/passwd
        ("name", "windows update"),   // "windows" without separators
    ];
    for (k, v) in &legit {
        let ctx = with_query(&[(k, v)]);
        let d = m.inspect(&ctx);
        assert!(matches!(d, Decision::Allow), "false positive on {k}={v}: {d:?}");
    }
}

// ── paranoia level ────────────────────────────────────────────────────────────

#[test]
fn pt_paranoia_gates_null_byte_and_unc() {
    // null-byte is PL2, unc is PL3 — neither active at PL1.
    let null_ctx = normalized_ctx("/", Some("file=x%00y"));
    let unc_ctx = with_query(&[("s", r"\\srv\share")]);

    let mut pl1 = PathTraversalModule::new();
    pl1.init(&config_with_paranoia(1));
    assert!(matches!(pl1.inspect(&null_ctx), Decision::Allow), "null-byte must be off at PL1");
    assert!(matches!(pl1.inspect(&unc_ctx), Decision::Allow), "unc must be off at PL1");

    let mut pl2 = PathTraversalModule::new();
    pl2.init(&config_with_paranoia(2));
    assert!(scores_contains(&pl2.inspect(&null_ctx), "pt-null-byte"), "null-byte must be on at PL2");
    assert!(matches!(pl2.inspect(&unc_ctx), Decision::Allow), "unc must still be off at PL2");

    let mut pl3 = PathTraversalModule::new();
    pl3.init(&config_with_paranoia(3));
    assert!(scores_contains(&pl3.inspect(&unc_ctx), "pt-unc-path"), "unc must be on at PL3");
}

#[test]
fn pt_high_confidence_rules_active_at_pl1() {
    let mut pl1 = PathTraversalModule::new();
    pl1.init(&config_with_paranoia(1));
    assert!(scores_contains(
        &pl1.inspect(&with_query(&[("f", "../../etc/passwd")])),
        "pt-dotdot-traversal"
    ));
}

// ── init behavior ─────────────────────────────────────────────────────────────

#[test]
fn pt_returns_allow_before_init() {
    let m = PathTraversalModule::new();
    assert!(matches!(m.inspect(&with_query(&[("f", "../../etc/passwd")])), Decision::Allow));
}

// ── pipeline integration / cumulative scoring ──────────────────────────────────

#[test]
fn pt_contributes_to_cumulative_score_with_sqli() {
    // A single query value that trips both SQLi (stacked query) and path
    // traversal (sequence + unix target). Detection-only runs every module
    // (no threshold short-circuit), so contributions from both accumulate.
    // NB: path_traversal (RequestLine) runs before SQLi (Body); in blocking
    // mode the threshold would short-circuit before SQLi — covered separately.
    let config = base_config(); // DetectionOnly, threshold 5

    let modules: Vec<Box<dyn WafModule>> = vec![
        Box::new(SqliModule::new()),
        Box::new(XssModule::new()),
        Box::new(PathTraversalModule::new()),
    ];
    let pipeline = Pipeline::new(&config, modules);

    let mut ctx = with_query(&[("p", "1; DROP TABLE users; ../../etc/passwd")]);
    let verdict = pipeline.run(&mut ctx);

    assert!(matches!(verdict, PipelineVerdict::Allow)); // detection-only
    // critical=5 each: sqli-stacked + pt-dotdot + pt-unix -> >= 15
    assert!(ctx.score >= 15, "score was {}", ctx.score);
    assert!(ctx.score_contributions.iter().any(|c| c.module == "sqli"));
    assert!(ctx.score_contributions.iter().any(|c| c.module == "path_traversal"));
}

#[test]
fn pt_blocks_in_blocking_mode() {
    let mut config = base_config();
    config.waf.mode = WafMode::Blocking;
    config.waf.block_threshold = 5;
    let pipeline = Pipeline::new(&config, vec![Box::new(PathTraversalModule::new())]);
    // dotdot (5) + unix (5) = 10 >= 5
    let mut ctx = with_query(&[("f", "../../etc/passwd")]);
    assert!(matches!(pipeline.run(&mut ctx), PipelineVerdict::Block { .. }));
}

#[test]
fn pt_allows_in_detection_only_mode() {
    let config = base_config(); // DetectionOnly
    let pipeline = Pipeline::new(&config, vec![Box::new(PathTraversalModule::new())]);
    let mut ctx = with_query(&[("f", "../../etc/passwd")]);
    assert!(matches!(pipeline.run(&mut ctx), PipelineVerdict::Allow));
    assert!(ctx.score >= 10, "score should still accumulate in detection-only: {}", ctx.score);
}

#[test]
fn pt_emits_critical_severity_for_traversal() {
    let m = make_pt();
    match m.inspect(&with_query(&[("f", "../../etc/passwd")])) {
        Decision::Scores(items) => {
            let it = items.iter().find(|i| i.rule_id == "pt-dotdot-traversal").unwrap();
            assert_eq!(it.severity, Severity::Critical);
        }
        other => panic!("expected Scores, got {other:?}"),
    }
}
