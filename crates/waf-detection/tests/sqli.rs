use waf_core::{
    Bytes, Config, Decision, LimitsConfig, ModulesConfig, Normalized, ParsedBody, ProxyConfig,
    RequestContext, Severity, WafConfig, WafMode, WafModule,
};
use waf_normalizer::Normalizer;
use waf_pipeline::{Pipeline, PipelineVerdict};

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

fn make_sqli() -> SqliModule {
    let mut m = SqliModule::new();
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

fn with_cookies(cookies: &[(&str, &str)]) -> RequestContext {
    let mut c = base_ctx();
    c.normalized.cookies = cookies
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    c
}

// ── detection ─────────────────────────────────────────────────────────────────

#[test]
fn sqli_union_select_detected_in_query() {
    let m = make_sqli();
    let ctx = with_query(&[("id", "1 UNION SELECT username,password FROM users--")]);
    let d = m.inspect(&ctx);
    assert!(scores_contains(&d, "sqli-union-select"), "got: {d:?}");
}

#[test]
fn sqli_or_tautology_detected() {
    let m = make_sqli();
    let ctx = with_query(&[("q", "' OR '1'='1")]);
    assert!(is_scored(&m.inspect(&ctx)));
}

#[test]
fn sqli_and_tautology_detected() {
    let m = make_sqli();
    let ctx = with_query(&[("id", "1 AND 1=1")]);
    assert!(is_scored(&m.inspect(&ctx)));
}

#[test]
fn sqli_or_tautology_variants_still_detected() {
    // Recall: the narrowed pattern must still catch every real OR-tautology form.
    let m = make_sqli();
    let payloads = ["or 1=1", "or 'a'='a'", "or x=x", "OR 1 = 1", "or \"a\"=\"a\"", "or 1=1--"];
    for p in payloads {
        assert!(
            scores_contains(&m.inspect(&with_query(&[("q", p)])), "sqli-tautology-or"),
            "missed: {p}"
        );
    }
}

#[test]
fn sqli_and_tautology_still_detected_after_narrowing() {
    let m = make_sqli(); // PL3 → and-tautology (PL2) active
    assert!(scores_contains(
        &m.inspect(&with_query(&[("q", "and 1=1")])),
        "sqli-tautology-and"
    ));
}

#[test]
fn sqli_tautology_no_fp_on_benign_phrases() {
    // Traps: `or word=word` / `and word=word` are legitimate English + query
    // assignments, not tautologies. They blocked at Critical/PL1 before the fix.
    let m = make_sqli();
    let traps = [
        "shoes for men or women=adult",
        "color or size=large",
        "store or online=yes",
        "red and blue=mix",
    ];
    for t in traps {
        let d = m.inspect(&with_query(&[("q", t)]));
        assert!(matches!(d, Decision::Allow), "false positive on {t}: {d:?}");
    }
}

#[test]
fn sqli_quote_comment_detected() {
    let m = make_sqli();
    let ctx = with_query(&[("name", "admin'--")]);
    assert!(is_scored(&m.inspect(&ctx)));
}

#[test]
fn sqli_stacked_drop_detected() {
    let m = make_sqli();
    let ctx = with_query(&[("id", "1; DROP TABLE users")]);
    assert!(is_scored(&m.inspect(&ctx)));
}

#[test]
fn sqli_time_based_sleep_detected() {
    let m = make_sqli();
    let ctx = with_query(&[("id", "1 AND SLEEP(5)")]);
    assert!(is_scored(&m.inspect(&ctx)));
}

#[test]
fn sqli_detected_in_form_body() {
    let m = make_sqli();
    let ctx = with_form_body(&[("user", "' UNION SELECT 1,2,3--")]);
    assert!(is_scored(&m.inspect(&ctx)));
}

#[test]
fn sqli_detected_in_json_body() {
    let m = make_sqli();
    let ctx = with_json_body(&[("search", "1 OR 1=1--")]);
    assert!(is_scored(&m.inspect(&ctx)));
}

#[test]
fn sqli_detected_in_cookie() {
    let m = make_sqli();
    let ctx = with_cookies(&[("session", "' UNION SELECT * FROM sessions--")]);
    assert!(is_scored(&m.inspect(&ctx)));
}

#[test]
fn sqli_url_decoded_payload_detected() {
    // Simulate normalizer output for q=%27+OR+1%3D1--
    let m = make_sqli();
    let ctx = with_query(&[("q", "' OR 1=1--")]);
    assert!(is_scored(&m.inspect(&ctx)));
}

#[test]
fn sqli_double_encoded_detected_via_normalizer() {
    // %2527 = double-encoded single-quote; after normalizer produces ' OR 1=1--
    let mut c = base_ctx();
    c.query = Some("q=%2527+OR+1%253D1--".to_string());
    Normalizer::new(&LimitsConfig::default()).normalize(&mut c).unwrap();
    assert!(c.normalized.double_encoding_detected, "normalizer should flag double encoding");
    // normalized query param should now be: ' OR 1=1--
    let m = make_sqli();
    assert!(
        is_scored(&m.inspect(&c)),
        "module did not detect sqli in double-decoded value; params: {:?}", c.normalized.query_params
    );
}

#[test]
fn sqli_encoded_payload_in_cookie_detected_via_normalizer() {
    // Regression for the Fase 2 cookie-decode fix: a percent-encoded SQLi payload
    // in a COOKIE (%27%20OR%201%3D1-- → ' OR 1=1--) is now decoded like query/body
    // and detected. Before the fix the raw cookie text would not match.
    let mut c = base_ctx();
    c.headers = vec![("cookie".to_string(), "sid=%27%20OR%201%3D1--".to_string())];
    Normalizer::new(&LimitsConfig::default()).normalize(&mut c).unwrap();
    let m = make_sqli();
    assert!(
        is_scored(&m.inspect(&c)),
        "module did not detect sqli in decoded cookie; cookies: {:?}",
        c.normalized.cookies
    );
}

// ── no false positives ────────────────────────────────────────────────────────

#[test]
fn sqli_no_false_positives_on_legit_input() {
    let m = make_sqli();
    let legit = [
        ("q", "rust programming"),
        ("id", "42"),
        ("name", "Alice"),
        ("filter", "price > 10"),
        ("search", "the best select occasions"),
        ("comment", "Great and helpful product!"),
        ("user", "john.doe@example.com"),
        ("sort", "created_at DESC"),
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
fn sqli_allows_in_detection_only_mode() {
    let config = base_config(); // DetectionOnly
    let pipeline = Pipeline::new(&config, vec![Box::new(SqliModule::new())]);
    let mut ctx = with_query(&[("q", "' UNION SELECT 1,2--")]);
    assert!(matches!(pipeline.run(&mut ctx), PipelineVerdict::Allow));
}

#[test]
fn sqli_blocks_in_blocking_mode() {
    let mut config = base_config();
    config.waf.mode = WafMode::Blocking;
    config.waf.block_threshold = 5;
    // union-select is Critical (default = 6, C2 / Fase7-P2, see ARCHITECTURE §7) →
    // reaches the threshold (5) alone.
    let pipeline = Pipeline::new(&config, vec![Box::new(SqliModule::new())]);
    let mut ctx = with_query(&[("q", "' UNION SELECT 1,2--")]);
    assert!(matches!(pipeline.run(&mut ctx), PipelineVerdict::Block { .. }));
}

// ── init behavior ─────────────────────────────────────────────────────────────

#[test]
fn sqli_returns_allow_before_init() {
    // Before init() the module must not panic and must return Allow.
    let m = SqliModule::new();
    let ctx = with_query(&[("q", "' UNION SELECT 1--")]);
    assert!(matches!(m.inspect(&ctx), Decision::Allow));
}

#[test]
fn sqli_detects_after_init() {
    let mut m = SqliModule::new();
    let ctx = with_query(&[("q", "' UNION SELECT 1--")]);
    assert!(matches!(m.inspect(&ctx), Decision::Allow)); // before
    m.init(&base_config());
    assert!(is_scored(&m.inspect(&ctx))); // after
}

#[test]
fn sqli_union_select_emits_critical_severity() {
    let m = make_sqli();
    let ctx = with_query(&[("q", "' UNION SELECT 1--")]);
    match m.inspect(&ctx) {
        Decision::Scores(items) => {
            let it = items.iter().find(|i| i.rule_id == "sqli-union-select").unwrap();
            assert_eq!(it.severity, Severity::Critical);
        }
        other => panic!("expected Scores, got {other:?}"),
    }
}

// ── paranoia level ──────────────────────────────────────────────────────────

#[test]
fn sqli_paranoia_level_gates_low_confidence_rules() {
    // CAST(...) is a Notice rule active only from paranoia level 3.
    let ctx = with_query(&[("id", "CAST(username AS int)")]);

    let mut low = SqliModule::new();
    low.init(&config_with_paranoia(1));
    assert!(
        matches!(low.inspect(&ctx), Decision::Allow),
        "PL1 must not activate the cast-convert rule"
    );

    let mut high = SqliModule::new();
    high.init(&config_with_paranoia(3));
    assert!(
        scores_contains(&high.inspect(&ctx), "sqli-cast-convert"),
        "PL3 must activate the cast-convert rule"
    );
}
