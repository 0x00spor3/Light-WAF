// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

use waf_core::{
    Bytes, Config, Decision, LimitsConfig, ModulesConfig, Normalized, ProxyConfig,
    RequestContext, Severity, WafConfig, WafMode, WafModule,
};
use waf_normalizer::Normalizer;
use waf_pipeline::{Pipeline, PipelineVerdict};

use waf_detection::sqli::SqliModule;
use waf_detection::ssrf::SsrfModule;

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

fn make_ssrf() -> SsrfModule {
    let mut m = SsrfModule::new();
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

// ── detection ─────────────────────────────────────────────────────────────────

#[test]
fn ssrf_cloud_metadata_detected() {
    let m = make_ssrf();
    assert!(scores_contains(
        &m.inspect(&with_query(&[("url", "http://169.254.169.254/latest/meta-data/")])),
        "ssrf-cloud-metadata"
    ));
    assert!(scores_contains(
        &m.inspect(&with_query(&[("u", "http://metadata.google.internal/")])),
        "ssrf-cloud-metadata"
    ));
}

#[test]
fn ssrf_dangerous_scheme_and_loopback_detected() {
    let m = make_ssrf();
    let d = m.inspect(&with_query(&[("u", "gopher://127.0.0.1:6379/_INFO")]));
    assert!(scores_contains(&d, "ssrf-dangerous-scheme"), "got: {d:?}");
    assert!(scores_contains(&d, "ssrf-loopback"), "got: {d:?}");

    let d2 = m.inspect(&with_query(&[("u", "dict://localhost:11211/stats")]));
    assert!(scores_contains(&d2, "ssrf-dangerous-scheme"), "got: {d2:?}");
    assert!(scores_contains(&d2, "ssrf-loopback"), "got: {d2:?}");
}

#[test]
fn ssrf_encoded_metadata_detected_via_normalizer() {
    let c = normalized_query_ctx("u=http%3a%2f%2f169.254.169.254%2flatest");
    let m = make_ssrf();
    assert!(
        scores_contains(&m.inspect(&c), "ssrf-cloud-metadata"),
        "params: {:?}",
        c.normalized.query_params
    );
}

#[test]
fn ssrf_ip_obfuscation_detected() {
    let m = make_ssrf();
    assert!(scores_contains(&m.inspect(&with_query(&[("u", "http://2130706433/")])), "ssrf-ip-obfuscation"));
    assert!(scores_contains(&m.inspect(&with_query(&[("u", "http://0x7f000001/")])), "ssrf-ip-obfuscation"));
}

#[test]
fn ssrf_short_loopback_form_detected() {
    let m = make_ssrf();
    assert!(scores_contains(&m.inspect(&with_query(&[("u", "http://127.1/admin")])), "ssrf-loopback"));
}

#[test]
fn ssrf_private_ip_detected_at_pl3() {
    let m = make_ssrf(); // PL3
    assert!(scores_contains(&m.inspect(&with_query(&[("u", "http://192.168.1.1/admin")])), "ssrf-private-ip"));
}

#[test]
fn ssrf_metadata_also_matches_link_local_at_pl3() {
    // DECLARED overlap: the metadata IP is also link-local, so at PL3 it scores
    // from both ssrf-cloud-metadata (Critical) and ssrf-private-ip (Notice).
    let m = make_ssrf();
    let d = m.inspect(&with_query(&[("u", "http://169.254.169.254/")]));
    assert!(scores_contains(&d, "ssrf-cloud-metadata"), "got: {d:?}");
    assert!(scores_contains(&d, "ssrf-private-ip"), "got: {d:?}");
}

// ── boundary with RFI / LFI (no double-counting) ───────────────────────────────

#[test]
fn ssrf_ignores_rfi_and_lfi_territory() {
    let m = make_ssrf();
    // Remote script (RFI's job) — SSRF must stay silent.
    assert!(matches!(m.inspect(&with_query(&[("p", "http://evil.com/shell.php")])), Decision::Allow));
    // file:// wrapper (LFI's job) — SSRF must stay silent.
    assert!(matches!(m.inspect(&with_query(&[("p", "file:///etc/passwd")])), Decision::Allow));
    // Ordinary external https URL — not SSRF.
    assert!(matches!(m.inspect(&with_query(&[("p", "https://api.github.com/users")])), Decision::Allow));
}

// ── no false positives ────────────────────────────────────────────────────────

#[test]
fn ssrf_no_false_positives_on_legit_input() {
    let m = make_ssrf(); // PL3 — every rule active
    let legit = [
        ("url", "https://api.github.com/users"),
        ("ip", "8.8.8.8"),                 // public IP
        ("host", "example.com"),
        ("port", "8080"),
        ("q", "local coffee shop"),        // "local" not "localhost"
        ("version", "release 10.2.3"),     // 3 octets, not an IPv4
        ("addr", "172.15.0.1"),            // 172.15 is OUTSIDE the private 16-31 range
        ("net", "200.100.100.100"),        // public
    ];
    for (k, v) in &legit {
        let ctx = with_query(&[(k, v)]);
        let d = m.inspect(&ctx);
        assert!(matches!(d, Decision::Allow), "false positive on {k}={v}: {d:?}");
    }
}

#[test]
fn ssrf_loopback_not_triggered_by_ip_ending_in_127_1() {
    // Regression: 192.168.127.1 must NOT trip the anchored 127.1 short form.
    let m = make_ssrf();
    let d = m.inspect(&with_query(&[("ip", "192.168.127.1")]));
    assert!(!scores_contains(&d, "ssrf-loopback"), "127.1 short form must be anchored: {d:?}");
    // It is a legit private IP, so ssrf-private-ip (PL3 Notice) firing is correct.
    assert!(scores_contains(&d, "ssrf-private-ip"));
}

#[test]
fn ssrf_private_ip_does_not_block_alone() {
    // A version-like 4-octet private value trips only Notice (2) < threshold (5).
    let mut config = base_config();
    config.waf.mode = WafMode::Blocking;
    config.waf.block_threshold = 5;
    let pipeline = Pipeline::new(&config, vec![Box::new(SsrfModule::new())]);

    let mut ctx = with_query(&[("host", "10.2.3.4")]);
    let verdict = pipeline.run(&mut ctx);
    assert!(matches!(verdict, PipelineVerdict::Allow), "single private-ip Notice must not block alone");
    assert_eq!(ctx.score, 2);
}

// ── paranoia level ────────────────────────────────────────────────────────────

#[test]
fn ssrf_paranoia_gates_loopback_and_private_ip() {
    let loopback = with_query(&[("u", "http://127.0.0.1/")]);
    let private = with_query(&[("u", "http://192.168.1.1/")]);
    let scheme = with_query(&[("u", "gopher://x/")]);

    let mut pl1 = SsrfModule::new();
    pl1.init(&config_with_paranoia(1));
    assert!(scores_contains(&pl1.inspect(&scheme), "ssrf-dangerous-scheme"), "scheme on at PL1");
    assert!(matches!(pl1.inspect(&loopback), Decision::Allow), "loopback off at PL1");
    assert!(matches!(pl1.inspect(&private), Decision::Allow), "private-ip off at PL1");

    let mut pl2 = SsrfModule::new();
    pl2.init(&config_with_paranoia(2));
    assert!(scores_contains(&pl2.inspect(&loopback), "ssrf-loopback"), "loopback on at PL2");
    assert!(matches!(pl2.inspect(&private), Decision::Allow), "private-ip still off at PL2");

    let mut pl3 = SsrfModule::new();
    pl3.init(&config_with_paranoia(3));
    assert!(scores_contains(&pl3.inspect(&private), "ssrf-private-ip"), "private-ip on at PL3");
}

// ── init behavior ─────────────────────────────────────────────────────────────

#[test]
fn ssrf_returns_allow_before_init() {
    let m = SsrfModule::new();
    assert!(matches!(m.inspect(&with_query(&[("u", "http://169.254.169.254/")])), Decision::Allow));
}

#[test]
fn ssrf_emits_critical_severity_for_metadata() {
    let m = make_ssrf();
    match m.inspect(&with_query(&[("u", "http://169.254.169.254/")])) {
        Decision::Scores(items) => {
            let it = items.iter().find(|i| i.rule_id == "ssrf-cloud-metadata").unwrap();
            assert_eq!(it.severity, Severity::Critical);
        }
        other => panic!("expected Scores, got {other:?}"),
    }
}

// ── pipeline integration / cumulative scoring ──────────────────────────────────

#[test]
fn ssrf_contributes_to_cumulative_score_with_sqli() {
    let config = base_config(); // DetectionOnly runs every module
    let modules: Vec<Box<dyn WafModule>> = vec![
        Box::new(SqliModule::new()),
        Box::new(SsrfModule::new()),
    ];
    let pipeline = Pipeline::new(&config, modules);

    let mut ctx = with_query(&[
        ("q", "1 UNION SELECT 1,2"),
        ("u", "gopher://169.254.169.254/"),
    ]);
    let verdict = pipeline.run(&mut ctx);

    assert!(matches!(verdict, PipelineVerdict::Allow)); // detection-only
    assert!(ctx.score_contributions.iter().any(|c| c.module == "sqli"));
    assert!(ctx.score_contributions.iter().any(|c| c.module == "ssrf"));
}

#[test]
fn ssrf_blocks_in_blocking_mode() {
    let mut config = base_config();
    config.waf.mode = WafMode::Blocking;
    config.waf.block_threshold = 5;
    let pipeline = Pipeline::new(&config, vec![Box::new(SsrfModule::new())]);
    // cloud-metadata = Critical 5 >= 5
    let mut ctx = with_query(&[("u", "http://169.254.169.254/latest/meta-data/")]);
    assert!(matches!(pipeline.run(&mut ctx), PipelineVerdict::Block { .. }));
}
