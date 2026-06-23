use waf_core::{
    Bytes, Config, Decision, LimitsConfig, ModulesConfig, Normalized, ProxyConfig, RequestContext,
    WafConfig, WafMode, WafModule,
};
use waf_pipeline::{Pipeline, PipelineVerdict};

use waf_detection::request_smuggling::RequestSmugglingModule;

// ── helpers ───────────────────────────────────────────────────────────────────

fn config(mode: WafMode) -> Config {
    Config {
        proxy: ProxyConfig {
            listen: "127.0.0.1:8080".parse().unwrap(),
            backend: "http://localhost:3000".to_string(),
        },
        waf: WafConfig {
            mode,
            block_threshold: 5,
            paranoia_level: 1,
            severity_scores: Default::default(),
        },
        limits: LimitsConfig::default(),
        modules: ModulesConfig::default(), // request_smuggling enabled by default
        rate_limit: Default::default(),
        network: Default::default(),
        resilience: Default::default(),
        tls: Default::default(),
    }
}

fn ctx_with_headers(headers: &[(&str, &str)]) -> RequestContext {
    RequestContext {
        client_ip: "127.0.0.1".parse().unwrap(),
        request_id: "t".to_string(),
        timestamp: std::time::SystemTime::now(),
        method: "POST".to_string(),
        path: "/".to_string(),
        raw_path: "/".to_string(),
        query: None,
        http_version: "HTTP/1.1".to_string(),
        // Header names lowercased, as the proxy's context builder produces them.
        headers: headers
            .iter()
            .map(|(k, v)| (k.to_ascii_lowercase(), v.to_string()))
            .collect(),
        cookies: vec![],
        body: Bytes::new(),
        normalized: Normalized::default(),
        score: 0,
        score_contributions: vec![],
    }
}

fn module() -> RequestSmugglingModule {
    let mut m = RequestSmugglingModule::new();
    m.init(&config(WafMode::Blocking));
    m
}

fn is_reject_400(d: &Decision) -> bool {
    matches!(d, Decision::Reject { status: 400, .. })
}

// ── Rule 1: CL + TE simultaneous ────────────────────────────────────────────────

#[test]
fn cl_and_te_together_rejected() {
    let m = module();
    let d = m.inspect(&ctx_with_headers(&[
        ("Content-Length", "5"),
        ("Transfer-Encoding", "chunked"),
    ]));
    assert!(is_reject_400(&d), "got: {d:?}");
}

// ── Rule 2: Content-Length integrity ────────────────────────────────────────────

#[test]
fn duplicate_content_length_divergent_rejected() {
    let m = module();
    let d = m.inspect(&ctx_with_headers(&[("Content-Length", "5"), ("Content-Length", "6")]));
    assert!(is_reject_400(&d), "got: {d:?}");
}

#[test]
fn duplicate_content_length_identical_rejected() {
    // Even identical duplicates are illegal framing (WAF posture: refuse, don't guess).
    let m = module();
    let d = m.inspect(&ctx_with_headers(&[("Content-Length", "5"), ("Content-Length", "5")]));
    assert!(is_reject_400(&d), "got: {d:?}");
}

#[test]
fn content_length_list_value_rejected() {
    let m = module();
    assert!(is_reject_400(&m.inspect(&ctx_with_headers(&[("Content-Length", "5, 6")]))));
}

#[test]
fn content_length_non_numeric_rejected() {
    let m = module();
    assert!(is_reject_400(&m.inspect(&ctx_with_headers(&[("Content-Length", "0x5")]))));
    assert!(is_reject_400(&m.inspect(&ctx_with_headers(&[("Content-Length", "-1")]))));
}

// ── Rule 3: Transfer-Encoding integrity ─────────────────────────────────────────

#[test]
fn te_chunked_chunked_rejected() {
    let m = module();
    assert!(is_reject_400(&m.inspect(&ctx_with_headers(&[("Transfer-Encoding", "chunked, chunked")]))));
}

#[test]
fn te_obfuscated_token_rejected() {
    let m = module();
    assert!(is_reject_400(&m.inspect(&ctx_with_headers(&[("Transfer-Encoding", "xchunked")]))));
}

#[test]
fn te_list_with_chunked_rejected_strict() {
    // Strict posture: a valid-but-listy TE is refused — lists are the smuggling
    // ground and we re-serialize toward the backend anyway.
    let m = module();
    assert!(is_reject_400(&m.inspect(&ctx_with_headers(&[("Transfer-Encoding", "gzip, chunked")]))));
}

#[test]
fn duplicate_transfer_encoding_rejected() {
    let m = module();
    let d = m.inspect(&ctx_with_headers(&[
        ("Transfer-Encoding", "chunked"),
        ("Transfer-Encoding", "chunked"),
    ]));
    assert!(is_reject_400(&d), "got: {d:?}");
}

#[test]
fn te_chunked_case_insensitive_allowed() {
    let m = module();
    assert!(matches!(m.inspect(&ctx_with_headers(&[("Transfer-Encoding", "Chunked")])), Decision::Allow));
}

// ── legitimate framing passes ───────────────────────────────────────────────────

#[test]
fn single_valid_content_length_passes() {
    let m = module();
    assert!(matches!(m.inspect(&ctx_with_headers(&[("Content-Length", "42")])), Decision::Allow));
}

#[test]
fn single_chunked_transfer_encoding_passes() {
    let m = module();
    assert!(matches!(m.inspect(&ctx_with_headers(&[("Transfer-Encoding", "chunked")])), Decision::Allow));
}

#[test]
fn no_framing_headers_passes() {
    let m = module();
    assert!(matches!(m.inspect(&ctx_with_headers(&[("Host", "example.com")])), Decision::Allow));
}

#[test]
fn disabled_module_allows_everything() {
    let mut cfg = config(WafMode::Blocking);
    cfg.modules.request_smuggling.enabled = false;
    let mut m = RequestSmugglingModule::new();
    m.init(&cfg);
    let d = m.inspect(&ctx_with_headers(&[
        ("Content-Length", "5"),
        ("Transfer-Encoding", "chunked"),
    ]));
    assert!(matches!(d, Decision::Allow));
}

// ── pipeline mode semantics ─────────────────────────────────────────────────────

#[test]
fn pipeline_rejects_smuggling_in_blocking_mode() {
    let pipeline = Pipeline::new(&config(WafMode::Blocking), vec![Box::new(RequestSmugglingModule::new())]);
    let mut ctx = ctx_with_headers(&[("Content-Length", "5"), ("Transfer-Encoding", "chunked")]);
    match pipeline.run_connection(&mut ctx) {
        PipelineVerdict::Reject { status: 400, .. } => {}
        other => panic!("expected Reject 400, got {other:?}"),
    }
}

#[test]
fn pipeline_detection_only_logs_but_allows() {
    let pipeline =
        Pipeline::new(&config(WafMode::DetectionOnly), vec![Box::new(RequestSmugglingModule::new())]);
    let mut ctx = ctx_with_headers(&[("Content-Length", "5"), ("Transfer-Encoding", "chunked")]);
    assert!(matches!(pipeline.run_connection(&mut ctx), PipelineVerdict::Allow));
}
