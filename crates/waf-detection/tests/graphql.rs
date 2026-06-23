//! GraphQL module transport coverage — isolates `operations()`/`expand()` from the
//! normalizer. Focus: the Fase 11-bis fix "b" — a JSON envelope `{"query":"<doc>"}` in
//! the GET `?query=` value must be unwrapped so the lexer sees the real document (before
//! the fix the document was opaque JSON string content → introspection/DoS invisible).

use waf_core::{
    Bytes, Config, Decision, GraphqlConfig, LimitsConfig, ModulesConfig, Normalized, ProxyConfig,
    RequestContext, WafConfig, WafMode, WafModule,
};

use waf_detection::graphql::GraphqlModule;

fn config() -> Config {
    Config {
        proxy: ProxyConfig {
            listen: "127.0.0.1:8080".parse().unwrap(),
            backend: "http://localhost:3000".to_string(),
        },
        waf: WafConfig {
            mode: WafMode::Blocking,
            block_threshold: 5,
            paranoia_level: 3,
            severity_scores: Default::default(),
        },
        limits: LimitsConfig::default(),
        modules: ModulesConfig {
            graphql: GraphqlConfig { enabled: true, block_introspection: true, ..Default::default() },
            ..Default::default()
        },
        rate_limit: Default::default(),
        network: Default::default(),
        resilience: Default::default(),
    }
}

fn module() -> GraphqlModule {
    let mut m = GraphqlModule::new();
    m.init(&config());
    m
}

/// A GET request to `path` whose already-normalized `?query=` value is `query_value`
/// (the normalizer's job — percent/double-decoding — is tested separately).
fn get(path: &str, query_value: &str) -> RequestContext {
    let mut ctx = RequestContext {
        client_ip: "127.0.0.1".parse().unwrap(),
        request_id: "t".to_string(),
        timestamp: std::time::SystemTime::now(),
        method: "GET".to_string(),
        path: path.to_string(),
        raw_path: path.to_string(),
        query: None,
        http_version: "HTTP/1.1".to_string(),
        headers: vec![],
        cookies: vec![],
        body: Bytes::new(),
        normalized: Normalized::default(),
        score: 0,
        score_contributions: vec![],
    };
    ctx.normalized.path = path.to_string();
    ctx.normalized.query_params = vec![("query".to_string(), query_value.to_string())];
    ctx
}

#[test]
fn get_json_envelope_introspection_is_blocked() {
    // gotestwaf shape: the whole JSON envelope sits in `?query=`. Unwrap → `__schema`.
    let ctx = get("/graphql", r#"{"query":"query IntrospectionQuery {__schema {queryType {name}}}"}"#);
    assert!(
        matches!(module().inspect(&ctx), Decision::Block { rule_id, .. } if rule_id == "graphql-introspection"),
        "envelope introspection must be blocked"
    );
}

#[test]
fn get_raw_document_introspection_still_blocked() {
    // The ordinary GET transport (bare document, not an envelope) keeps working.
    let ctx = get("/graphql", "{__schema{types{name}}}");
    assert!(matches!(module().inspect(&ctx), Decision::Block { .. }));
}

#[test]
fn get_json_envelope_deep_query_is_rejected() {
    // A DoS payload hidden in an envelope is unwrapped and capped too (depth > 15).
    let deep = format!("query{}{{id}}{}", "{a".repeat(20), "}".repeat(21));
    let ctx = get("/graphql", &format!("{{\"query\":\"{deep}\"}}"));
    assert!(matches!(module().inspect(&ctx), Decision::Reject { status: 400, .. }));
}

#[test]
fn get_benign_envelope_is_allowed() {
    // A normal query wrapped in an envelope must not false-positive.
    let ctx = get("/graphql", r#"{"query":"query{user{id name}}"}"#);
    assert!(matches!(module().inspect(&ctx), Decision::Allow));
}

#[test]
fn get_benign_raw_document_is_allowed() {
    let ctx = get("/graphql", "{user{id name}}");
    assert!(matches!(module().inspect(&ctx), Decision::Allow));
}

#[test]
fn envelope_on_non_graphql_path_is_ignored() {
    // Path-gating: the same envelope on a non-GraphQL path must be left alone.
    let ctx = get("/api/search", r#"{"query":"query{__schema{name}}"}"#);
    assert!(matches!(module().inspect(&ctx), Decision::Allow));
}
