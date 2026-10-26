// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

//! STEP-0 datapath bite-test: the schema-enforcement module, loaded as a `WafModule`, actually
//! BLOCKS a schema-invalid GraphQL operation on the REAL pipeline — and the SAME request through a
//! pipeline WITHOUT the module passes (control). This proves the module is on the datapath and
//! contributes to the SAME cumulative anomaly score, not that the request is green for some other
//! reason (same rigor as the reputation / CRS-curated bite-tests).
//!
//! It also proves the fail-safe: a VALID operation passes even WITH the module on, and default-off
//! (`enabled=false`) never contributes.

use waf_core::{Bytes, Config, Normalized, ParsedBody, RequestContext, Severity, WafMode, WafModule};
use waf_modules_premium::{rules, GraphqlSchemaModule};
use waf_pipeline::{Pipeline, PipelineVerdict};

const SDL: &str = r#"
    type Query { user(id: ID!): User }
    type User { id: ID!, name: String }
"#;

fn blocking_config() -> Config {
    let mut c = Config::default();
    c.waf.mode = WafMode::Blocking;
    c.waf.block_threshold = 5; // a single CRITICAL contribution (severity 6) crosses this
    c
}

fn graphql_request(op: &str) -> RequestContext {
    // `application/graphql` transport: the module reads the operation from `ctx.normalized`
    // (post-normalization), so the parsed body + lowercased headers live there.
    let normalized = Normalized {
        path: "/graphql".to_string(),
        headers: vec![("content-type".to_string(), "application/graphql".to_string())],
        body: ParsedBody::Raw(Bytes::from(op.to_string())),
        ..Default::default()
    };
    RequestContext {
        client_ip: "203.0.113.10".parse().unwrap(),
        request_id: "bite".to_string(),
        timestamp: std::time::SystemTime::now(),
        method: "POST".to_string(),
        path: "/graphql".to_string(),
        raw_path: "/graphql".to_string(),
        query: None,
        http_version: "HTTP/1.1".to_string(),
        headers: vec![("content-type".to_string(), "application/graphql".to_string())],
        cookies: vec![],
        body: Bytes::from(op.to_string()),
        normalized,
        score: 0,
        score_contributions: vec![],
    }
}

#[test]
fn schema_invalid_query_blocks_on_the_pipeline_but_control_without_the_module_passes() {
    let config = blocking_config();
    // `password` is not in the schema → UNKNOWN_FIELD → Critical → over threshold → blocked.
    let bad = "{ user(id: 1) { id password } }";

    let module = GraphqlSchemaModule::from_sdl(SDL, true).expect("valid SDL");
    let pipe = Pipeline::new(&config, vec![Box::new(module)]);
    let mut ctx = graphql_request(bad);
    let verdict = pipe.run(&mut ctx);
    assert!(
        !matches!(verdict, PipelineVerdict::Allow),
        "schema-invalid query must block on the datapath (got {verdict:?})"
    );
    assert!(
        ctx.score_contributions.iter().any(|c| c.rule_id == rules::GRAPHQL_UNKNOWN_FIELD.id()),
        "the block must be attributed to the schema-enforcement rule, not something else"
    );

    // Control: same request through a pipeline WITHOUT the module passes — proves the module caused it.
    let bare = Pipeline::new(&config, vec![]);
    let mut ctx_ctrl = graphql_request(bad);
    assert!(
        matches!(bare.run(&mut ctx_ctrl), PipelineVerdict::Allow),
        "without the module the same request must pass (control)"
    );
}

#[test]
fn valid_query_passes_even_with_the_module_on() {
    let config = blocking_config();
    let module = GraphqlSchemaModule::from_sdl(SDL, true).expect("valid SDL");
    let pipe = Pipeline::new(&config, vec![Box::new(module)]);
    let mut ctx = graphql_request("{ user(id: 1) { id name } }");
    assert!(
        matches!(pipe.run(&mut ctx), PipelineVerdict::Allow),
        "a schema-valid query must not be flagged (fail-safe / no FP)"
    );
}

#[test]
fn default_off_never_contributes() {
    let config = blocking_config();
    let module = GraphqlSchemaModule::from_sdl(SDL, false).expect("valid SDL");
    let pipe = Pipeline::new(&config, vec![Box::new(module)]);
    let mut ctx = graphql_request("{ user(id: 1) { id password } }");
    assert!(
        matches!(pipe.run(&mut ctx), PipelineVerdict::Allow),
        "disabled module must be inert even on a schema-invalid query"
    );
}

#[test]
fn legit_graphql_constructs_pass_through_the_pipeline() {
    // FP-guard end-to-end: real constructs a client sends (aliases, __typename, variables,
    // fragments, and introspection — which is the OPEN module's concern, not ours) must NOT be
    // flagged, even with the module ON in blocking mode.
    let config = blocking_config();
    let module = GraphqlSchemaModule::from_sdl(SDL, true).expect("valid SDL");
    let pipe = Pipeline::new(&config, vec![Box::new(module)]);
    for q in [
        "{ user(id: 1) { id name } }",
        "{ me: user(id: 1) { __typename id } }",
        "query($id: ID!) { user(id: $id) { id } }",
        "query { user(id: 1) { ...F } } fragment F on User { id name }",
        "{ __schema { queryType { name } } }",
    ] {
        let mut ctx = graphql_request(q);
        assert!(
            matches!(pipe.run(&mut ctx), PipelineVerdict::Allow),
            "legit query must pass (no FP): {q}"
        );
    }
}

// Sanity that the module carries the structural flag (must run on the content fast-path skip).
#[test]
fn module_is_structural() {
    let module = GraphqlSchemaModule::from_sdl(SDL, true).expect("valid SDL");
    assert!(module.structural());
}

// Keep the `Severity` import meaningful across refactors of the probe.
#[allow(dead_code)]
fn _severity_is_in_scope(_s: Severity) {}
