// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: BUSL-1.1

//! A4 datapath bite-test: the OpenAPI positive-security module, loaded as a `WafModule`, actually
//! runs on the REAL pipeline and contributes to the SAME cumulative anomaly score — an unknown route
//! BLOCKS (Critical), and the SAME request through a pipeline WITHOUT the module passes (control), so
//! the block is caused by this module, not something else. It also proves the fail-safes: a
//! contract-valid request passes even with the module ON, a contract violation is attributed to the
//! right `schema-api-*` rule, default-off is inert, and — the boundary — a schema-VALID body that
//! carries an injection *value* is NOT flagged by this module (value-level detection is OPEN §6's job;
//! this module governs the contract).

use std::time::SystemTime;

use waf_core::{Bytes, Config, Normalized, RequestContext, WafMode, WafModule};
use waf_modules_premium::{rules, ApiSchemaEnforcementConfig, ApiSchemaModule};
use waf_pipeline::{Pipeline, PipelineVerdict};

// A 3.0 spec (with the nullable field, to keep the normalization on the datapath too).
const SPEC: &str = r##"{
    "openapi": "3.0.3",
    "info": { "title": "t", "version": "1" },
    "components": {
        "schemas": {
            "User": {
                "type": "object",
                "additionalProperties": false,
                "required": ["name"],
                "properties": {
                    "name": { "type": "string" },
                    "nickname": { "type": "string", "nullable": true }
                }
            }
        }
    },
    "paths": {
        "/users/{id}": {
            "parameters": [
                { "name": "id", "in": "path", "required": true, "schema": { "type": "integer" } }
            ],
            "post": {
                "requestBody": {
                    "required": true,
                    "content": { "application/json": { "schema": { "$ref": "#/components/schemas/User" } } }
                },
                "responses": { "200": { "description": "ok" } }
            }
        }
    }
}"##;

fn blocking_config() -> Config {
    let mut c = Config::default();
    c.waf.mode = WafMode::Blocking;
    c.waf.block_threshold = 5; // a single CRITICAL contribution (severity 6) crosses this
    c
}

fn cfg(enabled: bool) -> ApiSchemaEnforcementConfig {
    ApiSchemaEnforcementConfig { enabled, paths: vec!["/users".to_string()], ..Default::default() }
}

fn module(enabled: bool) -> ApiSchemaModule {
    ApiSchemaModule::from_spec_json(SPEC, &cfg(enabled)).expect("valid spec")
}

fn request(method: &str, path: &str, ct: Option<&str>, body: &str) -> RequestContext {
    let headers: Vec<(String, String)> =
        ct.map(|c| vec![("content-type".to_string(), c.to_string())]).unwrap_or_default();
    let normalized = Normalized {
        path: path.to_string(), // the normalizer lowercases/decodes; tests pass the normalized form
        headers: headers.clone(),
        ..Default::default()
    };
    RequestContext {
        client_ip: "203.0.113.10".parse().unwrap(),
        request_id: "bite".to_string(),
        timestamp: SystemTime::now(),
        method: method.to_string(),
        path: path.to_string(),
        raw_path: path.to_string(),
        query: None,
        http_version: "HTTP/1.1".to_string(),
        headers,
        cookies: vec![],
        body: Bytes::from(body.to_string()),
        normalized,
        score: 0,
        score_contributions: vec![],
    }
}

#[test]
fn unknown_route_blocks_on_the_pipeline_but_control_passes() {
    let config = blocking_config();
    // Under the guarded `/users` prefix but not a declared route → UNKNOWN_ROUTE → Critical → blocks.
    let pipe = Pipeline::new(&config, vec![Box::new(module(true))]);
    let mut ctx = request("GET", "/users/1/posts", None, "");
    let verdict = pipe.run(&mut ctx);
    assert!(
        !matches!(verdict, PipelineVerdict::Allow),
        "an unknown route must block on the datapath (got {verdict:?})"
    );
    assert!(
        ctx.score_contributions.iter().any(|c| c.rule_id == rules::API_UNKNOWN_ROUTE.id()),
        "the block must be attributed to the schema-api unknown-route rule"
    );

    // Control: same request WITHOUT the module passes — proves the module caused the block.
    let bare = Pipeline::new(&config, vec![]);
    let mut ctrl = request("GET", "/users/1/posts", None, "");
    assert!(matches!(bare.run(&mut ctrl), PipelineVerdict::Allow), "control must pass");
}

#[test]
fn contract_valid_request_passes_even_with_module_on() {
    let config = blocking_config();
    let pipe = Pipeline::new(&config, vec![Box::new(module(true))]);
    // Valid body, including the 3.0 nullable field set to null (proves normalization on the datapath).
    let mut ctx = request("POST", "/users/1", Some("application/json"), r#"{"name":"ada","nickname":null}"#);
    assert!(
        matches!(pipe.run(&mut ctx), PipelineVerdict::Allow),
        "a contract-valid request must not be flagged (fail-safe / no FP)"
    );
    assert!(ctx.score_contributions.is_empty(), "no contribution on a clean request");
}

#[test]
fn contract_violation_is_attributed_on_the_datapath() {
    let config = blocking_config();
    let pipe = Pipeline::new(&config, vec![Box::new(module(true))]);
    // Unknown body property (additionalProperties:false) → contributes on the datapath.
    let mut ctx = request("POST", "/users/1", Some("application/json"), r#"{"name":"ada","isAdmin":true}"#);
    let _ = pipe.run(&mut ctx);
    assert!(
        ctx.score_contributions.iter().any(|c| c.rule_id == rules::API_UNKNOWN_PROPERTY.id()),
        "the contract violation must be attributed to schema-api-unknown-property"
    );

    // Control: without the module, the same request records no schema-api contribution.
    let bare = Pipeline::new(&config, vec![]);
    let mut ctrl = request("POST", "/users/1", Some("application/json"), r#"{"name":"ada","isAdmin":true}"#);
    let _ = bare.run(&mut ctrl);
    assert!(ctrl.score_contributions.iter().all(|c| !c.rule_id.starts_with("schema-api")));
}

#[test]
fn injection_value_in_a_valid_body_is_not_this_modules_concern() {
    // BOUNDARY: `name` is a valid string per the schema, so this module ALLOWS it — value-level
    // detection (SQLi/XSS) stays in the OPEN §6 channel. The assembled enterprise pipeline (A8 e2e)
    // proves §6 still blocks it; here we prove this module does not overreach into content.
    let config = blocking_config();
    let pipe = Pipeline::new(&config, vec![Box::new(module(true))]);
    let mut ctx = request("POST", "/users/1", Some("application/json"), r#"{"name":"' OR 1=1--"}"#);
    assert!(matches!(pipe.run(&mut ctx), PipelineVerdict::Allow), "contract-valid ⇒ this module allows");
    assert!(
        ctx.score_contributions.iter().all(|c| !c.rule_id.starts_with("schema-api")),
        "this module must not flag a contract-valid body on its value content"
    );
}

#[test]
fn default_off_never_contributes() {
    let config = blocking_config();
    let pipe = Pipeline::new(&config, vec![Box::new(module(false))]);
    let mut ctx = request("GET", "/users/1/posts", None, "");
    assert!(
        matches!(pipe.run(&mut ctx), PipelineVerdict::Allow),
        "disabled module must be inert even on an unknown route"
    );
    assert!(ctx.score_contributions.is_empty());
}

#[test]
fn module_is_structural() {
    assert!(module(true).structural());
}
