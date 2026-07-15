// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: BUSL-1.1

//! Premium detection modules (enterprise, §4). This crate hosts logic-driven premium `WafModule`s
//! injected via the core's `.add_module()` seam — starting with **GraphQL schema-enforcement**
//! (§4-B): validate each incoming GraphQL operation against the app's REAL schema (`.graphql` SDL).
//! A field/type/argument NOT in the schema means a query the app's own client would never send —
//! a strong probing/abuse signal — so it contributes to the SAME cumulative anomaly score the core
//! already uses (no new decision logic; `Decision::Scores`, severity resolved by the pipeline).
//!
//! This is **governance of the schema**, NOT baseline detection: value-level injection stays in the
//! OPEN §6 channel, and the structural DoS caps (depth/size/batch) stay in the OPEN Phase-11 GraphQL
//! module — which runs FIRST, so apollo-compiler only ever sees already-capped operations.
//!
//! **STEP 1 (scaffold + rule_id registry).** Steps 0–1 stand up the crate, the [`rules`] namespace
//! registry (G1/G7 — structural, not by convention) and a working `GraphqlSchemaModule` proven on
//! the real `Pipeline`. The full multi-transport operation-extraction (mirroring the OPEN
//! `GraphqlModule::operations`), config wiring and boot-fatal schema load from a path land in
//! Steps 2–7. See the frozen plan (G1–G7).

use std::path::Path;

use apollo_compiler::ast::Document;
use apollo_compiler::validation::Valid;
use apollo_compiler::{ExecutableDocument, Schema};
use waf_core::{Config, Decision, ParsedBody, Phase, RequestContext, ScoreItem, Severity, WafModule};
use waf_normalizer::graphql::unwrap_query_envelope;

pub mod api_schema;
pub mod bot;
pub mod grpc;
pub mod rules;

pub use api_schema::{
    load_spec, normalize_schema_3_0, parse_spec, ApiSchemaEnforcementConfig, ApiSchemaModule,
    CompiledSpec, LoadedSpec, RequestParts, Resolution, Router, Violation,
};
pub use bot::{BotDetectionConfig, BotDetectionModule};
pub use grpc::{GrpcSchemaEnforcementConfig, GrpcSchemaModule};

/// Configuration for the GraphQL schema-enforcement module. The core `Config` carries no
/// enterprise fields, so the enterprise wiring builds this from `[enterprise.schema_enforcement]`
/// (Step 5) and hands it to [`GraphqlSchemaModule::from_config`].
#[derive(Debug, Clone)]
pub struct SchemaEnforcementConfig {
    /// Off by default → the module is inert (contributes nothing).
    pub enabled: bool,
    /// GraphQL endpoint path(s) this schema guards. Used by the multi-transport operation
    /// extraction (Step 3); the probe transport (`application/graphql` body) ignores it.
    pub paths: Vec<String>,
    /// PEM-less SDL schema file (`.graphql`) describing the app's real API.
    pub schema_path: std::path::PathBuf,
    /// Severity for a body that is not parseable as GraphQL (lower — broken client / generic probing).
    pub parse_error_severity: Severity,
    /// Severity for a syntactically valid query that violates the schema (Critical — targeted probing).
    pub unknown_field_severity: Severity,
}

impl Default for SchemaEnforcementConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            paths: vec!["/graphql".to_string()],
            schema_path: std::path::PathBuf::new(),
            parse_error_severity: Severity::Warning,
            unknown_field_severity: Severity::Critical,
        }
    }
}

/// How a GraphQL operation validates against the loaded schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpValidity {
    /// Parses and validates cleanly against the schema.
    Valid,
    /// Not even parseable as GraphQL (broken client / generic probing).
    ParseError,
    /// Parses as GraphQL, but fails validation against the app's real schema — an unknown
    /// field/type/argument (the canonical targeted-probing case) or any other schema-validation
    /// failure (undefined/unused variable, missing subselection…). A spec-compliant client never
    /// emits these and the real backend rejects them too, so it is not a false positive.
    SchemaInvalid,
}

/// Pure, re-entrant SDL parse+validate (G5 reload-readiness): SDL **text** → validated schema, no
/// global state, no I/O. The testable core of schema loading.
pub fn parse_schema(sdl: &str) -> Result<Valid<Schema>, String> {
    Schema::parse_and_validate(sdl, "schema.graphql").map_err(|e| e.errors.to_string())
}

/// Load and validate a schema **from a file** (G5 reload-ready entry point): read → [`parse_schema`].
/// Called at construction so the boot can fail-closed on a missing/invalid schema; the future core
/// `module_factory` will call the SAME function with keep-old-on-invalid (re-entrant, no side effects
/// beyond the read).
pub fn load_schema(path: &Path) -> Result<Valid<Schema>, String> {
    let sdl = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read schema file {}: {e}", path.display()))?;
    parse_schema(&sdl)
}

/// Validate one operation string against the schema, splitting parse-error from schema-invalid so
/// the two carry distinct severities (G3).
///
/// **Step-0 discovery**: `ExecutableDocument::parse` is schema-aware — it already rejects unknown
/// fields at parse time — so it cannot separate "not GraphQL syntax" from "valid GraphQL, wrong for
/// the schema". The clean split uses the pure-syntax AST parser (no schema) as the parse-error gate,
/// then `parse_and_validate` for everything schema-related.
pub fn validate_op(schema: &Valid<Schema>, op: &str) -> OpValidity {
    // Pure syntax gate (schema-free): a broken client / non-GraphQL body fails here.
    if Document::parse(op, "op.graphql").is_err() {
        return OpValidity::ParseError;
    }
    // Syntactically valid → does it validate against the app's real schema?
    match ExecutableDocument::parse_and_validate(schema, op, "op.graphql") {
        Ok(_) => OpValidity::Valid,
        Err(_) => OpValidity::SchemaInvalid,
    }
}

/// GraphQL schema-enforcement module. Holds the app's validated schema (immutable in-memory — no
/// hot-reload in v1, see G5) and validates each operation the request carries.
pub struct GraphqlSchemaModule {
    schema: Valid<Schema>,
    enabled: bool,
    /// GraphQL endpoint path(s): JSON/GET transports are inspected ONLY here, so a non-GraphQL JSON
    /// API with a `query` field is left alone (mirrors the OPEN Phase-11 gating). The
    /// `application/graphql` body is recognised by Content-Type on any path.
    paths: Vec<String>,
    parse_error_severity: Severity,
    unknown_field_severity: Severity,
}

impl GraphqlSchemaModule {
    /// Production constructor: load the schema from `cfg.schema_path`. **Boot-fatal** on a
    /// missing/invalid schema — `init(&Config)` gets the core config (no schema path) and returns
    /// `()`, so the fail-closed load MUST happen here at construction (like `ReputationModule`).
    pub fn from_config(cfg: &SchemaEnforcementConfig) -> Result<Self, String> {
        Ok(Self {
            schema: load_schema(&cfg.schema_path)?,
            enabled: cfg.enabled,
            paths: cfg.paths.clone(),
            parse_error_severity: cfg.parse_error_severity,
            unknown_field_severity: cfg.unknown_field_severity,
        })
    }

    /// Test/embedding constructor from inline SDL **text** (no file), using default config (paths
    /// `["/graphql"]`, severities Warning/Critical).
    pub fn from_sdl(sdl: &str, enabled: bool) -> Result<Self, String> {
        let cfg = SchemaEnforcementConfig { enabled, ..Default::default() };
        Ok(Self {
            schema: parse_schema(sdl)?,
            enabled: cfg.enabled,
            paths: cfg.paths,
            parse_error_severity: cfg.parse_error_severity,
            unknown_field_severity: cfg.unknown_field_severity,
        })
    }

    /// The GraphQL operation text(s) the request carries — a faithful mirror of the OPEN
    /// `GraphqlModule::operations` (Phase 11): `application/graphql` raw body by Content-Type on any
    /// path; a JSON `query` leaf (and batch `<i>.query`) and a GET `?query=` value ONLY on a
    /// configured GraphQL path. Empty ⇒ not a recognised GraphQL request → the module stays inert.
    fn operations(&self, ctx: &RequestContext) -> Vec<String> {
        let mut carriers = Vec::new();

        // `application/graphql` raw body — identified by Content-Type, any path. A single operation.
        if content_type(ctx).trim_start().starts_with("application/graphql") {
            if let ParsedBody::Raw(b) = &ctx.normalized.body {
                if let Ok(s) = std::str::from_utf8(b) {
                    carriers.push(s.to_string());
                }
            }
            return expand(carriers);
        }

        // JSON / GET transports: only on a configured GraphQL endpoint path.
        let path_match = self.paths.iter().any(|p| ctx.normalized.path.eq_ignore_ascii_case(p));
        if !path_match {
            return Vec::new();
        }
        if let ParsedBody::JsonFlattened(pairs) = &ctx.normalized.body {
            for (k, v) in pairs {
                if is_graphql_query_key(k) {
                    carriers.push(v.clone());
                }
            }
        }
        if ctx.method.eq_ignore_ascii_case("GET") {
            for (k, v) in &ctx.normalized.query_params {
                if k == "query" {
                    carriers.push(v.clone());
                }
            }
        }
        expand(carriers)
    }
}

/// Expand each carrier into the operation(s) the validator must see: a carrier that is a JSON
/// envelope `{"query":"<doc>"}` is unwrapped to the inner document(s); any other carrier (a bare
/// GraphQL document, `application/graphql` body, or already-extracted JSON leaf) is used as-is.
/// Reuses the OPEN `unwrap_query_envelope` so extraction never diverges from the Phase-11 module.
fn expand(carriers: Vec<String>) -> Vec<String> {
    let mut out = Vec::with_capacity(carriers.len());
    for c in carriers {
        match unwrap_query_envelope(&c) {
            Some(docs) => out.extend(docs),
            None => out.push(c),
        }
    }
    out
}

fn content_type(ctx: &RequestContext) -> &str {
    ctx.normalized
        .headers
        .iter()
        .find(|(k, _)| k == "content-type")
        .map(|(_, v)| v.as_str())
        .unwrap_or("")
}

/// A flattened-JSON key that holds a GraphQL operation: the top-level `query`, or a batch element
/// `<index>.query`. NOT an arbitrary `*.query` (e.g. a variable named `query` nested under
/// `variables`). Re-derived from the OPEN module (where it is private).
fn is_graphql_query_key(k: &str) -> bool {
    if k == "query" {
        return true;
    }
    match k.strip_suffix(".query") {
        Some(prefix) => !prefix.is_empty() && prefix.bytes().all(|b| b.is_ascii_digit()),
        None => false,
    }
}

impl WafModule for GraphqlSchemaModule {
    fn id(&self) -> &str {
        "schema-graphql"
    }

    fn phase(&self) -> Phase {
        Phase::Body
    }

    /// Structural: its verdict is not a content-rule match, so the content fast-path must not skip
    /// it (lesson of Phase 11).
    fn structural(&self) -> bool {
        true
    }

    fn init(&mut self, _cfg: &Config) {}

    fn inspect(&self, ctx: &RequestContext) -> Decision {
        if !self.enabled {
            return Decision::Allow;
        }
        let ops = self.operations(ctx);
        if ops.is_empty() {
            return Decision::Allow;
        }
        // Dedup the signal by kind: a batch of N schema-invalid operations is one probing signal,
        // not N — so we emit at most one `parse-error` and one `unknown-field` contribution
        // regardless of batch size (bounded contribution; the OPEN Phase-11 cap bounds batch size
        // upstream anyway). We still scan every operation so any single violation is caught.
        let mut parse_error = false;
        let mut schema_invalid = false;
        for op in &ops {
            match validate_op(&self.schema, op) {
                OpValidity::Valid => {}
                OpValidity::ParseError => parse_error = true,
                OpValidity::SchemaInvalid => schema_invalid = true,
            }
        }
        let mut items = Vec::new();
        if parse_error {
            items.push(ScoreItem {
                rule_id: rules::GRAPHQL_PARSE_ERROR.id(),
                severity: self.parse_error_severity,
            });
        }
        if schema_invalid {
            items.push(ScoreItem {
                rule_id: rules::GRAPHQL_UNKNOWN_FIELD.id(),
                severity: self.unknown_field_severity,
            });
        }
        if items.is_empty() {
            Decision::Allow
        } else {
            Decision::Scores(items)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SDL: &str = r#"
        type Query { user(id: ID!): User }
        type User { id: ID!, name: String }
    "#;

    /// A unique temp path so parallel tests don't collide (no tempfile dep).
    fn temp_path(tag: &str) -> std::path::PathBuf {
        let uniq = format!(
            "waf-schema-{tag}-{}-{:?}.graphql",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        );
        std::env::temp_dir().join(uniq)
    }

    #[test]
    fn valid_schema_parses() {
        assert!(parse_schema(SDL).is_ok());
    }

    #[test]
    fn invalid_schema_is_rejected() {
        // `Query` references an undefined type.
        assert!(parse_schema("type Query { user: Undefined }").is_err());
    }

    #[test]
    fn valid_query_passes() {
        let schema = parse_schema(SDL).unwrap();
        assert_eq!(validate_op(&schema, "{ user(id: 1) { id name } }"), OpValidity::Valid);
    }

    #[test]
    fn unknown_field_is_schema_invalid() {
        let schema = parse_schema(SDL).unwrap();
        // `password` is not a field of `User` — a query the real client never sends.
        assert_eq!(
            validate_op(&schema, "{ user(id: 1) { id password } }"),
            OpValidity::SchemaInvalid
        );
    }

    #[test]
    fn broken_syntax_is_parse_error() {
        let schema = parse_schema(SDL).unwrap();
        assert_eq!(validate_op(&schema, "{ user(id: 1) {"), OpValidity::ParseError);
    }

    // ── Step 2: schema load from file + config-driven construction ──────────────

    #[test]
    fn load_schema_reads_and_validates_a_file() {
        let path = temp_path("ok");
        std::fs::write(&path, SDL).unwrap();
        let loaded = load_schema(&path);
        let _ = std::fs::remove_file(&path);
        assert!(loaded.is_ok());
    }

    #[test]
    fn load_schema_missing_file_is_err() {
        let path = temp_path("missing"); // never created
        assert!(load_schema(&path).is_err());
    }

    #[test]
    fn from_config_is_boot_fatal_on_invalid_schema() {
        let path = temp_path("bad");
        std::fs::write(&path, "type Query { user: Undefined }").unwrap();
        let cfg = SchemaEnforcementConfig { schema_path: path.clone(), ..Default::default() };
        let built = GraphqlSchemaModule::from_config(&cfg);
        let _ = std::fs::remove_file(&path);
        assert!(built.is_err(), "an invalid schema file must fail construction (fail-closed boot)");
    }

    #[test]
    fn from_config_builds_from_a_valid_file() {
        let path = temp_path("good");
        std::fs::write(&path, SDL).unwrap();
        let cfg = SchemaEnforcementConfig {
            enabled: true,
            schema_path: path.clone(),
            ..Default::default()
        };
        let built = GraphqlSchemaModule::from_config(&cfg);
        let _ = std::fs::remove_file(&path);
        assert!(built.is_ok());
    }

    #[test]
    fn default_config_is_off() {
        assert!(!SchemaEnforcementConfig::default().enabled);
    }

    // ── Step 3: multi-transport operation extraction ────────────────────────────

    use waf_core::{Bytes, Normalized, ParsedBody, RequestContext};

    fn ctx(
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: ParsedBody,
        query_params: &[(&str, &str)],
    ) -> RequestContext {
        let owned = |pairs: &[(&str, &str)]| -> Vec<(String, String)> {
            pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
        };
        let normalized = Normalized {
            path: path.to_string(),
            headers: owned(headers),
            query_params: owned(query_params),
            body,
            ..Default::default()
        };
        RequestContext {
            client_ip: "127.0.0.1".parse().unwrap(),
            request_id: "t".to_string(),
            timestamp: std::time::SystemTime::now(),
            method: method.to_string(),
            path: path.to_string(),
            raw_path: path.to_string(),
            query: None,
            http_version: "HTTP/1.1".to_string(),
            headers: vec![],
            cookies: vec![],
            body: Bytes::new(),
            normalized,
            score: 0,
            score_contributions: vec![],
        }
    }

    fn module() -> GraphqlSchemaModule {
        GraphqlSchemaModule::from_sdl(SDL, true).unwrap()
    }

    #[test]
    fn extracts_application_graphql_body_on_any_path() {
        let c = ctx(
            "POST",
            "/anything",
            &[("content-type", "application/graphql")],
            ParsedBody::Raw(Bytes::from("{ user(id: 1) { id } }")),
            &[],
        );
        assert_eq!(module().operations(&c), vec!["{ user(id: 1) { id } }".to_string()]);
    }

    #[test]
    fn extracts_json_query_leaf_only_on_graphql_path() {
        let body = ParsedBody::JsonFlattened(vec![("query".to_string(), "{ a }".to_string())]);
        // On the configured GraphQL path → extracted.
        let on = ctx("POST", "/graphql", &[], body.clone(), &[]);
        assert_eq!(module().operations(&on), vec!["{ a }".to_string()]);
        // On a non-GraphQL path → left alone (a JSON API with a `query` field is not GraphQL).
        let off = ctx("POST", "/api/search", &[], body, &[]);
        assert!(module().operations(&off).is_empty());
    }

    #[test]
    fn extracts_batched_query_leaves() {
        let body = ParsedBody::JsonFlattened(vec![
            ("0.query".to_string(), "{ a }".to_string()),
            ("1.query".to_string(), "{ b }".to_string()),
            // A nested variable named `query` must NOT be treated as an operation.
            ("variables.query".to_string(), "not an op".to_string()),
        ]);
        let c = ctx("POST", "/graphql", &[], body, &[]);
        assert_eq!(module().operations(&c), vec!["{ a }".to_string(), "{ b }".to_string()]);
    }

    #[test]
    fn extracts_get_query_param_and_unwraps_json_envelope() {
        // Bare document in ?query=.
        let bare = ctx("GET", "/graphql", &[], ParsedBody::None, &[("query", "{ a }")]);
        assert_eq!(module().operations(&bare), vec!["{ a }".to_string()]);
        // A JSON envelope carried in ?query= is unwrapped to the inner document (reuses OPEN helper).
        let env = ctx(
            "GET",
            "/graphql",
            &[],
            ParsedBody::None,
            &[("query", r#"{"query":"{ b }"}"#)],
        );
        assert_eq!(module().operations(&env), vec!["{ b }".to_string()]);
    }

    #[test]
    fn query_key_matching() {
        assert!(is_graphql_query_key("query"));
        assert!(is_graphql_query_key("0.query"));
        assert!(is_graphql_query_key("11.query"));
        assert!(!is_graphql_query_key("variables.query"));
        assert!(!is_graphql_query_key("a.query"));
        assert!(!is_graphql_query_key("query.sub"));
        assert!(!is_graphql_query_key(".query"));
    }

    // ── Step 6: FP-guard — legitimate GraphQL constructs must validate CLEAN ────
    // A richer schema so we can exercise aliases, fragments, variables, directives, lists.
    const RICH_SDL: &str = r#"
        type Query { user(id: ID!): User, me: User }
        type User { id: ID!, name: String, friends: [User!] }
    "#;

    /// Probe: discover apollo's verdict on a set of constructs, so a false positive on a real
    /// client's query can never slip into a schema-invalid score.
    #[test]
    fn legit_constructs_validate_clean() {
        let schema = parse_schema(RICH_SDL).unwrap();
        let legit = [
            ("plain", "{ user(id: 1) { id name } }"),
            ("field_alias", "{ current: user(id: 1) { id } me { id } }"),
            ("typename_meta", "{ user(id: 1) { __typename id } }"),
            ("named_fragment", "query { user(id: 1) { ...F } } fragment F on User { id name }"),
            ("inline_fragment", "{ user(id: 1) { ... on User { id } } }"),
            ("variables_used", "query($id: ID!) { user(id: $id) { id } }"),
            ("builtin_directive", "{ user(id: 1) { name @include(if: true) } }"),
            ("nested_list", "{ user(id: 1) { friends { id } } }"),
            ("introspection_schema", "{ __schema { queryType { name } } }"),
            ("introspection_type", r#"{ __type(name: "User") { name } }"#),
        ];
        for (name, q) in legit {
            assert_eq!(
                validate_op(&schema, q),
                OpValidity::Valid,
                "legit construct `{name}` must be Valid (no FP): {q}"
            );
        }
    }

    /// Documents the frozen verdict on spec-edge cases (probed empirically against apollo-compiler).
    /// All of these are genuine schema-validation failures that a spec-compliant client never emits
    /// and the real GraphQL backend rejects too — so flagging them is NOT a false positive. The one
    /// real FP source (schema drift: the app deployed a newer schema than the WAF's copy) is handled
    /// by G3 (Scores + tunable severity), not by loosening validation.
    #[test]
    fn spec_violations_are_flagged() {
        let schema = parse_schema(RICH_SDL).unwrap();
        for q in [
            "{ user(id: $nope) { id } }",                             // undefined variable
            "{ user(id: 1) }",                                        // missing subselection
            "query($x: ID!) { user(id: 1) { id } }",                 // unused variable
            "query { user(id: 1) { id } } fragment F on User { n }", // unused + invalid fragment
        ] {
            assert_eq!(validate_op(&schema, q), OpValidity::SchemaInvalid, "must flag: {q}");
        }
        // Identical duplicate fields are valid (they merge) — must NOT be flagged.
        assert_eq!(validate_op(&schema, "{ user(id: 1) { id id } }"), OpValidity::Valid);
    }

    #[test]
    fn batch_of_invalid_ops_dedups_to_one_contribution() {
        // Two schema-invalid operations in one batch → a single `unknown-field` signal (bounded).
        let body = ParsedBody::JsonFlattened(vec![
            ("0.query".to_string(), "{ user(id: 1) { nope } }".to_string()),
            ("1.query".to_string(), "{ user(id: 1) { alsoNope } }".to_string()),
        ]);
        let c = ctx("POST", "/graphql", &[], body, &[]);
        match module().inspect(&c) {
            Decision::Scores(items) => {
                assert_eq!(items.len(), 1, "batch must yield one deduped contribution, not N");
                assert_eq!(items[0].rule_id, rules::GRAPHQL_UNKNOWN_FIELD.id());
            }
            other => panic!("expected Scores, got {other:?}"),
        }
    }
}
