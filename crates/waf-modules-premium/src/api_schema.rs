// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

//! API Security — OpenAPI **positive-security** (§4-B pt3). Validate each incoming REST/JSON request
//! against the app's REAL OpenAPI spec: a path/method/parameter/body shape the app's own contract
//! does not declare is a request a spec-compliant client never sends — a probing/abuse signal — so it
//! contributes to the SAME cumulative anomaly score the core already uses (`Decision::Scores`,
//! severity resolved by the pipeline). This is **governance of the contract**, NOT baseline detection:
//! value-level injection (SQLi/XSS in a parameter *value*) stays in the OPEN §6 channel.
//!
//! **STEP A1 (scaffold + spec load).** This step stands up the crate module, the [`rules::ApiSchema`]
//! namespace (A1) and the pure, boot-fatal spec load — including the OpenAPI **3.0 → JSON-Schema
//! normalization** that A0 proved necessary (`jsonschema` does not understand 3.0's `nullable`, so a
//! nullable field set to `null` would be a false positive). The path router (A2), per-operation
//! parameter/body validation (A3) and the [`waf_core::WafModule`] impl (A4) land in later steps.
//!
//! [`rules::ApiSchema`]: crate::rules::Namespace::ApiSchema

use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};

use jsonschema::error::ValidationErrorKind;
use jsonschema::Validator;
use serde_json::Value;
use waf_core::{Config, Decision, Phase, RequestContext, ScoreItem, Severity, WafModule};

/// Configuration for the API schema-enforcement module. The core `Config` carries no enterprise
/// fields, so the enterprise wiring builds this from `[enterprise.api_schema]` (A5) and hands it to
/// the module constructor (A4).
#[derive(Debug, Clone)]
pub struct ApiSchemaEnforcementConfig {
    /// Off by default → the module is inert (contributes nothing).
    pub enabled: bool,
    /// Path prefix(es) this module guards. A request whose path starts with none of these is left
    /// alone, so a non-API surface (static assets, a different app) is never measured against the
    /// spec. Empty ⇒ guard nothing (still inert).
    pub paths: Vec<String>,
    /// The app's OpenAPI 3.0/3.1 spec, as a **JSON** file (v1 is JSON-only — see A0: the YAML path
    /// would pull a c2rust-transpiled libyaml, deliberately avoided).
    pub spec_path: PathBuf,
    /// Severity for a request to an endpoint/method the spec does not declare (higher — targeted
    /// probing, the strong signal).
    pub unknown_route_severity: Severity,
    /// Severity for a request to a KNOWN operation that violates its contract (param/body shape).
    /// Lower/tunable because schema drift (app deployed a newer spec than the WAF's copy) is the one
    /// legitimate source of these — handled by severity, not by loosening validation.
    pub violation_severity: Severity,
    /// Flag query/header parameters not declared for the operation (`schema-api-unknown-param`).
    pub strict_params: bool,
    /// Enforce `additionalProperties:false` on the request body (`schema-api-unknown-property`) even
    /// where the spec is silent. When false, only violations the spec itself declares are flagged.
    pub strict_body: bool,
}

impl Default for ApiSchemaEnforcementConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            paths: vec!["/api".to_string()],
            spec_path: PathBuf::new(),
            unknown_route_severity: Severity::Critical,
            violation_severity: Severity::Warning,
            strict_params: true,
            strict_body: true,
        }
    }
}

/// A parsed, structurally-valid OpenAPI spec held in memory (immutable — no hot-reload in v1; the
/// core `module_factory` re-runs the load on SIGHUP, A5). The spec is kept as raw JSON so the router
/// (A2) and validation (A3) navigate it and hand JSON-Schema fragments straight to `jsonschema`.
#[derive(Debug, Clone)]
pub struct LoadedSpec {
    /// The whole spec document, as JSON. `#/components/...` `$ref`s resolve within this one resource
    /// (no HTTP/file retriever — A0: `jsonschema` with `default-features = false`).
    pub doc: Value,
    /// True when the `openapi` version is `3.0.x`. Drives the [`normalize_schema_3_0`] pass at
    /// schema-compile time (A3): 3.0 is a JSON-Schema *dialect*, 3.1 is draft-2020-12 proper.
    pub is_3_0: bool,
    /// Path router built from the spec's `paths` (A2): resolves a request (path, method) to a declared
    /// operation, or to [`Resolution::UnknownRoute`] / [`Resolution::MethodNotAllowed`].
    pub router: Router,
}

/// Pure, re-entrant spec parse+structural-validate (A5 reload-readiness): spec **JSON text** →
/// [`LoadedSpec`], no global state, no I/O. `oas3` is the structural gate (it covers OpenAPI 3.0 AND
/// 3.1); the raw JSON is retained for navigation. Boot-fatal at the caller on `Err`.
pub fn parse_spec(json: &str) -> Result<LoadedSpec, String> {
    // Structural gate: must deserialize as a well-formed OpenAPI 3.x document.
    oas3::from_json(json).map_err(|e| format!("invalid OpenAPI spec: {e}"))?;
    let doc: Value = serde_json::from_str(json).map_err(|e| format!("spec is not valid JSON: {e}"))?;
    let is_3_0 = doc
        .get("openapi")
        .and_then(Value::as_str)
        .is_some_and(|v| v.starts_with("3.0"));
    let router = Router::build(&doc);
    Ok(LoadedSpec { doc, is_3_0, router })
}

/// Load and structurally-validate a spec **from a file** (A5 reload-ready entry point): read →
/// [`parse_spec`]. Called at construction so the boot can fail-closed on a missing/invalid spec.
pub fn load_spec(path: &Path) -> Result<LoadedSpec, String> {
    let json = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read OpenAPI spec {}: {e}", path.display()))?;
    parse_spec(&json)
}

/// Convert an OpenAPI **3.0** Schema Object (a JSON-Schema *dialect*) into standard JSON Schema that
/// `jsonschema` validates correctly. A0 proved this is not cosmetic: `jsonschema` ignores 3.0's
/// `nullable` keyword, so a `nullable:true` field carrying `null` is otherwise a false positive
/// ("null is not of type string"). Also normalizes 3.0's boolean `exclusiveMinimum/Maximum` to the
/// numeric 2020-12 form. Recurses into every nested schema; idempotent and a no-op on 3.1 schemas.
pub fn normalize_schema_3_0(v: &mut Value) {
    match v {
        Value::Object(map) => {
            // `nullable: true`  →  admit `null` in `type`.
            if map.get("nullable") == Some(&Value::Bool(true)) {
                if let Some(t) = map.get_mut("type") {
                    add_null_to_type(t);
                }
            }
            map.remove("nullable");
            // 3.0 `exclusiveMinimum/Maximum` are booleans paired with `minimum/maximum`; 2020-12
            // makes them the numeric bound itself.
            fix_exclusive_bound(map, "exclusiveMinimum", "minimum");
            fix_exclusive_bound(map, "exclusiveMaximum", "maximum");
            for child in map.values_mut() {
                normalize_schema_3_0(child);
            }
        }
        Value::Array(items) => {
            for child in items {
                normalize_schema_3_0(child);
            }
        }
        _ => {}
    }
}

/// Widen a `type` (string or array) to also admit `"null"`.
fn add_null_to_type(t: &mut Value) {
    let null = Value::String("null".to_string());
    match t {
        Value::String(s) => {
            *t = Value::Array(vec![Value::String(std::mem::take(s)), null]);
        }
        Value::Array(arr) if !arr.contains(&null) => arr.push(null),
        _ => {}
    }
}

/// Rewrite a 3.0 boolean `exclusive*` keyword to the numeric 2020-12 form: `exclusiveMinimum:true`
/// with `minimum:N` becomes `exclusiveMinimum:N` (and drops `minimum`); `false` just drops the
/// boolean, leaving the inclusive bound in place.
fn fix_exclusive_bound(map: &mut serde_json::Map<String, Value>, excl: &str, bound: &str) {
    if let Some(Value::Bool(is_exclusive)) = map.get(excl).cloned() {
        map.remove(excl);
        if is_exclusive {
            if let Some(bound_val) = map.remove(bound) {
                map.insert(excl.to_string(), bound_val);
            }
        }
    }
}

// ── A2: path router ──────────────────────────────────────────────────────────────
// OpenAPI paths are templated (`/users/{id}`); a request path must resolve to the ONE most-specific
// declared operation. The router owns only owned data (no borrow of the spec doc), so it composes
// into the module state (A4) without self-referential lifetimes.

/// The OpenAPI path-item HTTP method keys. Everything else in a path item (`parameters`, `summary`,
/// `$ref`, `servers`, `description`…) is not an operation.
const HTTP_METHODS: &[&str] = &["get", "put", "post", "delete", "options", "head", "patch", "trace"];

/// One segment of a path template.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Seg {
    /// A literal segment, matched case-sensitively (OpenAPI paths are case-sensitive).
    Static(String),
    /// A `{name}` template segment, matching any single non-empty segment.
    Param(String),
}

/// One declared route: a path template + its declared HTTP methods.
#[derive(Debug, Clone)]
struct Route {
    template: String,
    segments: Vec<Seg>,
    methods: std::collections::BTreeSet<String>,
}

/// Outcome of resolving a request (path, method) against the spec.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolution {
    /// No path template matches the request path → targeted probing (Critical).
    UnknownRoute,
    /// The path matches an operation's template, but not for this HTTP method (Critical).
    MethodNotAllowed,
    /// A declared operation. `template` + `path_params` let A3 look up and validate the operation.
    Matched {
        /// The matched OpenAPI path template (key into `doc["paths"]`).
        template: String,
        /// `{name}` → observed value, for A3 path-parameter validation.
        path_params: Vec<(String, String)>,
    },
}

/// A path router built once from the spec (A2).
#[derive(Debug, Clone, Default)]
pub struct Router {
    /// Routes, pre-sorted most-specific first (static segments before template segments).
    routes: Vec<Route>,
}

impl Router {
    /// Build the router from an OpenAPI document's `paths`. Routes are ordered most-specific first,
    /// so the first matching route is the correct (most specific) one.
    pub fn build(doc: &Value) -> Self {
        let mut routes = Vec::new();
        if let Some(paths) = doc.get("paths").and_then(Value::as_object) {
            for (template, item) in paths {
                let Some(item) = item.as_object() else { continue };
                let methods: std::collections::BTreeSet<String> = HTTP_METHODS
                    .iter()
                    .filter(|m| item.contains_key(**m))
                    .map(|m| (*m).to_string())
                    .collect();
                if methods.is_empty() {
                    continue; // a path item with no operations declares no route
                }
                routes.push(Route { segments: parse_template(template), template: template.clone(), methods });
            }
        }
        // Most-specific first: compare the per-segment specificity vector (Static=0, Param=1), then
        // template text for a stable order.
        routes.sort_by(|a, b| {
            specificity(&a.segments).cmp(&specificity(&b.segments)).then(a.template.cmp(&b.template))
        });
        Self { routes }
    }

    /// Resolve a request path + HTTP method against the spec.
    pub fn resolve(&self, path: &str, method: &str) -> Resolution {
        let req = split_segments(path);
        let m = method.to_ascii_lowercase();
        for route in &self.routes {
            if let Some(path_params) = route.match_path(&req) {
                // The most-specific matching path decides; the method is checked on THAT path only.
                return if route.methods.contains(&m) {
                    Resolution::Matched { template: route.template.clone(), path_params }
                } else {
                    Resolution::MethodNotAllowed
                };
            }
        }
        Resolution::UnknownRoute
    }
}

impl Route {
    /// Match this route's template against request segments, extracting path params on success.
    fn match_path(&self, req: &[&str]) -> Option<Vec<(String, String)>> {
        if self.segments.len() != req.len() {
            return None;
        }
        let mut params = Vec::new();
        for (seg, val) in self.segments.iter().zip(req) {
            match seg {
                Seg::Static(s) if s == val => {}
                Seg::Static(_) => return None,
                Seg::Param(_) if val.is_empty() => return None,
                Seg::Param(name) => params.push((name.clone(), (*val).to_string())),
            }
        }
        Some(params)
    }
}

/// Split a path into non-empty segments (a stray query/fragment is dropped, and trailing/duplicate
/// slashes are ignored — a WAF should treat `/users` and `/users/` as the same resource).
fn split_segments(path: &str) -> Vec<&str> {
    let path = path.split(['?', '#']).next().unwrap_or(path);
    path.split('/').filter(|s| !s.is_empty()).collect()
}

/// Parse a template into segments: a fully `{...}`-wrapped segment is a param, everything else is a
/// literal.
fn parse_template(template: &str) -> Vec<Seg> {
    split_segments(template)
        .into_iter()
        .map(|s| match s.strip_prefix('{').and_then(|inner| inner.strip_suffix('}')) {
            Some(name) if !name.is_empty() => Seg::Param(name.to_string()),
            _ => Seg::Static(s.to_string()),
        })
        .collect()
}

/// Per-segment specificity vector: Static=0, Param=1. Lexicographically smaller = more specific.
fn specificity(segs: &[Seg]) -> Vec<u8> {
    segs.iter().map(|s| u8::from(matches!(s, Seg::Param(_)))).collect()
}

// ── A3: parameter + body validation ──────────────────────────────────────────────
// A matched operation (A2) is validated against its contract: declared parameters (path/query/header)
// and the JSON request body, via `jsonschema`. Schemas are compiled ONCE at load (boot-fatal on a
// schema that won't compile), with the OpenAPI 3.0 → JSON-Schema normalization (A0) applied so 3.0
// `nullable` never yields a false positive.

/// A contract violation of a matched operation. Route/method mismatches come from the router
/// ([`Resolution`]); these are the per-operation contract failures. `Ord` so a request's violations
/// dedup into a set — one score contribution per kind (the batch-dedup discipline of §4-B).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Violation {
    /// A query parameter not declared for the operation (`strict_params`).
    UnknownParam,
    /// A required parameter or body (or required body property) is absent.
    MissingRequired,
    /// A parameter/body value fails its schema (type/format/enum/range).
    TypeViolation,
    /// A body property the schema does not permit (`additionalProperties`/`unevaluatedProperties`).
    UnknownProperty,
    /// The request Content-Type is not one the operation declares.
    ContentType,
    /// The body is JSON per its Content-Type but does not parse.
    BodyParseError,
}

impl Violation {
    /// The registry rule this violation emits (A4 turns it into a `ScoreItem`).
    pub fn rule(self) -> crate::rules::Rule {
        use crate::rules;
        match self {
            Violation::UnknownParam => rules::API_UNKNOWN_PARAM,
            Violation::MissingRequired => rules::API_MISSING_REQUIRED,
            Violation::TypeViolation => rules::API_TYPE_VIOLATION,
            Violation::UnknownProperty => rules::API_UNKNOWN_PROPERTY,
            Violation::ContentType => rules::API_CONTENT_TYPE,
            Violation::BodyParseError => rules::API_BODY_PARSE_ERROR,
        }
    }
}

/// The already-extracted request data A3 validates (A4 fills this from the `RequestContext`).
pub struct RequestParts<'a> {
    /// `{name}` → value, from the router match ([`Resolution::Matched`]).
    pub path_params: &'a [(String, String)],
    /// Query parameters, in order.
    pub query_params: &'a [(String, String)],
    /// Request headers, names lowercased.
    pub headers: &'a [(String, String)],
    /// The request Content-Type header value, if any.
    pub content_type: Option<&'a str>,
    /// The raw request body, if any.
    pub body: Option<&'a [u8]>,
}

/// Where a declared parameter lives (v1 covers path/query/header; `cookie` is out of scope).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParamIn {
    Path,
    Query,
    Header,
}

/// A scalar `type` we validate by coercing the (string) wire value into it. Array/object parameters
/// are presence-only in v1 (style/explode of collection params would risk false positives).
#[derive(Debug, Clone, Copy)]
enum ScalarType {
    Integer,
    Number,
    Boolean,
    String,
}

/// A compiled declared parameter.
struct CompiledParam {
    name: String,
    location: ParamIn,
    required: bool,
    scalar: Option<ScalarType>,
    validator: Option<Validator>,
}

/// A compiled request body.
struct CompiledBody {
    required: bool,
    /// Declared media types (lowercased, parameters stripped).
    media_types: Vec<String>,
    /// Validator for the JSON media type's schema (`None` ⇒ no JSON schema to enforce).
    json: Option<Validator>,
}

/// A compiled operation: its declared parameters and request body.
struct CompiledOp {
    params: Vec<CompiledParam>,
    body: Option<CompiledBody>,
}

/// A fully compiled spec: the A2 router + per-operation compiled parameter/body validators. Built
/// once (boot-fatal on a schema `jsonschema` cannot compile), then validates each request cheaply.
pub struct CompiledSpec {
    router: Router,
    strict_params: bool,
    ops: HashMap<(String, String), CompiledOp>,
}

impl CompiledSpec {
    /// Compile every operation's parameter + body schemas. **Boot-fatal** on a schema that won't
    /// compile — surfaces a broken spec at boot, like the GraphQL/gRPC modules.
    pub fn compile(spec: &LoadedSpec, cfg: &ApiSchemaEnforcementConfig) -> Result<Self, String> {
        let doc = &spec.doc;
        let mut ops = HashMap::new();
        if let Some(paths) = doc.get("paths").and_then(Value::as_object) {
            for (template, item) in paths {
                let Some(item_obj) = item.as_object() else { continue };
                let shared = item_obj.get("parameters");
                for m in HTTP_METHODS {
                    let Some(op) = item_obj.get(*m) else { continue };
                    let compiled = compile_op(doc, op, shared, spec.is_3_0, cfg.strict_body)
                        .map_err(|e| format!("{} {template}: {e}", m.to_uppercase()))?;
                    ops.insert((template.clone(), (*m).to_string()), compiled);
                }
            }
        }
        Ok(Self { router: spec.router.clone(), strict_params: cfg.strict_params, ops })
    }

    /// Resolve a request path+method (delegates to the A2 router).
    pub fn resolve(&self, path: &str, method: &str) -> Resolution {
        self.router.resolve(path, method)
    }

    /// Validate a matched operation's request against its contract, returning a deduped set of
    /// violations (one per kind). `template`/`method` come from a [`Resolution::Matched`].
    pub fn validate(&self, template: &str, method: &str, req: &RequestParts) -> BTreeSet<Violation> {
        let mut out = BTreeSet::new();
        let Some(op) = self.ops.get(&(template.to_string(), method.to_ascii_lowercase())) else {
            return out;
        };

        // ── parameters ──
        for p in &op.params {
            let observed = match p.location {
                ParamIn::Path => find(req.path_params, &p.name, false),
                ParamIn::Query => find(req.query_params, &p.name, false),
                ParamIn::Header => find(req.headers, &p.name, true),
            };
            match observed {
                None if p.required => {
                    out.insert(Violation::MissingRequired);
                }
                None => {}
                Some(val) => {
                    if let (Some(scalar), Some(v)) = (p.scalar, &p.validator) {
                        if !v.is_valid(&coerce(val, scalar)) {
                            out.insert(Violation::TypeViolation);
                        }
                    }
                }
            }
        }

        // ── unknown query parameters ──
        if self.strict_params {
            let declared: Vec<&str> = op
                .params
                .iter()
                .filter(|p| p.location == ParamIn::Query)
                .map(|p| p.name.as_str())
                .collect();
            if req.query_params.iter().any(|(k, _)| !declared.contains(&k.as_str())) {
                out.insert(Violation::UnknownParam);
            }
        }

        // ── request body ──
        if let Some(body) = &op.body {
            let present = req.body.is_some_and(|b| !b.is_empty());
            if !present {
                if body.required {
                    out.insert(Violation::MissingRequired);
                }
            } else {
                let ct = req.content_type.map(media_type_key).unwrap_or_default();
                if !body.media_types.is_empty()
                    && !body.media_types.iter().any(|m| m.as_str() == ct || m == "*/*")
                {
                    out.insert(Violation::ContentType);
                }
                if is_json_media_type(&ct) {
                    if let Some(v) = &body.json {
                        match serde_json::from_slice::<Value>(req.body.unwrap()) {
                            Err(_) => {
                                out.insert(Violation::BodyParseError);
                            }
                            Ok(instance) => {
                                for err in v.iter_errors(&instance) {
                                    out.insert(classify(err.kind()));
                                }
                            }
                        }
                    }
                }
            }
        }
        out
    }
}

/// Find a parameter value by name (case-insensitively for headers).
fn find<'a>(pairs: &'a [(String, String)], name: &str, ci: bool) -> Option<&'a str> {
    pairs
        .iter()
        .find(|(k, _)| if ci { k.eq_ignore_ascii_case(name) } else { k == name })
        .map(|(_, v)| v.as_str())
}

/// Map a failing JSON-Schema keyword to a violation kind.
fn classify(kind: &ValidationErrorKind) -> Violation {
    match kind {
        ValidationErrorKind::AdditionalProperties { .. }
        | ValidationErrorKind::UnevaluatedProperties { .. } => Violation::UnknownProperty,
        ValidationErrorKind::Required { .. } => Violation::MissingRequired,
        _ => Violation::TypeViolation,
    }
}

/// Coerce a string wire value into the parameter's declared scalar type so JSON-Schema type/format
/// checks apply. A value that will not parse is left as a string, which the validator then flags.
fn coerce(val: &str, scalar: ScalarType) -> Value {
    match scalar {
        ScalarType::String => Value::String(val.to_string()),
        ScalarType::Boolean => match val {
            "true" => Value::Bool(true),
            "false" => Value::Bool(false),
            _ => Value::String(val.to_string()),
        },
        ScalarType::Integer => {
            val.parse::<i64>().map(Value::from).unwrap_or_else(|_| Value::String(val.to_string()))
        }
        ScalarType::Number => val
            .parse::<f64>()
            .ok()
            .and_then(serde_json::Number::from_f64)
            .map(Value::Number)
            .unwrap_or_else(|| Value::String(val.to_string())),
    }
}

/// The media type without parameters, lowercased (`application/json; charset=utf-8` → `application/json`).
fn media_type_key(ct: &str) -> String {
    ct.split(';').next().unwrap_or("").trim().to_ascii_lowercase()
}

fn is_json_media_type(ct: &str) -> bool {
    ct == "application/json" || ct.ends_with("+json")
}

/// Compile one operation: merge path-item + operation parameters (operation wins on `(name, in)`),
/// then compile each parameter's + the request body's schema.
fn compile_op(
    doc: &Value,
    op: &Value,
    shared: Option<&Value>,
    is_3_0: bool,
    strict_body: bool,
) -> Result<CompiledOp, String> {
    let mut params = Vec::new();
    let mut seen: BTreeSet<(String, String)> = BTreeSet::new();
    // Operation-level parameters take precedence over path-item-level ones on the same `(name, in)`.
    for src in [op.get("parameters"), shared] {
        let Some(list) = src.and_then(Value::as_array) else { continue };
        for raw in list {
            let pobj = resolve_ref(doc, raw);
            let (Some(name), Some(loc)) =
                (pobj.get("name").and_then(Value::as_str), pobj.get("in").and_then(Value::as_str))
            else {
                continue;
            };
            let location = match loc {
                "path" => ParamIn::Path,
                "query" => ParamIn::Query,
                "header" => ParamIn::Header,
                _ => continue, // cookie & unknown: out of scope in v1
            };
            if !seen.insert((name.to_string(), loc.to_string())) {
                continue; // already defined at higher precedence
            }
            let required =
                loc == "path" || pobj.get("required").and_then(Value::as_bool).unwrap_or(false);
            let (scalar, validator) = match pobj.get("schema") {
                Some(schema) => {
                    let resolved = resolve_ref(doc, schema);
                    match scalar_type(resolved) {
                        Some(s) => (Some(s), Some(compile_validator(doc, resolved, is_3_0, false)?)),
                        None => (None, None), // array/object/absent → presence-only in v1
                    }
                }
                None => (None, None),
            };
            params.push(CompiledParam { name: name.to_string(), location, required, scalar, validator });
        }
    }

    let body = match op.get("requestBody") {
        Some(rb) => Some(compile_body(doc, resolve_ref(doc, rb), is_3_0, strict_body)?),
        None => None,
    };

    Ok(CompiledOp { params, body })
}

fn compile_body(
    doc: &Value,
    rb: &Value,
    is_3_0: bool,
    strict_body: bool,
) -> Result<CompiledBody, String> {
    let required = rb.get("required").and_then(Value::as_bool).unwrap_or(false);
    let mut media_types = Vec::new();
    let mut json = None;
    if let Some(content) = rb.get("content").and_then(Value::as_object) {
        for (mt, media) in content {
            let key = media_type_key(mt);
            if json.is_none() && is_json_media_type(&key) {
                if let Some(schema) = media.get("schema") {
                    json = Some(compile_validator(doc, resolve_ref(doc, schema), is_3_0, strict_body)?);
                }
            }
            media_types.push(key);
        }
    }
    Ok(CompiledBody { required, media_types, json })
}

/// The declared scalar `type`, if the schema is a scalar we validate.
fn scalar_type(schema: &Value) -> Option<ScalarType> {
    match schema.get("type").and_then(Value::as_str) {
        Some("integer") => Some(ScalarType::Integer),
        Some("number") => Some(ScalarType::Number),
        Some("boolean") => Some(ScalarType::Boolean),
        Some("string") => Some(ScalarType::String),
        _ => None,
    }
}

/// Compile a JSON-Schema fragment into a reusable validator: apply the 3.0 dialect normalization
/// (A0), optionally enforce `additionalProperties:false` (strict body), and attach the spec's
/// `components` so internal `$ref`s resolve within this one resource (no external retriever — A0).
fn compile_validator(
    doc: &Value,
    schema: &Value,
    is_3_0: bool,
    strict_object: bool,
) -> Result<Validator, String> {
    let mut s = schema.clone();
    if strict_object {
        enforce_additional_properties(&mut s);
    }
    if let (Value::Object(map), Some(comps)) = (&mut s, doc.get("components")) {
        map.entry("components".to_string()).or_insert_with(|| comps.clone());
    }
    if is_3_0 {
        normalize_schema_3_0(&mut s);
    }
    jsonschema::validator_for(&s).map_err(|e| format!("schema does not compile: {e}"))
}

/// Enforce `additionalProperties:false` on a **top-level** plain object schema that is silent about
/// it (strict body). Guarded: never applied to a composed schema (`allOf`/`anyOf`/`oneOf`/`$ref`/
/// `not`), whose semantics an injected keyword would break.
fn enforce_additional_properties(s: &mut Value) {
    let Value::Object(map) = s else { return };
    let composed = ["allOf", "anyOf", "oneOf", "$ref", "not"].iter().any(|k| map.contains_key(*k));
    let is_object =
        map.get("type").and_then(Value::as_str) == Some("object") || map.contains_key("properties");
    if is_object && !composed && !map.contains_key("additionalProperties") {
        map.insert("additionalProperties".to_string(), Value::Bool(false));
    }
}

/// Follow an internal `$ref` chain (`#/...`) within the document; returns the node unchanged if it
/// carries no `$ref` or the pointer does not resolve. Bounded against pathological cycles.
fn resolve_ref<'a>(doc: &'a Value, mut node: &'a Value) -> &'a Value {
    for _ in 0..32 {
        match node.get("$ref").and_then(Value::as_str) {
            Some(r) => match r.strip_prefix('#').and_then(|p| doc.pointer(p)) {
                Some(target) => node = target,
                None => break,
            },
            None => break,
        }
    }
    node
}

// ── A4: the WafModule ─────────────────────────────────────────────────────────────
// The datapath module: injected via the core's `.add_module()` seam, `Phase::Body`, `structural()`.
// It mirrors the OPEN normalization — routing/gating on `ctx.normalized.path` (decoded, traversal-
// resolved: evasion-resistant), reading query/headers from `ctx.normalized`, and the JSON body from
// the raw `ctx.body` — then turns route/method/contract failures into additive `Decision::Scores`.

/// OpenAPI positive-security module. Holds the compiled spec (immutable in-memory — no hot-reload in
/// v1; the core `module_factory` re-runs `from_config` on SIGHUP, A5) and scores each request that
/// falls under a guarded path prefix.
pub struct ApiSchemaModule {
    compiled: CompiledSpec,
    enabled: bool,
    /// Path prefixes this module guards (a request outside them is left alone).
    paths: Vec<String>,
    unknown_route_severity: Severity,
    violation_severity: Severity,
}

impl ApiSchemaModule {
    /// Production constructor: load + compile the spec from `cfg.spec_path`. **Boot-fatal** on a
    /// missing/invalid/uncompilable spec (like the GraphQL/gRPC modules): `init(&Config)` gets the
    /// core config (no spec path), so the fail-closed load MUST happen here at construction.
    pub fn from_config(cfg: &ApiSchemaEnforcementConfig) -> Result<Self, String> {
        Self::build(load_spec(&cfg.spec_path)?, cfg)
    }

    /// Test/embedding constructor from inline spec **JSON text** (no file).
    pub fn from_spec_json(json: &str, cfg: &ApiSchemaEnforcementConfig) -> Result<Self, String> {
        Self::build(parse_spec(json)?, cfg)
    }

    fn build(spec: LoadedSpec, cfg: &ApiSchemaEnforcementConfig) -> Result<Self, String> {
        Ok(Self {
            compiled: CompiledSpec::compile(&spec, cfg)?,
            enabled: cfg.enabled,
            paths: cfg.paths.clone(),
            unknown_route_severity: cfg.unknown_route_severity,
            violation_severity: cfg.violation_severity,
        })
    }

    /// True when the (normalized) path falls under a guarded prefix.
    fn guards(&self, path: &str) -> bool {
        self.paths.iter().any(|p| path.starts_with(p.as_str()))
    }
}

/// One-item `Decision::Scores` for a route/method failure.
fn one(rule: crate::rules::Rule, severity: Severity) -> Decision {
    Decision::Scores(vec![ScoreItem { rule_id: rule.id(), severity }])
}

impl WafModule for ApiSchemaModule {
    fn id(&self) -> &str {
        "schema-api"
    }

    fn phase(&self) -> Phase {
        Phase::Body
    }

    /// Structural: its verdict is not a content-rule match, so the content fast-path must not skip it.
    fn structural(&self) -> bool {
        true
    }

    fn init(&mut self, _cfg: &Config) {}

    fn inspect(&self, ctx: &RequestContext) -> Decision {
        if !self.enabled {
            return Decision::Allow;
        }
        let path = ctx.normalized.path.as_str();
        if !self.guards(path) {
            return Decision::Allow;
        }
        match self.compiled.resolve(path, &ctx.method) {
            Resolution::UnknownRoute => {
                one(crate::rules::API_UNKNOWN_ROUTE, self.unknown_route_severity)
            }
            Resolution::MethodNotAllowed => {
                one(crate::rules::API_METHOD_NOT_ALLOWED, self.unknown_route_severity)
            }
            Resolution::Matched { template, path_params } => {
                let content_type = ctx
                    .normalized
                    .headers
                    .iter()
                    .find(|(k, _)| k == "content-type")
                    .map(|(_, v)| v.as_str());
                let body = (!ctx.body.is_empty()).then(|| ctx.body.as_ref());
                let req = RequestParts {
                    path_params: &path_params,
                    query_params: &ctx.normalized.query_params,
                    headers: &ctx.normalized.headers,
                    content_type,
                    body,
                };
                let violations = self.compiled.validate(&template, &ctx.method, &req);
                if violations.is_empty() {
                    Decision::Allow
                } else {
                    Decision::Scores(
                        violations
                            .into_iter()
                            .map(|v| ScoreItem { rule_id: v.rule().id(), severity: self.violation_severity })
                            .collect(),
                    )
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const SPEC_30: &str = r#"{
        "openapi": "3.0.3",
        "info": { "title": "t", "version": "1" },
        "paths": { "/users": { "post": { "responses": { "200": { "description": "ok" } } } } }
    }"#;

    const SPEC_31: &str = r#"{
        "openapi": "3.1.0",
        "info": { "title": "t", "version": "1" },
        "paths": {}
    }"#;

    fn temp_path(tag: &str) -> PathBuf {
        let uniq = format!(
            "waf-oas-{tag}-{}-{:?}.json",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        );
        std::env::temp_dir().join(uniq)
    }

    #[test]
    fn parses_a_valid_3_0_spec_and_flags_the_dialect() {
        let loaded = parse_spec(SPEC_30).expect("valid 3.0 spec");
        assert!(loaded.is_3_0, "3.0.x must be flagged for the normalization pass");
    }

    #[test]
    fn parses_a_valid_3_1_spec_without_the_3_0_flag() {
        let loaded = parse_spec(SPEC_31).expect("valid 3.1 spec");
        assert!(!loaded.is_3_0, "3.1 is draft-2020-12 — no dialect normalization needed");
    }

    #[test]
    fn rejects_non_json() {
        assert!(parse_spec("openapi: 3.0.3").is_err(), "YAML/non-JSON must be rejected (v1 JSON-only)");
    }

    #[test]
    fn rejects_a_structurally_invalid_spec() {
        // Valid JSON, but not an OpenAPI document (no `openapi`/`info`/`paths`).
        assert!(parse_spec(r#"{"not":"a spec"}"#).is_err());
    }

    #[test]
    fn default_config_is_off() {
        assert!(!ApiSchemaEnforcementConfig::default().enabled);
    }

    #[test]
    fn load_spec_reads_and_validates_a_file() {
        let path = temp_path("ok");
        std::fs::write(&path, SPEC_30).unwrap();
        let loaded = load_spec(&path);
        let _ = std::fs::remove_file(&path);
        assert!(loaded.is_ok());
    }

    #[test]
    fn load_spec_missing_file_is_err() {
        assert!(load_spec(&temp_path("missing")).is_err());
    }

    // ── OpenAPI 3.0 → JSON-Schema normalization (the A0 finding) ─────────────────

    #[test]
    fn nullable_string_becomes_a_type_union() {
        let mut s = json!({ "type": "string", "nullable": true });
        normalize_schema_3_0(&mut s);
        assert_eq!(s, json!({ "type": ["string", "null"] }));
    }

    #[test]
    fn nullable_is_applied_deep_in_nested_schemas() {
        let mut s = json!({
            "type": "object",
            "properties": {
                "user": {
                    "type": "object",
                    "properties": { "nickname": { "type": "string", "nullable": true } }
                }
            }
        });
        normalize_schema_3_0(&mut s);
        assert_eq!(
            s["properties"]["user"]["properties"]["nickname"],
            json!({ "type": ["string", "null"] })
        );
    }

    #[test]
    fn nullable_on_an_array_type_appends_null_once() {
        let mut s = json!({ "type": ["string", "integer"], "nullable": true });
        normalize_schema_3_0(&mut s);
        assert_eq!(s, json!({ "type": ["string", "integer", "null"] }));
        // Idempotent: a second pass must not append a second "null".
        normalize_schema_3_0(&mut s);
        assert_eq!(s, json!({ "type": ["string", "integer", "null"] }));
    }

    #[test]
    fn boolean_exclusive_minimum_becomes_numeric() {
        let mut s = json!({ "type": "integer", "minimum": 1, "exclusiveMinimum": true });
        normalize_schema_3_0(&mut s);
        assert_eq!(s, json!({ "type": "integer", "exclusiveMinimum": 1 }));

        // `false` keeps the inclusive bound and just drops the boolean.
        let mut inclusive = json!({ "type": "integer", "minimum": 1, "exclusiveMinimum": false });
        normalize_schema_3_0(&mut inclusive);
        assert_eq!(inclusive, json!({ "type": "integer", "minimum": 1 }));
    }

    #[test]
    fn a_3_1_schema_is_left_unchanged() {
        let original = json!({ "type": ["string", "null"], "properties": { "n": { "type": "string" } } });
        let mut s = original.clone();
        normalize_schema_3_0(&mut s);
        assert_eq!(s, original, "a standard 2020-12 schema must be a no-op");
    }

    // ── A2: path router ─────────────────────────────────────────────────────────

    const ROUTER_SPEC: &str = r#"{
        "openapi": "3.0.3",
        "info": { "title": "t", "version": "1" },
        "paths": {
            "/users": {
                "get":  { "responses": { "200": { "description": "ok" } } },
                "post": { "responses": { "200": { "description": "ok" } } }
            },
            "/users/{id}": {
                "get":    { "responses": { "200": { "description": "ok" } } },
                "delete": { "responses": { "200": { "description": "ok" } } }
            },
            "/users/me": {
                "get": { "responses": { "200": { "description": "ok" } } }
            }
        }
    }"#;

    fn router() -> Router {
        parse_spec(ROUTER_SPEC).expect("valid spec").router
    }

    fn matched(template: &str, params: &[(&str, &str)]) -> Resolution {
        Resolution::Matched {
            template: template.to_string(),
            path_params: params.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
        }
    }

    #[test]
    fn resolves_static_route_and_method() {
        assert_eq!(router().resolve("/users", "GET"), matched("/users", &[]));
        assert_eq!(router().resolve("/users", "POST"), matched("/users", &[]));
    }

    #[test]
    fn method_not_declared_is_method_not_allowed() {
        assert_eq!(router().resolve("/users", "DELETE"), Resolution::MethodNotAllowed);
    }

    #[test]
    fn resolves_templated_route_and_extracts_path_param() {
        assert_eq!(router().resolve("/users/123", "GET"), matched("/users/{id}", &[("id", "123")]));
        assert_eq!(router().resolve("/users/123", "DELETE"), matched("/users/{id}", &[("id", "123")]));
    }

    #[test]
    fn static_route_beats_templated_at_same_position() {
        // `/users/me` (static) must win over `/users/{id}` (templated).
        assert_eq!(router().resolve("/users/me", "GET"), matched("/users/me", &[]));
        // And the method is checked on the STATIC path only: DELETE isn't declared there → 405,
        // even though `/users/{id}` would allow DELETE.
        assert_eq!(router().resolve("/users/me", "DELETE"), Resolution::MethodNotAllowed);
    }

    #[test]
    fn unknown_path_and_wrong_arity_are_unknown_route() {
        assert_eq!(router().resolve("/nope", "GET"), Resolution::UnknownRoute);
        assert_eq!(router().resolve("/users/123/posts", "GET"), Resolution::UnknownRoute);
    }

    #[test]
    fn trailing_slash_is_ignored_but_case_is_significant() {
        assert_eq!(router().resolve("/users/", "GET"), matched("/users", &[]));
        // OpenAPI paths are case-sensitive: `/Users` is a different (undeclared) resource.
        assert_eq!(router().resolve("/Users", "GET"), Resolution::UnknownRoute);
    }

    #[test]
    fn method_matching_is_case_insensitive() {
        assert_eq!(router().resolve("/users", "get"), matched("/users", &[]));
    }

    // ── A3: parameter + body validation ─────────────────────────────────────────

    // A 3.0 spec exercising: a typed path param, a typed optional query param, and a $ref'd JSON body
    // with a required field, additionalProperties:false, a constrained integer, and a NULLABLE field.
    const VALIDATION_SPEC: &str = r##"{
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
                        "age": { "type": "integer", "minimum": 0 },
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
                "get": {
                    "parameters": [
                        { "name": "verbose", "in": "query", "required": false, "schema": { "type": "boolean" } }
                    ],
                    "responses": { "200": { "description": "ok" } }
                },
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

    fn compiled() -> CompiledSpec {
        let spec = parse_spec(VALIDATION_SPEC).expect("valid spec");
        CompiledSpec::compile(&spec, &ApiSchemaEnforcementConfig::default()).expect("compiles")
    }

    fn v(items: &[Violation]) -> BTreeSet<Violation> {
        items.iter().copied().collect()
    }

    fn post_body(spec: &CompiledSpec, ct: &str, body: &str) -> BTreeSet<Violation> {
        let pp = vec![("id".to_string(), "1".to_string())];
        let req = RequestParts {
            path_params: &pp,
            query_params: &[],
            headers: &[],
            content_type: Some(ct),
            body: Some(body.as_bytes()),
        };
        spec.validate("/users/{id}", "post", &req)
    }

    fn get_users(spec: &CompiledSpec, id: &str, query: &[(&str, &str)]) -> BTreeSet<Violation> {
        match spec.resolve(&format!("/users/{id}"), "GET") {
            Resolution::Matched { template, path_params } => {
                let q: Vec<(String, String)> =
                    query.iter().map(|(k, val)| (k.to_string(), val.to_string())).collect();
                let req = RequestParts {
                    path_params: &path_params,
                    query_params: &q,
                    headers: &[],
                    content_type: None,
                    body: None,
                };
                spec.validate(&template, "get", &req)
            }
            other => panic!("expected Matched, got {other:?}"),
        }
    }

    #[test]
    fn compile_is_boot_fatal_on_a_broken_schema() {
        // An invalid regex `pattern`: structurally fine to oas3 (just a string), but `jsonschema`
        // fails to compile the regex → the compile step must surface it as boot-fatal.
        let broken = r#"{
            "openapi": "3.0.3", "info": { "title": "t", "version": "1" },
            "paths": { "/x": { "get": {
                "parameters": [ { "name": "q", "in": "query", "schema": { "type": "string", "pattern": "[" } } ],
                "responses": { "200": { "description": "ok" } }
            } } }
        }"#;
        let spec = parse_spec(broken).expect("spec parses structurally");
        assert!(
            CompiledSpec::compile(&spec, &ApiSchemaEnforcementConfig::default()).is_err(),
            "a parameter schema jsonschema cannot compile must be boot-fatal"
        );
    }

    #[test]
    fn valid_request_has_no_violations() {
        assert!(post_body(&compiled(), "application/json", r#"{"name":"ada","age":30}"#).is_empty());
        assert!(get_users(&compiled(), "5", &[("verbose", "true")]).is_empty());
    }

    #[test]
    fn nullable_body_field_set_to_null_is_clean() {
        // THE end-to-end proof that the 3.0 normalization is wired into compile: without it, `null`
        // on a `nullable:true` field would be a false TypeViolation.
        assert!(post_body(&compiled(), "application/json", r#"{"name":"ada","nickname":null}"#).is_empty());
    }

    #[test]
    fn missing_required_body_field_is_flagged() {
        assert_eq!(
            post_body(&compiled(), "application/json", r#"{"age":30}"#),
            v(&[Violation::MissingRequired])
        );
    }

    #[test]
    fn wrong_body_type_is_a_type_violation() {
        assert_eq!(
            post_body(&compiled(), "application/json", r#"{"name":123}"#),
            v(&[Violation::TypeViolation])
        );
    }

    #[test]
    fn unknown_body_property_is_flagged_via_additional_properties() {
        assert_eq!(
            post_body(&compiled(), "application/json", r#"{"name":"ada","isAdmin":true}"#),
            v(&[Violation::UnknownProperty])
        );
    }

    #[test]
    fn undeclared_content_type_is_flagged_and_body_not_json_validated() {
        // text/plain is not declared → ContentType; and not JSON, so no schema validation runs.
        assert_eq!(post_body(&compiled(), "text/plain", "hello"), v(&[Violation::ContentType]));
    }

    #[test]
    fn unparseable_json_body_is_a_parse_error() {
        assert_eq!(
            post_body(&compiled(), "application/json", "{not json"),
            v(&[Violation::BodyParseError])
        );
    }

    #[test]
    fn missing_required_body_altogether_is_flagged() {
        let pp = vec![("id".to_string(), "1".to_string())];
        let req = RequestParts {
            path_params: &pp,
            query_params: &[],
            headers: &[],
            content_type: None,
            body: None,
        };
        assert_eq!(compiled().validate("/users/{id}", "post", &req), v(&[Violation::MissingRequired]));
    }

    #[test]
    fn path_param_type_is_coerced_and_validated() {
        assert!(get_users(&compiled(), "5", &[]).is_empty());
        assert_eq!(get_users(&compiled(), "abc", &[]), v(&[Violation::TypeViolation]));
    }

    #[test]
    fn undeclared_query_param_is_flagged_when_strict() {
        assert_eq!(get_users(&compiled(), "5", &[("foo", "bar")]), v(&[Violation::UnknownParam]));
    }

    #[test]
    fn wrong_query_param_type_is_a_type_violation() {
        assert_eq!(
            get_users(&compiled(), "5", &[("verbose", "maybe")]),
            v(&[Violation::TypeViolation])
        );
    }

    #[test]
    fn strict_params_off_allows_undeclared_query_params() {
        let spec = parse_spec(VALIDATION_SPEC).unwrap();
        let cfg = ApiSchemaEnforcementConfig { strict_params: false, ..Default::default() };
        let compiled = CompiledSpec::compile(&spec, &cfg).unwrap();
        match compiled.resolve("/users/5", "GET") {
            Resolution::Matched { template, path_params } => {
                let q = vec![("foo".to_string(), "bar".to_string())];
                let req = RequestParts {
                    path_params: &path_params,
                    query_params: &q,
                    headers: &[],
                    content_type: None,
                    body: None,
                };
                assert!(compiled.validate(&template, "get", &req).is_empty());
            }
            other => panic!("expected Matched, got {other:?}"),
        }
    }
}
