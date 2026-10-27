// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

//! API attack-surface inventory (§4-B pt3 discovery). The control plane persists only **denied**
//! requests (`decision_events` = blocked/rejected), so this is an inventory of the endpoints that
//! appear in enforcement decisions — the API attack surface — NOT a full all-traffic inventory.
//!
//! Each observed endpoint is templated (variable-looking segments collapse to `{}`, so `/users/5`
//! and `/users/6` fold into `/users/{}`), aggregated, and classified against the app's OpenAPI spec:
//! `documented` (a declared operation that nonetheless drew blocks — contract violations or value
//! injection against a known API) vs `shadow` (an undeclared endpoint being hit — the strong
//! discovery signal). Without a spec the inventory is `unclassified`.
//!
//! **Core-free by design.** The control plane deliberately does NOT depend on `waf-core` (BOUNDARY:
//! it consumes the OPEN JSON contract, it does not link the datapath). So the path→route matcher
//! here is a standalone re-implementation of the datapath [`Router`] (waf-schema-enforcement A2), using
//! only `serde_json`. A future shared `waf-openapi` crate could unify the two — follow-on.
//!
//! [`Router`]: https://docs.rs/waf-schema-enforcement

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;
use serde_json::Value;
use time::OffsetDateTime;

/// The HTTP method keys an OpenAPI path item may declare.
const HTTP_METHODS: &[&str] = &["get", "put", "post", "delete", "options", "head", "patch", "trace"];

/// How an observed endpoint relates to the app's declared OpenAPI contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Classification {
    /// Observed path+method matches a declared operation (a known endpoint drawing blocks).
    Documented,
    /// Observed path+method matches no declared operation — an undeclared endpoint being hit.
    Shadow,
    /// No spec configured → not classified.
    Unclassified,
}

/// One aggregated observed endpoint (input from the store: per method + raw path).
#[derive(Debug, Clone)]
pub struct ObservedPath {
    pub method: String,
    pub path: String,
    pub hits: i64,
    pub first_seen: OffsetDateTime,
    pub last_seen: OffsetDateTime,
}

/// One inventoried endpoint (templated), aggregated across the observed raw paths, for the API.
#[derive(Debug, Clone, Serialize)]
pub struct EndpointEntry {
    pub method: String,
    /// The templated path (variable segments as `{}`).
    pub path: String,
    pub classification: Classification,
    pub hits: i64,
    #[serde(with = "time::serde::rfc3339")]
    pub first_seen: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub last_seen: OffsetDateTime,
}

/// One path segment of a declared route template.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Seg {
    Static(String),
    Param,
}

/// A declared route: its templated segments + declared HTTP methods.
#[derive(Debug, Clone)]
struct Route {
    segments: Vec<Seg>,
    methods: BTreeSet<String>,
}

/// The declared routes of an OpenAPI spec, for classifying observed paths. Standalone (serde_json
/// only) — mirrors the datapath `Router` so classification matches enforcement.
#[derive(Debug, Clone, Default)]
pub struct SpecRoutes {
    routes: Vec<Route>,
}

impl SpecRoutes {
    /// Parse the declared routes from an OpenAPI spec's `paths` (JSON text). `None` if the text is
    /// not valid JSON (the control plane logs and treats the inventory as unclassified).
    pub fn from_spec_json(json: &str) -> Option<Self> {
        let doc: Value = serde_json::from_str(json).ok()?;
        let mut routes = Vec::new();
        if let Some(paths) = doc.get("paths").and_then(Value::as_object) {
            for (template, item) in paths {
                let Some(item) = item.as_object() else { continue };
                let methods: BTreeSet<String> = HTTP_METHODS
                    .iter()
                    .filter(|m| item.contains_key(**m))
                    .map(|m| (*m).to_string())
                    .collect();
                if methods.is_empty() {
                    continue;
                }
                routes.push(Route { segments: parse_template(template), methods });
            }
        }
        // Most-specific first (Static=0, Param=1), so the first matching route is the right one.
        routes.sort_by_key(|r| specificity(&r.segments));
        Some(Self { routes })
    }

    /// Classify an observed (method, raw path) against the declared routes.
    pub fn classify(&self, method: &str, path: &str) -> Classification {
        let req = split_segments(path);
        let m = method.to_ascii_lowercase();
        for route in &self.routes {
            if route_matches(&route.segments, &req) {
                // Most-specific matching path decides; the method is checked on THAT path only.
                return if route.methods.contains(&m) {
                    Classification::Documented
                } else {
                    Classification::Shadow // path declared but not for this method → undeclared surface
                };
            }
        }
        Classification::Shadow
    }
}

/// Build the inventory: templatize + classify each observed endpoint, fold raw paths into one entry
/// per (method, template), and sort most-hit first.
pub fn build_inventory(observed: Vec<ObservedPath>, routes: Option<&SpecRoutes>) -> Vec<EndpointEntry> {
    let mut map: BTreeMap<(String, String), EndpointEntry> = BTreeMap::new();
    for o in observed {
        let classification =
            routes.map(|r| r.classify(&o.method, &o.path)).unwrap_or(Classification::Unclassified);
        let template = templatize(&o.path);
        let entry = map.entry((o.method.clone(), template.clone())).or_insert(EndpointEntry {
            method: o.method,
            path: template,
            classification,
            hits: 0,
            first_seen: o.first_seen,
            last_seen: o.last_seen,
        });
        entry.hits += o.hits;
        entry.classification = merge(entry.classification, classification);
        if o.first_seen < entry.first_seen {
            entry.first_seen = o.first_seen;
        }
        if o.last_seen > entry.last_seen {
            entry.last_seen = o.last_seen;
        }
    }
    let mut out: Vec<EndpointEntry> = map.into_values().collect();
    out.sort_by(|a, b| b.hits.cmp(&a.hits).then_with(|| a.path.cmp(&b.path)));
    out
}

/// Fold two classifications for the same templated endpoint: `documented` dominates `shadow`, and any
/// classification dominates `unclassified` (raw paths under one template should agree; defensive).
fn merge(a: Classification, b: Classification) -> Classification {
    use Classification::*;
    match (a, b) {
        (Documented, _) | (_, Documented) => Documented,
        (Shadow, _) | (_, Shadow) => Shadow,
        _ => Unclassified,
    }
}

/// Collapse variable-looking segments to `{}` so per-id paths fold into one endpoint template.
fn templatize(path: &str) -> String {
    let parts: Vec<&str> = split_segments(path);
    if parts.is_empty() {
        return "/".to_string();
    }
    let mut out = String::new();
    for p in parts {
        out.push('/');
        if is_variable_segment(p) {
            out.push_str("{}");
        } else {
            out.push_str(p);
        }
    }
    out
}

/// A segment that looks like an identifier value (numeric id, UUID, or a long hex token/hash).
fn is_variable_segment(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    let all_digits = s.bytes().all(|b| b.is_ascii_digit());
    let long_hex = s.len() >= 16 && s.bytes().all(|b| b.is_ascii_hexdigit());
    all_digits || long_hex || is_uuid(s)
}

/// RFC-4122 shape `8-4-4-4-12` hex.
fn is_uuid(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 36
        && b.iter().enumerate().all(|(i, &c)| match i {
            8 | 13 | 18 | 23 => c == b'-',
            _ => c.is_ascii_hexdigit(),
        })
}

fn split_segments(path: &str) -> Vec<&str> {
    let path = path.split(['?', '#']).next().unwrap_or(path);
    path.split('/').filter(|s| !s.is_empty()).collect()
}

fn parse_template(template: &str) -> Vec<Seg> {
    split_segments(template)
        .into_iter()
        .map(|s| match s.strip_prefix('{').and_then(|i| i.strip_suffix('}')) {
            Some(name) if !name.is_empty() => Seg::Param,
            _ => Seg::Static(s.to_string()),
        })
        .collect()
}

fn route_matches(segments: &[Seg], req: &[&str]) -> bool {
    if segments.len() != req.len() {
        return false;
    }
    segments.iter().zip(req).all(|(seg, val)| match seg {
        Seg::Static(s) => s == val,
        Seg::Param => !val.is_empty(),
    })
}

fn specificity(segs: &[Seg]) -> Vec<u8> {
    segs.iter().map(|s| u8::from(matches!(s, Seg::Param))).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SPEC: &str = r##"{
        "openapi": "3.0.3",
        "info": { "title": "t", "version": "1" },
        "paths": {
            "/api/users":        { "get": {}, "post": {} },
            "/api/users/{id}":   { "get": {}, "delete": {} },
            "/api/users/me":     { "get": {} }
        }
    }"##;

    fn ts(secs: i64) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(secs).unwrap()
    }

    fn obs(method: &str, path: &str, hits: i64, first: i64, last: i64) -> ObservedPath {
        ObservedPath { method: method.into(), path: path.into(), hits, first_seen: ts(first), last_seen: ts(last) }
    }

    #[test]
    fn templatize_collapses_ids_uuids_and_hashes() {
        assert_eq!(templatize("/api/users/5"), "/api/users/{}");
        assert_eq!(templatize("/api/users/550e8400-e29b-41d4-a716-446655440000"), "/api/users/{}");
        assert_eq!(templatize("/files/deadbeefdeadbeefcafe"), "/files/{}");
        // Non-variable segments and the leading/trailing slashes are preserved/normalized.
        assert_eq!(templatize("/api/users/me/"), "/api/users/me");
        assert_eq!(templatize("/"), "/");
    }

    #[test]
    fn classify_documented_shadow_and_method() {
        let r = SpecRoutes::from_spec_json(SPEC).unwrap();
        assert_eq!(r.classify("GET", "/api/users/5"), Classification::Documented);
        assert_eq!(r.classify("GET", "/api/users/me"), Classification::Documented); // static wins
        assert_eq!(r.classify("POST", "/api/users"), Classification::Documented);
        // Declared path, undeclared method → shadow (undeclared surface).
        assert_eq!(r.classify("DELETE", "/api/users"), Classification::Shadow);
        // Undeclared paths → shadow.
        assert_eq!(r.classify("GET", "/api/secrets"), Classification::Shadow);
        assert_eq!(r.classify("GET", "/api/users/5/tokens"), Classification::Shadow);
    }

    #[test]
    fn build_folds_ids_and_aggregates() {
        let r = SpecRoutes::from_spec_json(SPEC).unwrap();
        let observed = vec![
            obs("GET", "/api/users/5", 3, 100, 200),
            obs("GET", "/api/users/6", 2, 50, 150),   // folds into /api/users/{}
            obs("GET", "/api/secrets", 9, 10, 300),    // shadow
        ];
        let inv = build_inventory(observed, Some(&r));
        // Two templated endpoints; shadow first (most hits).
        assert_eq!(inv.len(), 2);
        assert_eq!(inv[0].path, "/api/secrets");
        assert_eq!(inv[0].classification, Classification::Shadow);
        assert_eq!(inv[0].hits, 9);
        let users = &inv[1];
        assert_eq!(users.path, "/api/users/{}");
        assert_eq!(users.classification, Classification::Documented);
        assert_eq!(users.hits, 5); // 3 + 2 folded
        assert_eq!(users.first_seen, ts(50)); // min across the folded rows
        assert_eq!(users.last_seen, ts(200)); // max
    }

    #[test]
    fn without_a_spec_entries_are_unclassified() {
        let inv = build_inventory(vec![obs("GET", "/api/users/5", 1, 1, 1)], None);
        assert_eq!(inv[0].classification, Classification::Unclassified);
        assert_eq!(inv[0].path, "/api/users/{}");
    }
}
