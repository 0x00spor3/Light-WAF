// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

//! GraphQL structural protections (Phase 11).
//!
//! This is NOT content-inspection (injection inside arguments/variables is already
//! caught by the JSON-leaf / derived channel, §6) — it is a STRUCTURAL control like
//! `request_smuggling`: it enforces DoS/abuse caps on the SHAPE of the GraphQL
//! operation(s) a request carries — selection-set depth, alias/field/directive
//! counts, batch size — plus an optional introspection policy. The counts come from
//! the lexical [`graphql_lex`] pass (paren-aware depth, string/comment-skipping), so
//! the module does NOT join the content-rule prefilter union.
//!
//! Transports recognised (Phase-11 Step-0 probe): a JSON body `query` leaf (and the
//! `<i>.query` leaves of a batched array) and a GET `?query=` value — both ONLY on a
//! configured GraphQL path, so a non-GraphQL JSON API with a `query` field is left
//! alone — and an `application/graphql` raw body, recognised by Content-Type on any
//! path. Violations of the DoS caps → `Reject{400}`; blocked introspection → 403.

use waf_core::{Config, Decision, GraphqlConfig, ParsedBody, Phase, RequestContext, WafModule};
use waf_normalizer::graphql::{graphql_lex, unwrap_query_envelope};

#[derive(Default)]
pub struct GraphqlModule {
    cfg: GraphqlConfig,
}

impl GraphqlModule {
    pub fn new() -> Self {
        Self::default()
    }

    /// The GraphQL operation text(s) the request carries (empty = not a recognised
    /// GraphQL request → the module stays out of the way).
    fn operations(&self, ctx: &RequestContext) -> Vec<String> {
        // Raw carrier strings before envelope-unwrapping (see `expand`).
        let mut carriers = Vec::new();

        // `application/graphql` raw body — identified by Content-Type, any path. A
        // single operation (this media type does not batch).
        if content_type(ctx).trim_start().starts_with("application/graphql") {
            if let ParsedBody::Raw(b) = &ctx.normalized.body {
                if let Ok(s) = std::str::from_utf8(b) {
                    carriers.push(s.to_string());
                }
            }
            return expand(carriers);
        }

        // JSON / GET transports: only on a configured GraphQL endpoint path.
        let path_match = self
            .cfg
            .paths
            .iter()
            .any(|p| ctx.normalized.path.eq_ignore_ascii_case(p));
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

/// Expand each carrier into the operation(s) the lexer must see: a carrier that is a JSON
/// envelope `{"query":"<doc>"}` (gotestwaf's GET shape — the lexer would otherwise treat
/// the document as opaque string content) is unwrapped to the inner document(s); any other
/// carrier (a bare GraphQL document, `application/graphql` body, or already-extracted JSON
/// leaf) is lexed as-is.
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

/// A flattened-JSON key that holds a GraphQL operation: the top-level `query`, or a
/// batch element `<index>.query`. NOT an arbitrary `*.query` (e.g. a variable named
/// `query` nested under `variables`) — those must not be parsed as operations.
fn is_graphql_query_key(k: &str) -> bool {
    if k == "query" {
        return true;
    }
    match k.strip_suffix(".query") {
        Some(prefix) => !prefix.is_empty() && prefix.bytes().all(|b| b.is_ascii_digit()),
        None => false,
    }
}

fn reject(reason: &'static str) -> Decision {
    Decision::Reject {
        rule_id: "graphql".to_string(),
        reason: reason.to_string(),
        status: 400,
        retry_after: None,
    }
}

impl WafModule for GraphqlModule {
    fn id(&self) -> &str {
        "graphql"
    }

    fn phase(&self) -> Phase {
        Phase::Body
    }

    /// Structural: its caps are not content-rule matches, so the content fast-path
    /// must not skip it (else a GraphQL DoS with no content signature would bypass).
    fn structural(&self) -> bool {
        true
    }

    fn init(&mut self, cfg: &Config) {
        self.cfg = cfg.modules.graphql.clone();
    }

    fn inspect(&self, ctx: &RequestContext) -> Decision {
        if !self.cfg.enabled {
            return Decision::Allow;
        }
        let ops = self.operations(ctx);
        if ops.is_empty() {
            return Decision::Allow;
        }
        // Batch amplification (also bypasses per-request rate limits).
        if ops.len() as u32 > self.cfg.max_batch {
            return reject("graphql batch operation count exceeds limit");
        }
        for op in &ops {
            let st = graphql_lex(op);
            if st.max_depth > self.cfg.max_depth {
                return reject("graphql query nesting depth exceeds limit");
            }
            if st.aliases > self.cfg.max_aliases {
                return reject("graphql alias count exceeds limit");
            }
            if st.fields > self.cfg.max_fields {
                return reject("graphql field/complexity exceeds limit");
            }
            if st.directives > self.cfg.max_directives {
                return reject("graphql directive count exceeds limit");
            }
            if self.cfg.block_introspection && st.has_introspection {
                return Decision::Block {
                    rule_id: "graphql-introspection".to_string(),
                    reason: "graphql schema introspection is blocked".to_string(),
                };
            }
        }
        Decision::Allow
    }
}

#[cfg(test)]
mod tests {
    use super::is_graphql_query_key;

    #[test]
    fn query_key_matching() {
        // Operation-carrying keys.
        assert!(is_graphql_query_key("query")); // single operation
        assert!(is_graphql_query_key("0.query")); // batch element
        assert!(is_graphql_query_key("11.query"));
        // NOT operations: a variable/field named `query` nested elsewhere must be ignored.
        assert!(!is_graphql_query_key("variables.query"));
        assert!(!is_graphql_query_key("variables.filter.query"));
        assert!(!is_graphql_query_key("a.query"));
        assert!(!is_graphql_query_key("query.sub"));
        assert!(!is_graphql_query_key("operationName"));
        assert!(!is_graphql_query_key(".query"));
    }
}
