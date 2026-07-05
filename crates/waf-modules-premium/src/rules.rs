// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: BUSL-1.1

//! Central `rule_id` registry (G1 marker / G7 anti-double-count) — **structural, not by convention**.
//!
//! Every premium rule this crate can emit is declared here ONCE, under a [`Namespace`]. A premium
//! module never writes a `rule_id` string literal: it emits [`Rule::id`], whose value is *composed*
//! from the namespace prefix, so a leaf can neither drift out of its namespace nor collide with the
//! OPEN core's ids (which live outside the reserved `schema-*` prefix). The [`ALL`] table plus the
//! uniqueness test below make a collision a compile-of-tests failure, so it can't slip in silently.
//!
//! When §4-A (native premium signatures) and §4-B part 2 (gRPC schema-enforcement) land in this
//! crate, they add their leaves HERE (a new [`Namespace`] variant + entries in [`ALL`]) — the same
//! gate then covers them for free.

/// Reserved top-level `rule_id` prefixes owned by the premium tier. Disjoint from every OPEN core
/// id, so premium contributions to the cumulative anomaly score are always attributable to the tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Namespace {
    /// GraphQL schema-enforcement (§4-B): `schema-graphql-*`.
    GraphqlSchema,
    /// gRPC schema-enforcement (§4-B part 2): `schema-grpc-*`.
    GrpcSchema,
    /// Client-integrity / bot detection (§4-A): `bot-*`.
    Bot,
}

impl Namespace {
    /// The `rule_id` prefix for this namespace. `const` so it composes at declaration time.
    pub const fn prefix(self) -> &'static str {
        match self {
            Namespace::GraphqlSchema => "schema-graphql",
            Namespace::GrpcSchema => "schema-grpc",
            Namespace::Bot => "bot",
        }
    }
}

/// A single registered premium rule = a namespace + a leaf name. Construct ONLY via the `pub const`
/// entries below (fields are private): that keeps the registry the single source of truth.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rule {
    ns: Namespace,
    leaf: &'static str,
}

impl Rule {
    const fn new(ns: Namespace, leaf: &'static str) -> Self {
        Self { ns, leaf }
    }

    /// This rule's namespace.
    pub const fn namespace(self) -> Namespace {
        self.ns
    }

    /// The fully-qualified `rule_id` (`<prefix>-<leaf>`) emitted into `ScoreItem`. Composed from the
    /// namespace, so it is impossible to emit a premium id outside its namespace.
    pub fn id(self) -> String {
        format!("{}-{}", self.ns.prefix(), self.leaf)
    }
}

// ── The registry ────────────────────────────────────────────────────────────────
// §4-B GraphQL schema-enforcement. Two leaves with distinct severities (G3): a body that is not
// GraphQL at all (broken client / generic probing) vs a syntactically valid query that references
// something not in the schema (targeted probing).

/// Body is not parseable as a GraphQL operation (lower severity).
pub const GRAPHQL_PARSE_ERROR: Rule = Rule::new(Namespace::GraphqlSchema, "parse-error");
/// Valid GraphQL, but references a field/type/argument not in the app's schema (Critical).
pub const GRAPHQL_UNKNOWN_FIELD: Rule = Rule::new(Namespace::GraphqlSchema, "unknown-field");

// §4-B pt2 gRPC schema-enforcement. Protobuf is schema-less on the wire and tolerates unknown
// fields by design (forward-compat), so the leaves differ from GraphQL: the strong signal is an
// unknown RPC method, the parse-error analog is a message that won't decode, and unknown-field is
// opt-in (H3) because a newer client legitimately carries fields the WAF's descriptor lacks.

/// The `:path` (`/pkg.Service/Method`) is not in the compiled descriptor (Critical).
pub const GRPC_UNKNOWN_METHOD: Rule = Rule::new(Namespace::GrpcSchema, "unknown-method");
/// The message bytes do not decode against the RPC's input type (Warning — parse-error analog).
pub const GRPC_DECODE_ERROR: Rule = Rule::new(Namespace::GrpcSchema, "decode-error");
/// The message decodes but carries fields not in the descriptor (opt-in; forward-compat FP-prone).
pub const GRPC_UNKNOWN_FIELD: Rule = Rule::new(Namespace::GrpcSchema, "unknown-field");

// §4-A client-integrity / bot detection. Native cross-header heuristics (not content signatures,
// not UA-tool matching — that is the OPEN `scanner` module).

/// The UA advertises a modern browser but the request lacks the `sec-fetch-*` headers that browser
/// always sends → a client impersonating a browser (Critical).
pub const BOT_BROWSER_IMPERSONATION: Rule = Rule::new(Namespace::Bot, "browser-impersonation");

/// Every premium rule the crate can emit. Adding a rule = add it here (the uniqueness gate then
/// covers it). Consumed by the anti-double-count / coverage test.
pub const ALL: &[Rule] = &[
    GRAPHQL_PARSE_ERROR,
    GRAPHQL_UNKNOWN_FIELD,
    GRPC_UNKNOWN_METHOD,
    GRPC_DECODE_ERROR,
    GRPC_UNKNOWN_FIELD,
    BOT_BROWSER_IMPERSONATION,
];

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn every_rule_id_is_namespaced_and_unique() {
        let mut seen = HashSet::new();
        for rule in ALL {
            let id = rule.id();
            // Structural: the id always carries its namespace prefix, followed by a `-` and a leaf.
            let ns = rule.namespace().prefix();
            assert!(
                id.starts_with(ns) && id.len() > ns.len() + 1 && id.as_bytes()[ns.len()] == b'-',
                "{id} is not under its namespace prefix `{ns}-`"
            );
            // No two registered rules share an id.
            assert!(seen.insert(id.clone()), "duplicate rule_id in the registry: {id}");
        }
    }

    #[test]
    fn ids_are_the_expected_wire_strings() {
        assert_eq!(GRAPHQL_PARSE_ERROR.id(), "schema-graphql-parse-error");
        assert_eq!(GRAPHQL_UNKNOWN_FIELD.id(), "schema-graphql-unknown-field");
        assert_eq!(GRPC_UNKNOWN_METHOD.id(), "schema-grpc-unknown-method");
        assert_eq!(GRPC_DECODE_ERROR.id(), "schema-grpc-decode-error");
        assert_eq!(GRPC_UNKNOWN_FIELD.id(), "schema-grpc-unknown-field");
        assert_eq!(BOT_BROWSER_IMPERSONATION.id(), "bot-browser-impersonation");
    }
}
