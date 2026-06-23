//! GraphQL structural-protection cases (Phase 11). The module is OFF by default in
//! production; the corpus harness enables it (with `block_introspection = true`) at
//! the default caps (depth 15, aliases 30, fields 1000, directives 50, batch 10).
//! Cases use `application/graphql` raw bodies (recognised by Content-Type, no path
//! needed). The JSON/GET/batch transports + path-gating are covered by the module
//! unit tests in `waf-detection/src/graphql.rs`.

use crate::{Case, Expect, Field, Module};

pub static CASES: &[Case] = &[
    // ── DoS-class caps → Reject{400} ─────────────────────────────────────────────
    Case {
        id: "graphql-deep-query",
        module: Module::Graphql,
        field: Field::RawBody {
            content_type: "application/graphql",
            body: "query{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a{id}}}}}}}}}}}}}}}}}}}}",
        },
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["graphql"],
        desc: "selection-set nesting beyond max_depth (15) — DoS → Reject{400}",
    },
    Case {
        id: "graphql-alias-bomb",
        module: Module::Graphql,
        field: Field::RawBody {
            content_type: "application/graphql",
            body: "query{a:f a:f a:f a:f a:f a:f a:f a:f a:f a:f a:f a:f a:f a:f a:f a:f a:f a:f a:f a:f a:f a:f a:f a:f a:f a:f a:f a:f a:f a:f a:f }",
        },
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["graphql"],
        desc: "31 aliases beyond max_aliases (30) — alias-bomb DoS → Reject{400}",
    },
    Case {
        // Batched request (JSON array of operations) to the GraphQL endpoint path.
        id: "graphql-batch-bomb",
        module: Module::Graphql,
        field: Field::Post {
            path: "/graphql",
            content_type: "application/json",
            body: r#"[{"query":"{a}"},{"query":"{a}"},{"query":"{a}"},{"query":"{a}"},{"query":"{a}"},{"query":"{a}"},{"query":"{a}"},{"query":"{a}"},{"query":"{a}"},{"query":"{a}"},{"query":"{a}"}]"#,
        },
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["graphql"],
        desc: "11 batched operations beyond max_batch (10) — amplification DoS → Reject{400}",
    },
    Case {
        id: "graphql-directive-bomb",
        module: Module::Graphql,
        field: Field::RawBody {
            content_type: "application/graphql",
            body: "query{f @d @d @d @d @d @d @d @d @d @d @d @d @d @d @d @d @d @d @d @d @d @d @d @d @d @d @d @d @d @d @d @d @d @d @d @d @d @d @d @d @d @d @d @d @d @d @d @d @d @d @d}",
        },
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["graphql"],
        desc: "51 directives beyond max_directives (50) — directive-overloading DoS → Reject{400}",
    },
    Case {
        // GET transport (`?query=`, URL-encoded) on the endpoint path: a deep query is
        // rejected like the body transports. Locks the GET extraction path.
        id: "graphql-deep-query-get",
        module: Module::Graphql,
        field: Field::Get {
            path: "/graphql",
            query: "query=query%7Ba%7Ba%7Ba%7Ba%7Ba%7Ba%7Ba%7Ba%7Ba%7Ba%7Ba%7Ba%7Ba%7Ba%7Ba%7Ba%7Ba%7Ba%7Bid%7D%7D%7D%7D%7D%7D%7D%7D%7D%7D%7D%7D%7D%7D%7D%7D%7D%7D%7D%7D",
        },
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["graphql"],
        desc: "GraphQL-over-GET (`?query=`) deep query beyond max_depth — GET transport DoS",
    },
    // ── introspection policy → Block{403} (block_introspection = true in the harness) ─
    Case {
        id: "graphql-introspection",
        module: Module::Graphql,
        field: Field::RawBody {
            content_type: "application/graphql",
            body: "query{__schema{types{name}}}",
        },
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["graphql-introspection"],
        desc: "schema introspection (`__schema`) — blocked by policy → 403",
    },
    // ── benign guards ────────────────────────────────────────────────────────────
    Case {
        id: "graphql-benign-normal",
        module: Module::Graphql,
        field: Field::RawBody {
            content_type: "application/graphql",
            body: "query{user(id:42){id name email}}",
        },
        min_pl: 1,
        expect: Expect::Clean,
        rules: &[],
        desc: "an ordinary GraphQL query is within all caps → Clean",
    },
    Case {
        // JSON transport on the endpoint path: a normal single operation passes.
        id: "graphql-benign-json",
        module: Module::Graphql,
        field: Field::Post {
            path: "/graphql",
            content_type: "application/json",
            body: r#"{"operationName":"Me","query":"query Me{me{id name}}","variables":{}}"#,
        },
        min_pl: 1,
        expect: Expect::Clean,
        rules: &[],
        desc: "a normal JSON GraphQL request on the endpoint path is within all caps → Clean",
    },
    Case {
        id: "graphql-benign-get",
        module: Module::Graphql,
        field: Field::Get { path: "/graphql", query: "query=query%7Buser%7Bid%20name%7D%7D" },
        min_pl: 1,
        expect: Expect::Clean,
        rules: &[],
        desc: "a normal GraphQL-over-GET query is within all caps → Clean",
    },
    Case {
        // Path-gating: the SAME deep query as `graphql-deep-query`, but to a NON-GraphQL
        // path with a JSON `query` field (a normal search API) → the module must NOT act.
        id: "graphql-benign-non-endpoint-path",
        module: Module::Graphql,
        field: Field::Post {
            path: "/api/search",
            content_type: "application/json",
            body: r#"{"query":"query{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a{id}}}}}}}}}}}}}}}}}}}}"}"#,
        },
        min_pl: 1,
        expect: Expect::Clean,
        rules: &[],
        desc: "a deep `query` field on a NON-GraphQL path (ordinary JSON API) must be \
               ignored — path-gating keeps it Clean",
    },
    Case {
        // The Phase-11 Step-0 trap: a deeply nested input OBJECT in an argument but a
        // FLAT selection set. Paren-aware depth must keep this under the cap (NOT a
        // false Reject).
        id: "graphql-benign-deep-inputobject",
        module: Module::Graphql,
        field: Field::RawBody {
            content_type: "application/graphql",
            body: "mutation{c(input:{a:{b:{c:{d:{e:{f:{g:1}}}}}}}){id}}",
        },
        min_pl: 1,
        expect: Expect::Clean,
        rules: &[],
        desc: "deep input-object in an argument, flat selection set — paren-aware depth \
               keeps it Clean (no false Reject); the Step-0 negative reference",
    },
];
