// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

//! LDAP injection corpus cases (Fase 10a). Field: query.
//! Rules (paranoia): ldap-logical-filter 1, ldap-extensible-match 1 (both Critical).
//! Source: gotestwaf `ldap-injection`. The URL/Plain payloads are 10a Triggers; the
//! Base64Flat duplicates are tracked as `ExpectedMiss{until_phase:"10c"}` — they must
//! flip to caught once §6 base64-decodes (the oracle enforces it at 10c).

use crate::{Case, Expect, Field, Module};

pub static CASES: &[Case] = &[
    // ── malicious (URL/Plain — 10a) ─────────────────────────────────────────────
    Case {
        id: "ldap-logical-filter-query",
        module: Module::Ldap,
        field: Field::Query {
            name: "user",
            value: "(&(uid=admin)(!(&(1=0)(userPassword=q))))",
        },
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["ldap-logical-filter"],
        desc: "compound LDAP filter (auth-bypass) in a query value — gotestwaf ldap-injection (URL)",
    },
    Case {
        id: "ldap-objectclass-enum-query",
        module: Module::Ldap,
        field: Field::Query { name: "search", value: "*(|(objectclass=*))" },
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["ldap-logical-filter"],
        desc: "wildcard-into-OR filter for objectclass enumeration — gotestwaf ldap-injection (URL)",
    },
    Case {
        id: "ldap-extensible-match-query",
        module: Module::Ldap,
        field: Field::Query { name: "attr", value: "userPassword:2.5.13.18:=123" },
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["ldap-extensible-match"],
        desc: "extensible-match OID injection — gotestwaf ldap-injection (URL)",
    },
    // ── Base64Flat duplicates — CAUGHT at 10c via §6 base64-decode (derived) ─────
    Case {
        id: "ldap-logical-filter-b64",
        module: Module::Ldap,
        field: Field::Query { name: "user", value: "KCYodWlkPWFkbWluKSghKCYoMT0wKSh1c2VyUGFzc3dvcmQ9cSkpKSk" },
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["ldap-logical-filter"],
        desc: "base64(`(&(uid=admin)…`) — caught at 10c via base64-decode",
    },
    Case {
        id: "ldap-objectclass-enum-b64",
        module: Module::Ldap,
        field: Field::Query { name: "search", value: "Kih8KG9iamVjdGNsYXNzPSopKQ" },
        min_pl: 1,
        expect: Expect::Triggers,
        // decodes to `*(|(objectclass=*))` → the `(|(` compound-filter signature, so
        // ldap-logical-filter is the firing rule (not a dedicated objectclass rule).
        rules: &["ldap-logical-filter"],
        desc: "base64(`*(|(objectclass=*))`) — caught at 10c; fires ldap-logical-filter on the `(|(`",
    },
    Case {
        id: "ldap-extensible-match-b64",
        module: Module::Ldap,
        field: Field::Query { name: "attr", value: "dXNlclBhc3N3b3JkOjIuNS4xMy4xODo9MTIz" },
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["ldap-extensible-match"],
        desc: "base64(`userPassword:2.5.13.18:=123`) — caught at 10c via base64-decode",
    },
    // ── URLPath coverage (10c REOPEN, pcap) ──────────────────────────────────────
    Case {
        id: "ldap-urlpath-filter",
        module: Module::Ldap,
        field: Field::Path("/(&(uid=admin)(!(&(1=0)(userPassword=q))))"),
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["ldap-logical-filter"],
        desc: "compound LDAP filter in the URL PATH — gotestwaf ldap-injection URLPath; path now inspected",
    },
    // ── P1-B: header-surface (custom x-* allowlist) ─────────────────────────────
    Case {
        id: "ldap-header-xcustom",
        module: Module::Ldap,
        field: Field::Header { name: "x-foo", value: "(&(uid=admin)(!(&(1=0)(userPassword=q))))" },
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["ldap-logical-filter"],
        desc: "LDAP filter injection in a custom X- header — gotestwaf Header placeholder; allowlist (P1-B)",
    },
    // ── benign guards (must stay 200): the FP traps of this class ────────────────
    Case {
        id: "ldap-benign-single-filter",
        module: Module::Ldap,
        field: Field::Query { name: "filter", value: "(cn=John Doe)" },
        min_pl: 1,
        expect: Expect::Clean,
        rules: &[],
        desc: "legitimate single LDAP filter — no boolean combinator, must NOT flag",
    },
    Case {
        id: "ldap-benign-wildcard",
        module: Module::Ldap,
        field: Field::Query { name: "q", value: "john*" },
        min_pl: 1,
        expect: Expect::Clean,
        rules: &[],
        desc: "literal `*` wildcard search term — a lone wildcard must NOT flag",
    },
    Case {
        id: "ldap-benign-oid",
        module: Module::Ldap,
        field: Field::Query { name: "oid", value: "2.5.4.3" },
        min_pl: 1,
        expect: Expect::Clean,
        rules: &[],
        desc: "bare OID value (no `(&(`/`(|(` combinator) — must NOT flag",
    },
];
