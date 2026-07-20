// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

//! NoSQL injection corpus cases (Fase 10a). Field: query.
//! Rules (paranoia): nosql-where-js 1, nosql-shell-method 1 (Critical),
//! nosql-js-timing 2, nosql-operator 2 (Warning, accumulate). Source: gotestwaf
//! `nosql-injection`. URL payloads are 10a Triggers; Base64Flat duplicates are
//! `ExpectedMiss{until_phase:"10c"}`.

use crate::{Case, Expect, Field, Module};

pub static CASES: &[Case] = &[
    // ── malicious (URL/Plain — 10a) ─────────────────────────────────────────────
    Case {
        id: "nosql-shell-method-query",
        module: Module::Nosql,
        field: Field::Query { name: "q", value: "db.injection.insert({success:1});" },
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["nosql-shell-method"],
        desc: "Mongo shell collection method call — gotestwaf nosql-injection (URL)",
    },
    Case {
        id: "nosql-where-js-query",
        module: Module::Nosql,
        field: Field::Query { name: "q", value: "true, $where: '99 == 88'" },
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["nosql-where-js"],
        desc: "$where server-side JS predicate — gotestwaf nosql-injection (URL)",
    },
    Case {
        id: "nosql-operator-query",
        module: Module::Nosql,
        field: Field::Query { name: "q", value: "', $or: [ {}, { 'order':'order" },
        min_pl: 2,
        expect: Expect::Triggers,
        rules: &["nosql-operator"],
        desc: "$or boolean operator injection — gotestwaf nosql-injection (URL)",
    },
    Case {
        id: "nosql-js-timing-query",
        module: Module::Nosql,
        field: Field::Query {
            name: "q",
            value: ";var date = new Date(); do{curDate = new Date();}while(curDate-date",
        },
        min_pl: 2,
        expect: Expect::Triggers,
        rules: &["nosql-js-timing"],
        desc: "busy-loop timing payload (server-side JS) — gotestwaf nosql-injection (URL)",
    },
    // ── Base64Flat duplicates — CAUGHT at 10c via §6 base64-decode (derived) ─────
    Case {
        id: "nosql-shell-method-b64",
        module: Module::Nosql,
        field: Field::Query { name: "q", value: "ZGIuaW5qZWN0aW9uLmluc2VydCh7c3VjY2VzczoxfSk7" },
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["nosql-shell-method"],
        desc: "base64(`db.injection.insert({success:1});`) — caught at 10c via base64-decode",
    },
    Case {
        id: "nosql-where-js-b64",
        module: Module::Nosql,
        field: Field::Query { name: "q", value: "dHJ1ZSwgJHdoZXJlOiAnOTkgPT0gODgn" },
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["nosql-where-js"],
        desc: "base64(`true, $where: '99 == 88'`) — caught at 10c via base64-decode",
    },
    Case {
        id: "nosql-operator-b64",
        module: Module::Nosql,
        field: Field::Query { name: "q", value: "JywgJG9yOiBbIHt9LCB7ICdvcmRlcic6J29yZGVy" },
        min_pl: 2,
        expect: Expect::Triggers,
        rules: &["nosql-operator"],
        desc: "base64(`', $or: [ {}, …`) — caught at 10c via base64-decode (Warning/PL2)",
    },
    // ── URLPath coverage (10c REOPEN, pcap) ──────────────────────────────────────
    Case {
        id: "nosql-urlpath-where",
        module: Module::Nosql,
        field: Field::Path("/q=true, $where: '99 == 88'"),
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["nosql-where-js"],
        desc: "$where JS injection in the URL PATH — gotestwaf nosql-injection URLPath; path now inspected",
    },
    // ── benign guards (must stay 200): the FP traps of this class ────────────────
    Case {
        id: "nosql-benign-json-schema-field",
        module: Module::Nosql,
        field: Field::Query { name: "meta", value: "$schema" },
        min_pl: 1,
        expect: Expect::Clean,
        rules: &[],
        desc: "a legit `$`-prefixed JSON field name ($schema) — NOT a Mongo operator",
    },
    Case {
        id: "nosql-benign-currency",
        module: Module::Nosql,
        field: Field::Query { name: "price", value: "$100.00" },
        min_pl: 1,
        expect: Expect::Clean,
        rules: &[],
        desc: "a currency value with `$` — must NOT flag",
    },
    Case {
        id: "nosql-benign-hostname",
        module: Module::Nosql,
        field: Field::Query { name: "host", value: "db.example.com" },
        min_pl: 1,
        expect: Expect::Clean,
        rules: &[],
        desc: "a hostname starting `db.` — not a shell method call, must NOT flag",
    },
    // ── G-3: operator in KEY position (param name / JSON key) — pentest #2 ────────
    Case {
        id: "nosql-operator-key-query",
        module: Module::Nosql,
        field: Field::RawQuery("q%5B%24ne%5D=null"),
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["nosql-operator-key"],
        desc: "`q[$ne]=null` — Mongo operator in the PARAM NAME (bracket notation); G-3",
    },
    Case {
        id: "nosql-operator-key-json",
        module: Module::Nosql,
        field: Field::JsonBody(r#"{"email":{"$gt":""},"password":{"$gt":""}}"#),
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["nosql-operator-key"],
        desc: "`{\"$gt\":\"\"}` — operator as a JSON KEY (auth-bypass on Mongo); G-3",
    },
    Case {
        id: "nosql-benign-jsonschema-keys",
        module: Module::Nosql,
        field: Field::JsonBody(r##"{"$schema":"draft-2020-12","$ref":"#/defs/x","$id":"thing","$comment":"note"}"##),
        min_pl: 1,
        expect: Expect::Clean,
        rules: &[],
        desc: "G-3 FP guard: JSON-Schema `$schema`/`$ref`/`$id` keys are NOT Mongo operators",
    },
    // ── E-4: prototype pollution in KEY position (EXTREME follow-on) ─────────────
    Case {
        id: "nosql-proto-pollution-underscore",
        module: Module::Nosql,
        field: Field::JsonBody(r#"{"__proto__":{"isAdmin":true}}"#),
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["proto-pollution-key"],
        desc: "E-4: `{\"__proto__\":{…}}` — prototype pollution via JSON key (Node/JS)",
    },
    Case {
        id: "nosql-proto-pollution-constructor",
        module: Module::Nosql,
        field: Field::JsonBody(r#"{"constructor":{"prototype":{"polluted":true}}}"#),
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["proto-pollution-key"],
        desc: "E-4: `constructor.prototype` chain pollution via JSON key",
    },
    Case {
        id: "nosql-benign-constructor-name",
        module: Module::Nosql,
        field: Field::JsonBody(r#"{"constructorName":"Acme","prototype":"v2"}"#),
        min_pl: 1,
        expect: Expect::Clean,
        rules: &[],
        desc: "E-4 FP guard: fields merely CONTAINING the words (`constructorName`, lone `prototype`) — must NOT flag",
    },
];
