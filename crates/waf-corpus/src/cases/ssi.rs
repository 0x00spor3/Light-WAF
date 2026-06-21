//! Server-Side Includes injection corpus cases (Fase 10b). Field: query.
//! Rule (paranoia): ssi-directive 1 (Critical) — `<!--#<verb>`. Source: gotestwaf
//! ss-include. Before this module the payloads only tripped sqli-quote-comment
//! incidentally (the `"-->` tail), so the clean-attribution triggers below use a
//! quote-less directive to prove ssi-directive is the real catcher.

use crate::{Case, Expect, Field, Module};

pub static CASES: &[Case] = &[
    // ── malicious: clean-attribution (quote-less → ONLY ssi-directive fires) ──────
    Case {
        id: "ssi-printenv-directive-query",
        module: Module::Ssi,
        field: Field::Query { name: "q", value: "<!--#printenv -->" },
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["ssi-directive"],
        desc: "SSI #printenv directive (no quotes) — gotestwaf ss-include; isolates ssi-directive",
    },
    Case {
        id: "ssi-exec-directive-query",
        module: Module::Ssi,
        field: Field::Query { name: "q", value: "<!--#exec cmd=id-->" },
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["ssi-directive"],
        desc: "SSI #exec command directive (quote-less) — gotestwaf ss-include",
    },
    // ── malicious: real gotestwaf payload (declared overlap with sqli-quote-comment
    //     via the `" -->` tail — defense-in-depth; attribution stays ssi) ──────────
    Case {
        id: "ssi-exec-ls-quoted-query",
        module: Module::Ssi,
        field: Field::Query { name: "q", value: "<!--#exec cmd=\"ls\" -->" },
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["ssi-directive"],
        desc: "SSI #exec cmd=\"ls\" — gotestwaf ss-include (also trips sqli-quote-comment, declared)",
    },
    // ── Base64Flat harvest (Fase 10c) — recall-lock under §6 base64-decode ───────
    // Not a gotestwaf-tracked deferral; pins that the derived channel feeds SSI too.
    Case {
        id: "ssi-exec-directive-b64",
        module: Module::Ssi,
        field: Field::Query { name: "q", value: "PCEtLSNleGVjIGNtZD1pZC0tPg==" },
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["ssi-directive"],
        desc: "base64(`<!--#exec cmd=id-->`) — caught at 10c via base64-decode",
    },
    // ── benign guards (must stay 200) ────────────────────────────────────────────
    Case {
        id: "ssi-benign-html-comment",
        module: Module::Ssi,
        field: Field::Query { name: "q", value: "<!-- this is a normal page comment -->" },
        min_pl: 1,
        expect: Expect::Clean,
        rules: &[],
        desc: "plain HTML comment without a `#verb` — must NOT match ssi-directive",
    },
    Case {
        id: "ssi-benign-hash-text",
        module: Module::Ssi,
        field: Field::Query { name: "q", value: "topic #exec and #include in the docs" },
        min_pl: 1,
        expect: Expect::Clean,
        rules: &[],
        desc: "SSI verbs as prose without the `<!--#` opener — must NOT match",
    },
];
