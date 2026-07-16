// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

//! Server-Side Template Injection corpus cases (Fase 10a). Field: query.
//! Rules (paranoia): ssti-template-arithmetic 1 (Critical), ssti-freemarker-directive
//! 1 (Critical). Source: gotestwaf `sst-injection`. URL payloads are 10a Triggers;
//! the Base64Flat duplicates are `ExpectedMiss{until_phase:"10c"}` (need §6 base64).

use crate::{Case, Expect, Field, Module};

pub static CASES: &[Case] = &[
    // ── malicious (URL/Plain — 10a) ─────────────────────────────────────────────
    Case {
        id: "ssti-jinja-arithmetic-query",
        module: Module::Ssti,
        field: Field::Query { name: "name", value: "{{1337*1338}}" },
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["ssti-template-arithmetic"],
        desc: "Jinja/Twig `{{1337*1338}}` arithmetic probe — gotestwaf sst-injection (URL)",
    },
    Case {
        id: "ssti-expr-interpolation-query",
        module: Module::Ssti,
        field: Field::Query { name: "q", value: "aaaa'+#{16*8787}+'bbb" },
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["ssti-template-arithmetic"],
        desc: "expression-language `#{16*8787}` interpolation — gotestwaf sst-injection (URL)",
    },
    Case {
        id: "ssti-freemarker-execute-query",
        module: Module::Ssti,
        field: Field::Query {
            name: "tpl",
            value: "<#assign ex = \"freemarker.template.utility.Execute\"?new()>${ ex(\"id\")}",
        },
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["ssti-freemarker-directive"],
        desc: "FreeMarker `<#assign …?new()>` RCE — gotestwaf sst-injection (URL)",
    },
    // ── ERB/EJS/JSP arithmetic (F-2 remediation, Juice-Shop report) ──────────────
    Case {
        id: "ssti-erb-arithmetic-query",
        module: Module::Ssti,
        field: Field::Query { name: "q", value: "<%=7*7%>" },
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["ssti-erb-jsp-arithmetic"],
        desc: "ERB `<%=7*7%>` arithmetic probe — Juice-Shop report F-2 (new delimiter family)",
    },
    // ── Base64Flat duplicates — CAUGHT at 10c via §6 base64-decode (derived) ─────
    Case {
        id: "ssti-jinja-arithmetic-b64",
        module: Module::Ssti,
        field: Field::Query { name: "name", value: "e3sxMzM3KjEzMzh9fQ" },
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["ssti-template-arithmetic"],
        desc: "base64(`{{1337*1338}}`) — caught at 10c via base64-decode",
    },
    Case {
        id: "ssti-expr-interpolation-b64",
        module: Module::Ssti,
        field: Field::Query { name: "q", value: "YWFhYScrI3sxNio4Nzg3fSsnYmJi" },
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["ssti-template-arithmetic"],
        desc: "base64(`aaaa'+#{16*8787}+'bbb`) — caught at 10c via base64-decode",
    },
    Case {
        id: "ssti-freemarker-execute-b64",
        module: Module::Ssti,
        field: Field::Query {
            name: "tpl",
            value: "PCNhc3NpZ24gZXggPSAiZnJlZW1hcmtlci50ZW1wbGF0ZS51dGlsaXR5LkV4ZWN1dGUiP25ldygpPiR7IGV4KCJpZCIpfQ",
        },
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["ssti-freemarker-directive"],
        desc: "base64(FreeMarker `<#assign…Execute…>`) — caught at 10c via base64-decode",
    },
    // ── URLPath coverage (10c REOPEN, pcap) ──────────────────────────────────────
    Case {
        id: "ssti-urlpath-arith",
        module: Module::Ssti,
        field: Field::Path("/{{1337*1338}}"),
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["ssti-template-arithmetic"],
        desc: "Jinja arithmetic in the URL PATH — gotestwaf sst-injection URLPath; path now inspected",
    },
    // ── Base64Flat-in-PATH (10c REOPEN, pcap): gotestwaf places the b64 blob AS the path.
    //    The decode channel now reads the (case-preserved) path segments too. ──────────
    Case {
        id: "ssti-urlpath-b64",
        module: Module::Ssti,
        field: Field::Path("/e3sxMzM3KjEzMzh9fQ"),
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["ssti-template-arithmetic"],
        desc: "base64(`{{1337*1338}}`) UNPADDED as the URL PATH — gotestwaf Base64Flat URLPath; \
               path-segment base64-derive closes it (10c REOPEN)",
    },
    // ── benign guards (must stay 200): template delimiters WITHOUT eval payload ───
    Case {
        id: "ssti-benign-b64-path-noise",
        module: Module::Ssti,
        field: Field::Path("/assets/build/app.e3sxMzM3.chunk.js"),
        min_pl: 1,
        expect: Expect::Clean,
        rules: &[],
        desc: "FP trap: a normal hashed-asset path segment must NOT be treated as a b64 attack \
               (segments fail candidacy / decode to noise → mostly_printable discards)",
    },
    Case {
        id: "ssti-benign-template-var",
        module: Module::Ssti,
        field: Field::Query { name: "tpl", value: "{{ user.name }}" },
        min_pl: 1,
        expect: Expect::Clean,
        rules: &[],
        desc: "a bare `{{ var }}` with no arithmetic — must NOT flag (mustache/Vue prose)",
    },
    Case {
        id: "ssti-benign-shell-var",
        module: Module::Ssti,
        field: Field::Query { name: "path", value: "${base_url}/assets/app.js" },
        min_pl: 1,
        expect: Expect::Clean,
        rules: &[],
        desc: "`${base_url}` interpolation with no digit-op-digit — must NOT flag",
    },
    Case {
        id: "ssti-benign-arithmetic-prose",
        module: Module::Ssti,
        field: Field::Query { name: "note", value: "the result of 7 * 7 = 49" },
        min_pl: 1,
        expect: Expect::Clean,
        rules: &[],
        desc: "arithmetic in prose, no template delimiter — must NOT flag",
    },
    Case {
        id: "ssti-benign-erb-comment",
        module: Module::Ssti,
        field: Field::Query { name: "tpl", value: "<%-- build 2024 rev 7 --%>" },
        min_pl: 1,
        expect: Expect::Clean,
        rules: &[],
        desc: "F-2 FP trap: an ERB comment `<%-- … --%>` — a `-` follows `<%`, no adjacent \
               digit-op-digit → must NOT flag",
    },
    Case {
        id: "ssti-benign-erb-template-var",
        module: Module::Ssti,
        field: Field::Query { name: "tpl", value: "<%= user.name %>" },
        min_pl: 1,
        expect: Expect::Clean,
        rules: &[],
        desc: "F-2 FP trap: a real ERB output tag with no arithmetic — must NOT flag",
    },
    // ── G-2: Jinja/Python object-access SSTI (pentest #2) ────────────────────────
    Case {
        id: "ssti-jinja-config-object",
        module: Module::Ssti,
        field: Field::Query { name: "q", value: "{{config.items()}}" },
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["ssti-jinja-object"],
        desc: "Jinja `{{config.items()}}` secret disclosure — G-2 (was missed on Node/Python)",
    },
    Case {
        id: "ssti-python-dunder-rce",
        module: Module::Ssti,
        field: Field::Query { name: "q", value: "{{''.__class__.__mro__[1].__subclasses__()}}" },
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["ssti-python-dunder"],
        desc: "Jinja/Python RCE gadget via `__class__/__mro__/__subclasses__` — G-2",
    },
    Case {
        id: "ssti-jinja-statement",
        module: Module::Ssti,
        field: Field::Query { name: "q", value: "{%for x in range(3)%}a{%endfor%}" },
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["ssti-template-statement"],
        desc: "Jinja `{% for x in … %}` statement tag with argument — G-2",
    },
    Case {
        id: "ssti-benign-jinja-prose",
        module: Module::Ssti,
        field: Field::Query { name: "note", value: "use {% for %} and {% endfor %} to loop in Jinja" },
        min_pl: 1,
        expect: Expect::Clean,
        rules: &[],
        desc: "G-2 FP trap: technical prose naming BARE statement tags (no argument) — must NOT flag",
    },
    Case {
        id: "ssti-benign-js-proto",
        module: Module::Ssti,
        field: Field::Query { name: "q", value: "obj.__proto__.x" },
        min_pl: 1,
        expect: Expect::Clean,
        rules: &[],
        desc: "G-2 FP trap: JS `__proto__` is not a Python introspection gadget — must NOT flag",
    },
];
