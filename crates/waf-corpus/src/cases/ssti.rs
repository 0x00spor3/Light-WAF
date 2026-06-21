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
    // ── Base64Flat duplicates — CAUGHT at 10c via §6 base64-decode (derived) ─────
    Case {
        id: "ssti-jinja-arithmetic-b64",
        module: Module::Ssti,
        field: Field::Query { name: "name", value: "e3sxMzM3KjEzMzh9fQ==" },
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
            value: "PCNhc3NpZ24gZXggPSAiZnJlZW1hcmtlci50ZW1wbGF0ZS51dGlsaXR5LkV4ZWN1dGUiP25ldygpPiR7IGV4KCJpZCIpfQ==",
        },
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["ssti-freemarker-directive"],
        desc: "base64(FreeMarker `<#assign…Execute…>`) — caught at 10c via base64-decode",
    },
    // ── benign guards (must stay 200): template delimiters WITHOUT eval payload ───
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
];
