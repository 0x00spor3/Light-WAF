// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

//! Header-injection (CRLF / response-splitting) corpus cases. Field-aware: rules
//! carry a scope (All / NonBody / HostHeaders / Body). The live surface is CRLF
//! percent-encoded in query/body params (hyper rejects raw CR/LF in headers), in the
//! URL PATH (Fase 10a B2 — gotestwaf crlf), plus Host absolute-URI injection. The
//! normalizer trims header values, so CR/LF is injected via %0d%0a in query/body/path.
//! Rules (paranoia): hdr-crlf-header-injection 1 (All), hdr-crlf-control-char 2
//! (NonBody), hdr-host-injection 2 (HostHeaders), hdr-crlf-in-body 3 (Body).

use crate::{Case, Expect, Field, Module};

pub static CASES: &[Case] = &[
    // ── malicious: one per rule ────────────────────────────────────────────────
    Case {
        id: "hdr-crlf-header-injection-query",
        module: Module::HeaderInjection,
        field: Field::RawQuery("x=%0d%0aSet-Cookie:%20sessionid=evil"),
        min_pl: 1,
        expect: Expect::Triggers,
        // also fires hdr-crlf-control-char (bare CR/LF, NonBody, PL2) at PL3.
        rules: &["hdr-crlf-header-injection"],
        desc: "CRLF + injected Set-Cookie response header in a query value",
    },
    Case {
        id: "hdr-crlf-control-char-query",
        module: Module::HeaderInjection,
        field: Field::RawQuery("x=line1%0d%0aline2"),
        min_pl: 2,
        expect: Expect::Triggers,
        rules: &["hdr-crlf-control-char"],
        desc: "bare CR/LF in a query value, no injectable header name (Warning/PL2)",
    },
    Case {
        id: "hdr-host-injection-header",
        module: Module::HeaderInjection,
        field: Field::Header { name: "host", value: "http://evil.example/" },
        min_pl: 2,
        expect: Expect::Triggers,
        rules: &["hdr-host-injection"],
        desc: "absolute-URI Host header (scheme + slash) — cache poisoning (Warning/PL2)",
    },
    Case {
        id: "hdr-crlf-in-body-form",
        module: Module::HeaderInjection,
        field: Field::FormBody("comment=line1%0d%0aline2"),
        min_pl: 3,
        expect: Expect::Triggers,
        rules: &["hdr-crlf-in-body"],
        desc: "bare CR/LF in a body field — legit in textareas, so Notice/PL3 only",
    },
    // ── benign / traps ─────────────────────────────────────────────────────────
    Case {
        id: "hdr-benign-host-port",
        module: Module::HeaderInjection,
        field: Field::Header { name: "host", value: "example.com:8080" },
        min_pl: 2,
        expect: Expect::Clean,
        rules: &[],
        desc: "legitimate host:port Host header (no scheme/slash/userinfo)",
    },
    Case {
        id: "hdr-benign-host-ipv6",
        module: Module::HeaderInjection,
        field: Field::Header { name: "host", value: "[2001:db8::1]:8080" },
        min_pl: 2,
        expect: Expect::Clean,
        rules: &[],
        desc: "IPv6-literal Host: colons only, must not be read as injection",
    },
    Case {
        id: "hdr-benign-body-text",
        module: Module::HeaderInjection,
        field: Field::FormBody("comment=hello world, thanks"),
        min_pl: 1,
        expect: Expect::Clean,
        rules: &[],
        desc: "ordinary single-line body field, no CR/LF",
    },
    Case {
        id: "hdr-benign-query-text",
        module: Module::HeaderInjection,
        field: Field::Query { name: "q", value: "normal search text" },
        min_pl: 1,
        expect: Expect::Clean,
        rules: &[],
        desc: "ordinary query value, no control characters",
    },
    // ── URL-PATH CRLF injection (Fase 10a B2) — gotestwaf crlf ────────────────────
    Case {
        id: "hdr-crlf-path-setcookie",
        module: Module::HeaderInjection,
        field: Field::Path("/%0d%0aSet-Cookie:crlf=injection"),
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["hdr-crlf-header-injection"],
        desc: "CR/LF + Set-Cookie smuggled in the URL path — gotestwaf crlf (Plain)",
    },
    Case {
        id: "hdr-crlf-path-lf-cr",
        module: Module::HeaderInjection,
        field: Field::Path("/%0a%0dSet-cookie:crlf=injection"),
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["hdr-crlf-header-injection"],
        desc: "reversed LF/CR + Set-Cookie in the URL path — gotestwaf crlf (Plain)",
    },
    Case {
        id: "hdr-crlf-path-double-encoded",
        module: Module::HeaderInjection,
        field: Field::Path("/%25%30%41%25%30%44Set-cookie:crlf=injection"),
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["hdr-crlf-header-injection"],
        desc: "double-encoded CR/LF (%25%30%41…) in the path — resolved by Fase 2 second decode",
    },
    Case {
        id: "hdr-crlf-path-overlong-unicode",
        module: Module::HeaderInjection,
        // %e5%98%8d is VALID UTF-8 (U+560D 嘍), not a CR/LF — the normalizer keeps it
        // as the character, so no CR/LF ever appears. Catching this needs best-fit /
        // overlong mapping the normalizer deliberately does NOT do (§6). Permanent gap.
        field: Field::Path("/%e5%98%8dSet-cookie%3acrlf%3dinjection"),
        min_pl: 1,
        expect: Expect::ExpectedMiss { until_phase: None },
        rules: &[],
        desc: "overlong-unicode CR/LF — documented limit, normalizer decodes to 嘍 not CR/LF",
    },
    Case {
        // 10c DEFERRAL (tracked, not silent): overlong LF `%C0%8A` (= `\n`) in a HEADER
        // VALUE inspected by header_injection. 10c folds overlong into query/body/cookie/
        // path, but NOT into the stored header values header_injection reads — extending
        // it there is a CANONICAL CHANGE to a CRLF module's input surface, and 10c has no
        // bite for it. Deferred to 10d, where it closes with full rigour (re-run P1/P2/P3
        // + dedicated bite). Until then this stays an honest, under-test gap.
        id: "hdr-overlong-crlf-header-value",
        module: Module::HeaderInjection,
        field: Field::Header { name: "x-trace-id", value: "%C0%8ASet-Cookie:sessionid=evil" },
        min_pl: 1,
        expect: Expect::ExpectedMiss { until_phase: Some("10d") },
        rules: &[],
        desc: "overlong LF `%C0%8A`→`\\n` in a header value — header values are NOT overlong-folded \
               (out of 10c by §13: canonical change with no bite); flips to caught at 10d",
    },
    Case {
        id: "hdr-benign-path-text",
        module: Module::HeaderInjection,
        field: Field::Path("/api/v1/articles/2024/summary.html"),
        min_pl: 1,
        expect: Expect::Clean,
        rules: &[],
        desc: "ordinary multi-segment path, no CR/LF — must NOT flag now path is inspected",
    },
];
