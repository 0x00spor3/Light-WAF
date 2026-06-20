//! Path-traversal corpus cases. Fields inspected: normalized.path, query,
//! cookies, body. `../` survives on query/body (the normalizer resolves it away
//! on the path); sensitive targets are detected on the resolved path.
//! Rules (paranoia): pt-dotdot-traversal 1, pt-sensitive-unix 1,
//! pt-sensitive-windows 1, pt-null-byte 2, pt-unc-path 3.

use crate::{Case, Expect, Field, Module};

pub static CASES: &[Case] = &[
    // ── malicious: one per rule ────────────────────────────────────────────────
    Case {
        id: "pt-dotdot-traversal-query",
        module: Module::PathTraversal,
        field: Field::Query { name: "file", value: "../../../foo/bar" },
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["pt-dotdot-traversal"],
        desc: "../ sequence surviving on a query parameter",
    },
    Case {
        id: "pt-sensitive-unix-path",
        module: Module::PathTraversal,
        field: Field::Path("/etc/passwd"),
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["pt-sensitive-unix"],
        desc: "sensitive Unix target on the resolved path",
    },
    Case {
        id: "pt-sensitive-windows-path",
        module: Module::PathTraversal,
        field: Field::Path("/windows/system32/cmd"),
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["pt-sensitive-windows"],
        desc: "Windows system32 target on the resolved path",
    },
    Case {
        id: "pt-null-byte-query",
        module: Module::PathTraversal,
        field: Field::RawQuery("file=secret%00.png"),
        min_pl: 2,
        expect: Expect::Triggers,
        rules: &["pt-null-byte"],
        desc: "%00 decoded to a real NUL byte in a query value (Warning/PL2)",
    },
    Case {
        id: "pt-unc-path-query",
        module: Module::PathTraversal,
        field: Field::Query { name: "file", value: r"\\server\share\secret" },
        min_pl: 3,
        expect: Expect::Triggers,
        rules: &["pt-unc-path"],
        desc: "UNC network path (Notice/PL3)",
    },
    // ── gotestwaf path-traversal payloads (Fase 10b B3) ─────────────────────────
    Case {
        id: "pt-gotestwaf-resolved-passwd-path",
        module: Module::PathTraversal,
        field: Field::Path("/static/img/../../etc/passwd"),
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["pt-sensitive-unix"],
        desc: "gotestwaf path-traversal: the normalizer RESOLVES `../` away, so the \
               signature is the resolved target `/etc/passwd` (pt-sensitive-unix), not `../`",
    },
    Case {
        id: "pt-unc-ipv6-localhost-query",
        module: Module::PathTraversal,
        field: Field::Query { name: "file", value: r"\\::1\c$\users\default\ntuser.dat" },
        min_pl: 3,
        expect: Expect::Triggers,
        rules: &["pt-unc-path"],
        desc: "gotestwaf path-traversal: UNC path to an IPv6-literal host (`\\\\::1\\c$\\`) — \
               the `:` widening of pt-unc-path's host class is what catches it (Notice/PL3)",
    },
    Case {
        id: "pt-gotestwaf-faro-query",
        module: Module::PathTraversal,
        field: Field::Query { name: "file", value: "/static/img/../../etc/passwd" },
        min_pl: 1,
        expect: Expect::Triggers,
        // `../../` survives in the query value (not path-resolved) → pt-dotdot-traversal
        // (now `{2,}` consecutive); the literal `/etc/passwd` substring also trips
        // pt-sensitive-unix. Assert the target rule; pt-dotdot is a declared overlap.
        rules: &["pt-sensitive-unix"],
        desc: "gotestwaf path-traversal faro in the QUERYSTRING (URL encoder): the `../../` \
               escape survives unresolved on a query value and reaches /etc/passwd (10b-cont)",
    },
    // ── field-coverage: multipart body (10b-cont) ───────────────────────────────
    Case {
        id: "pt-gotestwaf-faro-multipart-filename",
        module: Module::PathTraversal,
        field: Field::MultipartFile {
            field: "upload",
            filename: "/static/img/../../etc/passwd",
            content: "harmless file body",
        },
        min_pl: 1,
        expect: Expect::Triggers,
        // The traversal hides in the multipart part's `filename`, previously a blind
        // spot (body_str_values inspected part DATA but not the filename). Field-
        // coverage now feeds the filename to inspection → pt-sensitive-unix fires
        // (pt-dotdot-traversal `{2,}` is a declared overlap on the `../../`).
        rules: &["pt-sensitive-unix"],
        desc: "gotestwaf community-lfi-multipart faro: `/static/img/../../etc/passwd` in a \
               multipart FILENAME — field-coverage extension, not pattern broadening (10b-cont)",
    },
    Case {
        // Base64Flat encoder: the corpus has no base64-decode (ARCHITECTURE §6 / 10c),
        // so the encoded faro carries no `/etc/passwd` or `../` signature yet. The
        // oracle FLIPS this to a required Triggers once CURRENT_PHASE reaches 10c.
        id: "pt-gotestwaf-faro-base64-query",
        module: Module::PathTraversal,
        field: Field::Query { name: "file", value: "L3N0YXRpYy9pbWcvLi4vLi4vZXRjL3Bhc3N3ZA==" },
        min_pl: 1,
        expect: Expect::ExpectedMiss { until_phase: Some("10c") },
        rules: &[],
        desc: "gotestwaf path-traversal faro, Base64Flat: base64(`/static/img/../../etc/passwd`) \
               — needs §6 base64-decode (10c); no signature survives until then",
    },
    Case {
        // UNC `\\::1\c$\…` URL/Plain is ALREADY caught by pt-unc-path (the `:` host
        // widening from B3, see pt-unc-ipv6-localhost-query). Only its Base64Flat
        // form is missed — deferred to 10c with the other base64 payloads. The D1
        // "defer Windows-backslash broadening to 10b-bis" decision means NO new UNC
        // pattern work this batch; the existing coverage stands.
        id: "pt-gotestwaf-unc-base64-query",
        module: Module::PathTraversal,
        field: Field::Query { name: "file", value: "XFw6OjFcYyQpdXNlcnNcZGVmYXVsdFxudHVzZXIuZGF0" },
        min_pl: 3,
        expect: Expect::ExpectedMiss { until_phase: Some("10c") },
        rules: &[],
        desc: "gotestwaf path-traversal UNC IPv6-localhost, Base64Flat — needs §6 base64-decode \
               (10c); URL/Plain UNC already caught by pt-unc-path (D1: no 10b-bis broadening)",
    },
    Case {
        // Overlong UTF-8 of `../../etc/passwd` (`%C0%AE`=`.`, `%C0%AF`=`/`). The
        // normalizer's `from_utf8_lossy` maps the invalid overlong bytes to U+FFFD
        // (NOT `.`/`/`), so no `/etc/passwd` signature ever forms. Closing it needs
        // overlong-sequence decoding (ARCHITECTURE §6), deliberately out of 10b.
        id: "pt-overlong-utf8-passwd-query",
        module: Module::PathTraversal,
        field: Field::RawQuery("file=%C0%AE%C0%AE%C0%AF%C0%AE%C0%AE%C0%AFetc%C0%AFpasswd"),
        min_pl: 1,
        expect: Expect::ExpectedMiss { until_phase: None },
        rules: &[],
        desc: "gotestwaf community-lfi: overlong-UTF8 `../../etc/passwd` — invalid bytes \
               become U+FFFD, no signature forms; needs §6 overlong decode (documented limit)",
    },
    // ── benign / traps ─────────────────────────────────────────────────────────
    Case {
        id: "pt-trap-system32-token",
        module: Module::PathTraversal,
        field: Field::Query { name: "theme", value: "system32_dark" },
        min_pl: 1,
        expect: Expect::Clean,
        rules: &[],
        desc: "windows-target narrowing trap: 'system32_dark' must not match system32\\b",
    },
    Case {
        id: "pt-benign-normal-path",
        module: Module::PathTraversal,
        field: Field::Path("/api/v1/users/42"),
        min_pl: 1,
        expect: Expect::Clean,
        rules: &[],
        desc: "ordinary application path",
    },
    Case {
        id: "pt-benign-filename",
        module: Module::PathTraversal,
        field: Field::Query { name: "file", value: "quarterly_report.pdf" },
        min_pl: 1,
        expect: Expect::Clean,
        rules: &[],
        desc: "ordinary download filename",
    },
    // ── benign `../` traps locking in the pt-dotdot `{2,}` narrowing (10b-cont) ──
    Case {
        id: "pt-benign-relative-dotdot-query",
        module: Module::PathTraversal,
        field: Field::Query { name: "path", value: "docs/../report.pdf" },
        min_pl: 1,
        expect: Expect::Clean,
        rules: &[],
        desc: "legit relative path with a SINGLE `../` staying in-app — must stay Clean now \
               that pt-dotdot-traversal requires `{2,}` consecutive segments (10b-cont trap)",
    },
    Case {
        id: "pt-benign-relative-dotdot-ref-query",
        module: Module::PathTraversal,
        field: Field::Query { name: "ref", value: "../images/logo.png" },
        min_pl: 1,
        expect: Expect::Clean,
        rules: &[],
        desc: "legit single `../` asset reference — Clean under the `{2,}` narrowing (10b-cont)",
    },
    Case {
        id: "pt-benign-passwd-prose-query",
        module: Module::PathTraversal,
        field: Field::Query { name: "msg", value: "reset your passwd here, not in /etcetera" },
        min_pl: 1,
        expect: Expect::Clean,
        rules: &[],
        desc: "the words `passwd`/`etc` outside a path context — `/etc/passwd` never forms, so \
               nothing fires (broadening stays semantic, not generic-substring; 10b-cont trap)",
    },
    Case {
        id: "pt-benign-multipart-filename",
        module: Module::PathTraversal,
        field: Field::MultipartFile {
            field: "upload",
            filename: "report-2026.pdf",
            content: "quarterly numbers",
        },
        min_pl: 1,
        expect: Expect::Clean,
        rules: &[],
        desc: "legit multipart upload filename (no `../`, no sensitive target) — field-coverage \
               must not turn ordinary filenames into false positives (10b-cont trap)",
    },
];
