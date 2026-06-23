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
            filename: Some("/static/img/../../etc/passwd"),
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
        id: "pt-gotestwaf-faro-multipart-name",
        module: Module::PathTraversal,
        field: Field::MultipartFile {
            field: "/static/img/../../etc/passwd",
            filename: None,
            content: "Test",
        },
        min_pl: 1,
        expect: Expect::Triggers,
        // gotestwaf's REAL shape: the traversal is the part `name=` (no filename), the
        // value is benign. `name` is now inspected (canonicalize_multipart_field) →
        // pt-sensitive-unix + pt-dotdot `{2,}` on `../../`. This is the bypass the
        // filename-only B1-cont fix missed.
        rules: &["pt-sensitive-unix"],
        desc: "gotestwaf community-lfi-multipart: traversal in the part NAME (no filename) — \
               the field actually used by gotestwaf; name-coverage closes it (10b-cont fix)",
    },
    Case {
        id: "pt-gotestwaf-multipart-overlong-value",
        module: Module::PathTraversal,
        field: Field::MultipartFile {
            field: "32c7608727",
            filename: None,
            content: "%25C0%25AE%25C0%25AE%25C0%25AF%25C0%25AE%25C0%25AE%25C0%25AFetc%25C0%25AFpasswd",
        },
        min_pl: 1,
        expect: Expect::Triggers,
        // Double-encoded overlong UTF-8 in the part VALUE: `%25C0%25AE` → `%C0%AE` →
        // byte `0xC0 0xAE` → `.`. The multipart deep-normalization (recursive decode +
        // overlong collapse) resolves it to `../../etc/passwd` BEFORE the rules run.
        // NB: the same payload in a QUERY stays ExpectedMiss (query keeps the shared
        // pass; overlong decode is scoped to the multipart smuggling surface).
        rules: &["pt-sensitive-unix"],
        desc: "gotestwaf community-lfi-multipart: overlong+double-encoded `../../etc/passwd` in \
               the part VALUE — closed by multipart deep-normalization (10b-cont fix)",
    },
    Case {
        // ── WIRE GROUND-TRUTH (Fase 10c REOPEN, pcap bypass.txt line 591) ──────────
        // EXACT bytes: JSON body whose string value is `\u`-escaped. serde unescapes
        // to `%25C0%25AE…` (double-encoded overlong `../../etc/passwd`) — but the JSON
        // leaf is then read RAW: `body_str_values`/`body_canonical_strings` clone the
        // JSON value WITHOUT canonicalize_value, so no percent-decode/overlong runs and
        // the modules see `%25C0%25AE…` (no `../` signature). CONTRAST: the SAME bytes
        // in a query param ARE canonicalized → caught (score 12). Probe-confirmed BYPASS
        // (score 0). STEP-1 ground-truth; STEP 2 closes it by canonicalizing JSON leaves.
        id: "pt-wire-json-unicode-overlong",
        module: Module::PathTraversal,
        field: Field::JsonBody(
            r#"{"test": true, "bcbd6bdb4d": "\u0025\u0032\u0035\u0043\u0030\u0025\u0032\u0035\u0041\u0045\u0025\u0032\u0035\u0043\u0030\u0025\u0032\u0035\u0041\u0045\u0025\u0032\u0035\u0043\u0030\u0025\u0032\u0035\u0041\u0046\u0025\u0032\u0035\u0043\u0030\u0025\u0032\u0035\u0041\u0045\u0025\u0032\u0035\u0043\u0030\u0025\u0032\u0035\u0041\u0045\u0025\u0032\u0035\u0043\u0030\u0025\u0032\u0035\u0041\u0046\u0065\u0074\u0063\u0025\u0032\u0035\u0043\u0030\u0025\u0032\u0035\u0041\u0046\u0070\u0061\u0073\u0073\u0077\u0064"}"#,
        ),
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["pt-sensitive-unix"],
        desc: "WIRE pcap L591: JSON \\u-escaped overlong ../../etc/passwd — JSON leaf never \
               canonicalized (root cause refined: serde DOES unescape; canonicalize missing)",
    },
    Case {
        // Base64Flat encoder, CAUGHT at 10c: §6 base64-decode produces the derived
        // `/static/img/../../etc/passwd`, which trips pt-sensitive-unix (+ pt-dotdot
        // on `../../`). Bite-verified: break base64-decode → this goes RED.
        id: "pt-gotestwaf-faro-base64-query",
        module: Module::PathTraversal,
        field: Field::Query { name: "file", value: "L3N0YXRpYy9pbWcvLi4vLi4vZXRjL3Bhc3N3ZA" },
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["pt-sensitive-unix"],
        desc: "base64(`/static/img/../../etc/passwd`) — caught at 10c via base64-decode \
               (pt-dotdot `{2,}` overlap declared)",
    },
    Case {
        // UNC `\\::1\c$\…` URL/Plain caught by pt-unc-path (`:` host widening, B3). Its
        // Base64Flat form is caught at 10c via base64-decode → the UNC string. Since the
        // share is the admin share `c$`, 10b-bis `pt-unc-admin-share` (Critical) now ALSO
        // fires on the decoded string.
        id: "pt-gotestwaf-unc-base64-query",
        module: Module::PathTraversal,
        field: Field::Query { name: "file", value: "XFw6OjFcYyRcdXNlcnNcZGVmYXVsdFxudHVzZXIuZGF0" },
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["pt-unc-admin-share"],
        desc: "base64(UNC `\\\\::1\\c$\\…`) — base64-decode → pt-unc-path + pt-unc-admin-share (10b-bis)",
    },
    // ── 10b-bis: UNC to an ADMINISTRATIVE share (`\\host\c$\…`) ───────────────────
    // WIRE (pcap bypass-new.txt L7918): gotestwaf path-traversal `\\::1\c$\users\default\
    // ntuser.dat`. Was sub-threshold (only pt-unc-path Notice=2); the admin-share (`$`)
    // anchor (Critical) now blocks it. Path-placed (URL-encoded backslashes) form.
    Case {
        id: "pt-unc-admin-share-wire",
        module: Module::PathTraversal,
        field: Field::Path("/%5C%5C::1%5Cc$%5Cusers%5Cdefault%5Cntuser.dat"),
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["pt-unc-admin-share"],
        desc: "WIRE: UNC admin-share `\\\\::1\\c$\\…ntuser.dat` in URL path — 10b-bis `$`-share anchor",
    },
    // Lock (probe-confirmed already CAUGHT, score 12 — the wire 200 was a stale binary):
    // multipart field-NAME carrying `../../etc/passwd` stays blocked.
    Case {
        id: "pt-lfi-multipart-name-wire",
        module: Module::PathTraversal,
        field: Field::MultipartFile { field: "/static/img/../../etc/passwd", filename: None, content: "x" },
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["pt-dotdot-traversal"],
        desc: "WIRE lock: `../../etc/passwd` in a multipart field NAME — pt-dotdot `{2,}` + \
               pt-sensitive-unix already catch it (regression guard)",
    },
    Case {
        // Overlong UTF-8 of `../../etc/passwd` (`%C0%AE`=`.`, `%C0%AF`=`/`), CAUGHT at
        // 10c: the overlong collapse (folded PIPELINE-WIDE into canonicalize_value)
        // resolves the bytes to `../../etc/passwd` → pt-sensitive-unix + pt-dotdot.
        // Bite-verified: break the overlong collapse → this goes RED.
        id: "pt-overlong-utf8-passwd-query",
        module: Module::PathTraversal,
        field: Field::RawQuery("file=%C0%AE%C0%AE%C0%AF%C0%AE%C0%AE%C0%AFetc%C0%AFpasswd"),
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["pt-sensitive-unix"],
        desc: "overlong-UTF8 `../../etc/passwd` — caught at 10c via overlong-decode in §6 \
               (the documented limit is now closed; pt-dotdot `{2,}` overlap declared)",
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
            filename: Some("report-2026.pdf"),
            content: "quarterly numbers",
        },
        min_pl: 1,
        expect: Expect::Clean,
        rules: &[],
        desc: "legit multipart upload filename (no `../`, no sensitive target) — field-coverage \
               must not turn ordinary filenames into false positives (10b-cont trap)",
    },
    Case {
        id: "pt-benign-multipart-name-value",
        module: Module::PathTraversal,
        field: Field::MultipartFile {
            field: "profile_photo",
            filename: None,
            content: "see docs/../report.pdf for the layout",
        },
        min_pl: 1,
        expect: Expect::Clean,
        rules: &[],
        desc: "ordinary part name + a value with a single benign `../` — name/value coverage \
               must stay Clean under pt-dotdot `{2,}` (10b-cont fix trap)",
    },
    // ── Fase 10c: nested-JSON recursion lock + JSON-leaf FP traps (FIX #1) ────────
    Case {
        id: "pt-wire-json-nested-overlong",
        module: Module::PathTraversal,
        field: Field::JsonBody(
            r#"{"outer": {"inner": ["x", "%25C0%25AE%25C0%25AE%25C0%25AFetc%25C0%25AFpasswd"]}}"#,
        ),
        min_pl: 1,
        expect: Expect::Triggers,
        // Recursion lock (guardrail #3): the overlong payload is nested under an object
        // AND inside an array. flatten_json descends both, so json_leaf_derived runs on
        // every leaf → the canonical `../etc/passwd` reaches the derived channel.
        rules: &["pt-sensitive-unix"],
        desc: "10c: NESTED JSON object+array leaf carrying overlong `../etc/passwd` — locks \
               recursive leaf canonicalization (a wrapper must not reintroduce the bypass)",
    },
    Case {
        id: "pt-benign-json-percent-path",
        module: Module::PathTraversal,
        field: Field::JsonBody(r#"{"path": "%2Fhome%2Fuser%2Freport.pdf"}"#),
        min_pl: 1,
        expect: Expect::Clean,
        rules: &[],
        desc: "10c FP trap: benign percent-encoded JSON leaf → `/home/user/report.pdf` (no `../`, \
               no sensitive target) must stay Clean after leaf canonicalization",
    },
    Case {
        id: "pt-benign-json-base64-text",
        module: Module::PathTraversal,
        field: Field::JsonBody(r#"{"note": "V2VsY29tZSB0byBvdXIgd2Vic2l0ZSwgZW5qb3kgeW91ciBzdGF5"}"#),
        min_pl: 1,
        expect: Expect::Clean,
        rules: &[],
        desc: "10c FP trap: benign base64 JSON leaf decoding to printable prose (no rule signature) \
               must stay Clean — decode-then-match-then-discard",
    },
    Case {
        id: "pt-benign-json-base64-entropy",
        module: Module::PathTraversal,
        field: Field::JsonBody(r#"{"token": "jyrRB7xEnm8D4VWq+xKQfcwx"}"#),
        min_pl: 1,
        expect: Expect::Clean,
        rules: &[],
        desc: "10c FP trap: high-entropy base64 JSON leaf (session-token-like) decodes to binary → \
               mostly_printable rejects it before the rules → must stay Clean",
    },
];
