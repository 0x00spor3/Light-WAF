//! Mail (SMTP/IMAP) command injection corpus cases (Fase 10a). Field: query.
//! Rule (paranoia): mail-command-injection 1 (Critical) — CR/LF + a mail verb.
//! Source: gotestwaf `mail-injection`. URL payloads are 10a Triggers; Base64Flat
//! duplicates are `ExpectedMiss{until_phase:"10c"}`.
//!
//! Declared overlap (§8): a mail payload's CR/LF also trips `header_injection`'s
//! CR/LF-in-query rule — defense-in-depth, attribution stays Mail. The benign guards are
//! CR/LF-FREE on purpose (bare CR/LF in a query is header_injection's concern, not benign).

use crate::{Case, Expect, Field, Module};

pub static CASES: &[Case] = &[
    // ── malicious (URL/Plain — 10a) ─────────────────────────────────────────────
    Case {
        id: "mail-imap-capability-query",
        module: Module::Mail,
        field: Field::Query { name: "id", value: "\r\nV100 CAPABILITY\r\nV101 FETCH 4791" },
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["mail-command-injection"],
        desc: "injected IMAP CAPABILITY/FETCH after CR/LF — gotestwaf mail-injection (URL)",
    },
    Case {
        id: "mail-smtp-quit-query",
        module: Module::Mail,
        field: Field::Query { name: "id", value: "\r\nQUIT\r\n" },
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["mail-command-injection"],
        desc: "injected SMTP QUIT after CR/LF — gotestwaf mail-injection (URL)",
    },
    Case {
        id: "mail-smtp-rcpt-query",
        module: Module::Mail,
        field: Field::Query { name: "to", value: "\nRCPT TO: test@evil.com\n" },
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["mail-command-injection"],
        desc: "injected SMTP RCPT TO after LF — gotestwaf mail-injection (URL)",
    },
    // ── Base64Flat duplicates — CAUGHT at 10c via §6 base64-decode (derived) ─────
    Case {
        id: "mail-imap-capability-b64",
        module: Module::Mail,
        field: Field::Query { name: "id", value: "VjEwMCBDQVBBQklMSVRZDQpWMTAxIEZFVENIIDQ3OTE" },
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["mail-command-injection"],
        desc: "base64(IMAP CAPABILITY + CRLF) — §6 base64-decode (10c) feeds the derived form to mail",
    },
    Case {
        id: "mail-smtp-quit-b64",
        module: Module::Mail,
        field: Field::Query { name: "id", value: "DQpRVUlUDQo=" },
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["mail-command-injection"],
        desc: "base64(`\\r\\nQUIT\\r\\n`) — the 12-char floor case; caught at 10c via base64-decode",
    },
    Case {
        id: "mail-smtp-rcpt-b64",
        module: Module::Mail,
        field: Field::Query { name: "to", value: "ClJDUFQgVE86IHRlc3RAZXZpbC5jb20K" },
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["mail-command-injection"],
        desc: "base64(`\\nRCPT TO: test@evil.com\\n`) — caught at 10c via base64-decode",
    },
    // ── URLPath coverage (10c REOPEN, pcap): CRLF survives path normalization ─────
    Case {
        id: "mail-urlpath-rcpt",
        module: Module::Mail,
        field: Field::Path("/x%0d%0aRCPT TO: test@evil.com%0d%0a"),
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["mail-command-injection"],
        desc: "SMTP RCPT injection in the URL PATH — gotestwaf mail-injection URLPath (overlaps hdr-crlf, declared)",
    },
    // ── benign guards (must stay 200): CR/LF-free, so they isolate the mail rule ──
    Case {
        id: "mail-benign-quit-word",
        module: Module::Mail,
        field: Field::Query { name: "msg", value: "please quit the app" },
        min_pl: 1,
        expect: Expect::Clean,
        rules: &[],
        desc: "the word `quit` without CR/LF — must NOT flag (rule requires the newline)",
    },
    Case {
        id: "mail-benign-verb-no-crlf",
        module: Module::Mail,
        field: Field::Query { name: "note", value: "MAIL FROM headquarters" },
        min_pl: 1,
        expect: Expect::Clean,
        rules: &[],
        desc: "`MAIL FROM` as prose with no CR/LF — the verb alone must NOT flag",
    },
    Case {
        id: "mail-benign-email",
        module: Module::Mail,
        field: Field::Query { name: "contact", value: "test@evil.com" },
        min_pl: 1,
        expect: Expect::Clean,
        rules: &[],
        desc: "a bare email address (no CR/LF, no verb) — must NOT flag",
    },
];
