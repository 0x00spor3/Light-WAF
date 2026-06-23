//! Request-smuggling corpus cases. Structural module (framing, not content): runs
//! in the Connection phase on raw CL/TE headers and rejects illegal framing with
//! 400 (binary, single rule_id `request-smuggling`, no paranoia gating → min_pl 1).
//! Five framing checks: CL+TE, duplicate CL, malformed CL, duplicate TE,
//! non-`chunked` TE. Header names are lowercase (the proxy's context builder
//! lowercases before this phase).

use crate::{Case, Expect, Field, Module};

pub static CASES: &[Case] = &[
    // ── malicious: one per framing check ───────────────────────────────────────
    Case {
        id: "smuggling-cl-and-te",
        module: Module::RequestSmuggling,
        field: Field::Smuggling(&[("content-length", "10"), ("transfer-encoding", "chunked")]),
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["request-smuggling"],
        desc: "Content-Length and Transfer-Encoding both present",
    },
    Case {
        id: "smuggling-duplicate-cl",
        module: Module::RequestSmuggling,
        field: Field::Smuggling(&[("content-length", "10"), ("content-length", "20")]),
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["request-smuggling"],
        desc: "duplicate Content-Length headers",
    },
    Case {
        id: "smuggling-malformed-cl",
        module: Module::RequestSmuggling,
        field: Field::Smuggling(&[("content-length", "12a")]),
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["request-smuggling"],
        desc: "non-integer Content-Length value",
    },
    Case {
        id: "smuggling-duplicate-te",
        module: Module::RequestSmuggling,
        field: Field::Smuggling(&[("transfer-encoding", "chunked"), ("transfer-encoding", "chunked")]),
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["request-smuggling"],
        desc: "duplicate Transfer-Encoding headers",
    },
    Case {
        id: "smuggling-te-non-chunked",
        module: Module::RequestSmuggling,
        field: Field::Smuggling(&[("transfer-encoding", "gzip, chunked")]),
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["request-smuggling"],
        desc: "TE list / non-single-chunked token (strict posture)",
    },
    // ── benign ──────────────────────────────────────────────────────────────────
    Case {
        id: "smuggling-benign-single-cl",
        module: Module::RequestSmuggling,
        field: Field::Smuggling(&[("content-length", "42")]),
        min_pl: 1,
        expect: Expect::Clean,
        rules: &[],
        desc: "single valid Content-Length",
    },
    Case {
        id: "smuggling-benign-single-te",
        module: Module::RequestSmuggling,
        field: Field::Smuggling(&[("transfer-encoding", "chunked")]),
        min_pl: 1,
        expect: Expect::Clean,
        rules: &[],
        desc: "single valid chunked Transfer-Encoding",
    },
    Case {
        id: "smuggling-benign-te-case-insensitive",
        module: Module::RequestSmuggling,
        field: Field::Smuggling(&[("transfer-encoding", "CHUNKED")]),
        min_pl: 1,
        expect: Expect::Clean,
        rules: &[],
        desc: "chunked is matched case-insensitively",
    },
];
