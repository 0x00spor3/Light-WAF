// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

//! gRPC corpus cases. Two concerns, kept apart on purpose (the accounting paletto):
//!   - **CONTENT** (§6): a SQLi smuggled inside a protobuf string field is extracted to the
//!     derived channel and caught by the `sqli` module — credited to §6, NOT to gRPC.
//!   - **STRUCTURAL** (the `grpc` module): a depth-bomb → `Reject`; the benign-but-deep
//!     nesting trap stays within the cap → `Clean` (no false Reject — the negative
//!     reference that proves the depth cap distinguishes nesting from a bomb).
//!
//! The corpus harness enables the gRPC module at default caps (depth 16). The structural
//! caps (size/field/compressed/malformed) are exercised exhaustively by the module
//! integration tests in `waf-detection/tests/grpc.rs`.

use crate::{Case, Expect, Field, Module};

pub static CASES: &[Case] = &[
    // ── CONTENT path (§6) — credited to the content module, not grpc ─────────────
    Case {
        id: "grpc-sqli-in-field",
        module: Module::Sqli,
        field: Field::Grpc { value: "1 UNION SELECT a,b FROM users--" },
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["sqli-union-select"],
        desc: "SQLi inside a protobuf string field → extracted to the §6 derived channel and \
               caught by the sqli module (the catch is content, not structural)",
    },
    Case {
        id: "grpc-benign-field",
        module: Module::Grpc,
        field: Field::Grpc { value: "hello world, this is a perfectly fine field" },
        min_pl: 1,
        expect: Expect::Clean,
        rules: &[],
        desc: "an ordinary gRPC field is within all caps and matches no rule → Clean",
    },
    // ── STRUCTURAL (grpc module) ─────────────────────────────────────────────────
    Case {
        // Paletto A — the negative reference: legitimately nested, but UNDER the cap.
        id: "grpc-benign-deep-nesting",
        module: Module::Grpc,
        field: Field::GrpcNested { depth: 8, leaf: "benign-leaf" },
        min_pl: 1,
        expect: Expect::Clean,
        rules: &[],
        desc: "a legitimately deep but benign nested message (depth 8 < cap 16) must NOT \
               false-Reject — proves the depth cap distinguishes nesting from a depth-bomb",
    },
    Case {
        id: "grpc-depth-bomb",
        module: Module::Grpc,
        field: Field::GrpcNested { depth: 40, leaf: "x" },
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["grpc"],
        desc: "sub-message nesting beyond max_depth (16) — a depth-bomb DoS → Reject{400}",
    },
];
