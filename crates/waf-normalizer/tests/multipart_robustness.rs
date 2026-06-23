// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

//! Multipart robustness — Fase 8, target DEC 2 #2 (the custom binary parser:
//! `parse_multipart` / `find_bytes` / `parse_part_headers`, byte-indexed with state).
//!
//! Multipart has NO sensible differential oracle (it is not an invertible transform
//! against an "obviously correct" reference — it is a stateful binary parser). So
//! the focus is ROBUSTNESS INVARIANTS, not equivalence:
//!   (1) NON-PANIC on arbitrary input (missing/empty/prefix boundary, stray CRLF,
//!       malformed part headers, no closing boundary, truncated mid-scan);
//!   (2) BOUNDED termination: #parts <= body length (each part consumes >=1 byte →
//!       no infinite loop producing unbounded parts);
//!   (3) NO out-of-range index in find_bytes/parse_part_headers — in this safe-Rust
//!       parser an OOB IS a panic, so (1) already covers it. ASan (cargo-fuzz) adds
//!       value chiefly if `unsafe` is ever introduced.
//!
//! cargo-fuzz (`fuzz/fuzz_targets/multipart.rs`) adds coverage-guided depth on Linux;
//! these properties are the always-on cross-platform guard in `cargo test`.

use proptest::prelude::*;
use waf_core::{Bytes, LimitsConfig, ParsedBody};
use waf_normalizer::body::parse_body;

/// Run the multipart parser the way the normalizer does, and assert the robustness
/// invariants. `boundary` may be empty (→ delimiter `--`), a stress case.
fn check_multipart(boundary: &str, body: Vec<u8>) {
    let ct = format!("multipart/form-data; boundary={boundary}");
    let len = body.len();
    // (1) NON-PANIC: parse_body must return, never panic (a panic fails the test).
    let parsed = parse_body(Some(&ct), &Bytes::from(body), &LimitsConfig::default());
    if let Ok(ParsedBody::Multipart(fields)) = parsed {
        // (2) BOUNDED: each extracted part consumes >=1 input byte.
        assert!(
            fields.len() <= len,
            "unbounded parts: {} fields from {len} bytes",
            fields.len()
        );
    }
}

// ── (1)+(2) on broadly arbitrary input ────────────────────────────────────────

proptest! {
    #[test]
    fn prop_multipart_arbitrary_never_panics(
        boundary in "[a-zA-Z0-9]{0,8}",
        body in prop::collection::vec(any::<u8>(), 0..512),
    ) {
        check_multipart(&boundary, body);
    }
}

// ── (1)+(2) on STRUCTURED-but-fuzzy input (reaches deep parser paths) ──────────

#[derive(Debug, Clone)]
enum Tok {
    Delim,          // --<boundary>
    EndDelim,       // --<boundary>--
    Crlf,
    Dashes,         // --
    Disposition,    // a Content-Disposition header line
    ContentType,    // a Content-Type header line
    Junk(Vec<u8>),  // arbitrary bytes
}

fn tok() -> impl Strategy<Value = Tok> {
    prop_oneof![
        Just(Tok::Delim),
        Just(Tok::EndDelim),
        Just(Tok::Crlf),
        Just(Tok::Dashes),
        Just(Tok::Disposition),
        Just(Tok::ContentType),
        prop::collection::vec(any::<u8>(), 0..16).prop_map(Tok::Junk),
    ]
}

fn render(boundary: &str, toks: &[Tok]) -> Vec<u8> {
    let mut out = Vec::new();
    for t in toks {
        match t {
            Tok::Delim => {
                out.extend_from_slice(b"--");
                out.extend_from_slice(boundary.as_bytes());
            }
            Tok::EndDelim => {
                out.extend_from_slice(b"--");
                out.extend_from_slice(boundary.as_bytes());
                out.extend_from_slice(b"--");
            }
            Tok::Crlf => out.extend_from_slice(b"\r\n"),
            Tok::Dashes => out.extend_from_slice(b"--"),
            Tok::Disposition => {
                out.extend_from_slice(b"content-disposition: form-data; name=\"f\"")
            }
            Tok::ContentType => out.extend_from_slice(b"content-type: text/plain"),
            Tok::Junk(b) => out.extend_from_slice(b),
        }
    }
    out
}

proptest! {
    #[test]
    fn prop_multipart_structured_never_panics(
        boundary in "[a-zA-Z0-9]{0,6}",
        toks in prop::collection::vec(tok(), 0..40),
    ) {
        check_multipart(&boundary, render(&boundary, &toks));
    }
}
