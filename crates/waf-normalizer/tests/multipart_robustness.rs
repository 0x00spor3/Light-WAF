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
//!
//! The second half pins the parse itself: well-formed bodies keep their exact fields and
//! stay off the whole-body fallback, malformed ones lose nothing. Verdicts on the same
//! shapes are in `waf-corpus` (`cases/multipart_framing.rs`, `tests/multipart_differential.rs`).

use proptest::prelude::*;
use waf_core::{Bytes, LimitsConfig, MultipartField, ParsedBody};
use waf_normalizer::body::{multipart_field_text, parse_body};

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

// ── well-formed bodies keep their exact parse ─────────────────────────────────

fn fields_of(content_type: &str, body: &[u8]) -> Vec<MultipartField> {
    let parsed = parse_body(
        Some(content_type),
        &Bytes::copy_from_slice(body),
        &LimitsConfig::default(),
    )
    .expect("multipart parsing never fails");
    match parsed {
        ParsedBody::Multipart(fields) => fields,
        other => panic!("expected Multipart, got {other:?}"),
    }
}

fn fallback_of(fields: &[MultipartField]) -> Option<String> {
    let last = fields.last()?;
    let synthetic = last.name.is_empty() && last.filename.is_none() && last.content_type.is_none();
    synthetic.then(|| String::from_utf8_lossy(&last.data).into_owned())
}

const CT: &str = "multipart/form-data; boundary=B";

proptest! {
    /// The no-regression invariant: what browsers and HTTP clients send is parsed to exactly
    /// its fields, with arbitrary content (binary too), and never reaches the fallback.
    #[test]
    fn prop_well_formed_parses_exactly(
        parts in prop::collection::vec(
            (
                "[a-z_]{1,8}",
                prop::option::of("[a-zA-Z0-9_.-]{0,12}"),
                prop::collection::vec(any::<u8>(), 0..64),
            ),
            1..6,
        ),
    ) {
        let mut body = Vec::new();
        for (name, filename, content) in &parts {
            body.extend_from_slice(b"--B\r\n");
            match filename {
                Some(f) => body.extend_from_slice(format!(
                    "Content-Disposition: form-data; name=\"{name}\"; filename=\"{f}\"\r\n\
                     Content-Type: application/octet-stream\r\n"
                ).as_bytes()),
                None => body.extend_from_slice(
                    format!("Content-Disposition: form-data; name=\"{name}\"\r\n").as_bytes(),
                ),
            }
            body.extend_from_slice(b"\r\n");
            body.extend_from_slice(content);
            body.extend_from_slice(b"\r\n");
        }
        body.extend_from_slice(b"--B--\r\n");

        // The boundary is chosen to be absent from the content: skip the rare input where
        // random bytes spelled it out.
        prop_assume!(!parts.iter().any(|(_, _, c)| c.windows(3).any(|w| w == b"--B")));

        let fields = fields_of(CT, &body);
        prop_assert_eq!(fields.len(), parts.len());
        for (field, (name, filename, content)) in fields.iter().zip(&parts) {
            prop_assert_eq!(&field.name, name);
            prop_assert_eq!(&field.filename, filename);
            prop_assert_eq!(field.data.as_ref(), content.as_slice());
        }
    }
}

#[test]
fn clients_in_the_wild_stay_off_the_fallback() {
    let wild: &[&[u8]] = &[
        // No trailing CRLF after the closing delimiter.
        b"--B\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\n1\r\n--B--",
        // Extra part headers some clients add.
        b"--B\r\nContent-Disposition: form-data; name=\"a\"\r\nContent-Length: 1\r\n\
          Content-Transfer-Encoding: binary\r\n\r\n1\r\n--B--\r\n",
        // A value that is empty, and unquoted attributes.
        b"--B\r\nContent-Disposition: form-data; name=a\r\n\r\n\r\n--B--\r\n",
        // A filename holding a semicolon: quoted, so nothing unusual.
        b"--B\r\nContent-Disposition: form-data; name=\"a\"; filename=\"x;y.txt\"\r\n\r\n1\r\n--B--\r\n",
    ];
    for body in wild {
        let fields = fields_of(CT, body);
        assert_eq!(fields.len(), 1, "body {:?}", String::from_utf8_lossy(body));
        assert_eq!(fields[0].name, "a");
    }
}

// ── malformed bodies: what gets extracted, and the fallback ───────────────────

#[test]
fn bare_lf_framing_extracts_the_field() {
    let fields = fields_of(CT, b"--B\nContent-Disposition: form-data; name=\"a\"\n\nvalue\n--B--\n");
    assert_eq!(fields[0].name, "a");
    assert_eq!(fields[0].data.as_ref(), b"value");
    assert!(fallback_of(&fields).is_some());
}

#[test]
fn unterminated_body_keeps_the_last_part() {
    let fields = fields_of(CT, b"--B\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nvalue");
    assert_eq!(fields[0].data.as_ref(), b"value");
    assert!(fallback_of(&fields).is_some());
}

#[test]
fn non_utf8_header_does_not_lose_later_parts() {
    let fields = fields_of(
        CT,
        b"--B\r\nContent-Disposition: form-data; name=\"a\"\r\nX-Pad: \xff\r\n\r\n1\r\n\
          --B\r\nContent-Disposition: form-data; name=\"b\"\r\n\r\n2\r\n--B--\r\n",
    );
    assert_eq!(fields[0].name, "a");
    assert_eq!(fields[1].name, "b");
}

#[test]
fn quoted_semicolon_stays_in_the_value() {
    let fields = fields_of(
        CT,
        b"--B\r\nContent-Disposition: form-data; name=\"a;b\"; filename=\"c;d\"\r\n\r\n1\r\n--B--\r\n",
    );
    assert_eq!(fields[0].name, "a;b");
    assert_eq!(fields[0].filename.as_deref(), Some("c;d"));
}

#[test]
fn folded_header_is_unfolded() {
    let fields = fields_of(CT, b"--B\r\nContent-Disposition: form-data;\r\n name=\"a\"\r\n\r\n1\r\n--B--\r\n");
    assert_eq!(fields[0].name, "a");
}

#[test]
fn extended_filename_drops_its_charset_prefix() {
    let fields = fields_of(
        CT,
        b"--B\r\nContent-Disposition: form-data; name=\"a\"; filename*=UTF-8''x%2Fy\r\n\r\n1\r\n--B--\r\n",
    );
    assert_eq!(fields[0].filename.as_deref(), Some("x%2Fy"));
}

#[test]
fn quoted_printable_is_decoded() {
    let fields = fields_of(
        CT,
        b"--B\r\nContent-Disposition: form-data; name=\"a\"\r\n\
          Content-Transfer-Encoding: quoted-printable\r\n\r\n=2Fetc=\r\n=2Fpasswd=\r\n--B--\r\n",
    );
    assert_eq!(fields[0].data.as_ref(), b"/etc/passwd=");
}

#[test]
fn fallback_keeps_no_framing_bytes() {
    let fields = fields_of(CT, b"--B\nContent-Disposition: form-data; name=\"a\"\n\nx\0y\n--B--\n");
    let text = fallback_of(&fields).unwrap();
    assert!(!text.contains(['\r', '\n', '\0']), "{text:?}");
    assert!(text.contains("name=\"a\""));
}

const BINARY_FILE: &[u8] = b"--B\nContent-Disposition: form-data; name=\"a\"; filename=\"f\"\n\n\xffSECRET\n--B--\n";

#[test]
fn fallback_leaves_out_binary_files() {
    let text = fallback_of(&fields_of(CT, BINARY_FILE)).unwrap();
    assert!(!text.contains("SECRET"), "{text:?}");
}

#[test]
fn fallback_keeps_a_file_that_holds_the_boundary() {
    // Werkzeug breaks lines on a bare CR, so `\r--B` ends this "file" for it and what
    // follows is a field. It must not leave the scan for looking like binary.
    let body = b"--B\r\nContent-Disposition: form-data; name=\"a\"; filename=\"f\"\r\n\r\n\xff\r--B\r\n\
                 Content-Disposition: form-data; name=\"q\"\r\n\r\nATTACK\r\n--B--\r\n";
    let text = fallback_of(&fields_of(CT, body)).unwrap();
    assert!(text.contains("ATTACK"), "{text:?}");
}

#[test]
fn nameless_parts_are_capped() {
    let limits = LimitsConfig::default();
    let body = "--B\r\n\r\n\r\n".repeat(limits.max_params * 3);
    let fields = fields_of(CT, body.as_bytes());
    // The cap, plus the whole-body field that still covers the rest.
    assert_eq!(fields.len(), limits.max_params + 1);
}

#[test]
fn empty_body_has_no_fields() {
    assert!(fields_of(CT, b"").is_empty());
}

#[test]
fn field_text_skips_only_real_binary_files() {
    let field = |filename: Option<&str>, data: &'static [u8]| MultipartField {
        name: "a".into(),
        filename: filename.map(Into::into),
        content_type: None,
        data: Bytes::from_static(data),
    };
    assert!(multipart_field_text(&field(Some("f"), b"\xff")).is_none());
    assert_eq!(multipart_field_text(&field(Some("f"), b"text")).unwrap(), "text");
    assert_eq!(multipart_field_text(&field(Some(""), b"\xffx")).unwrap(), "\u{FFFD}x");
    assert_eq!(multipart_field_text(&field(None, b"\xff\0x")).unwrap(), "\u{FFFD}x");
    assert_eq!(multipart_field_text(&field(None, b"a\0b")).unwrap(), "a\0b");
}
