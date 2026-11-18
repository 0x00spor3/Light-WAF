// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

//! Form-urlencoded body robustness — Fase 8, target DEC 2 #7 (`parse_form_urlencoded`).
//!
//! The split/canonicalize/bound mechanics are SHARED with `parse_query` (#4) and not
//! re-proven from scratch — `parse_query` is reused as the oracle. The NEW surface is
//! the UTF-8 boundary: the body is raw `&[u8]`, decoded with `from_utf8_lossy`.
//!
//! Pinned invariants:
//!   (1) non-panic + bounded on ARBITRARY bytes (not just valid `&str` like #4);
//!   (2a) valid-UTF-8 body behaves EXACTLY like `parse_query` on the same text;
//!   (2b) ANY invalid byte → every parameter is still extracted, like `parse_query` on
//!        the lossy text. Backends split on `&` and `=` whatever the bytes are, so neither
//!        an empty parse nor a partial one is acceptable: both hide parameters the
//!        application reads. Empty is what this used to do, and it was a bypass: one
//!        `0xFF` anywhere took the whole form out of inspection.

use proptest::prelude::*;
use waf_core::{Bytes, LimitsConfig, ParsedBody};
use waf_normalizer::body::{lossy_text, parse_body};
use waf_normalizer::url::parse_query;

/// Parse a form body, returning the params or `Err(())` on `TooManyParams`.
fn parse_form(body: &[u8], limits: &LimitsConfig) -> Result<Vec<(String, String)>, ()> {
    match parse_body(
        Some("application/x-www-form-urlencoded"),
        &Bytes::copy_from_slice(body),
        limits,
    ) {
        Ok(ParsedBody::FormUrlEncoded(p)) => Ok(p),
        Ok(other) => unreachable!("form content-type must yield FormUrlEncoded, got {other:?}"),
        Err(_) => Err(()),
    }
}

fn limits(max_params: usize) -> LimitsConfig {
    let mut l = LimitsConfig::default();
    l.max_params = max_params;
    l
}

proptest! {
    // (2a) valid UTF-8 → identical to parse_query (the #4-proven reference). Same
    // biased alphabet as #4 (delimiters, encoded delimiters, `+`).
    #[test]
    fn prop_form_valid_utf8_equals_query(s in "(&|=|%26|%3D|%25|[a-z0-9+]){0,60}") {
        let lim = limits(8);
        let form = parse_form(s.as_bytes(), &lim);
        let query = parse_query(&s, &lim).map(|(p, _, _)| p).map_err(|_| ());
        prop_assert_eq!(form, query);
    }
}

proptest! {
    // (1)+(2b) arbitrary BYTES: non-panic, bounded, and identical to the lossy text.
    #[test]
    fn prop_form_arbitrary_bytes_parse_as_lossy_text(body in prop::collection::vec(any::<u8>(), 0..256)) {
        let lim = limits(8);
        let res = parse_form(&body, &lim);
        if let Ok(params) = &res {
            prop_assert!(params.len() <= lim.max_params);
        }
        let text = lossy_text(&body);
        let query = parse_query(&text, &lim).map(|(p, _, _)| p).map_err(|_| ());
        prop_assert_eq!(res, query);
    }
}

#[test]
fn invalid_byte_keeps_every_parameter() {
    let lim = LimitsConfig::default();
    let pair = |k: &str, v: &str| (k.to_string(), v.to_string());
    assert_eq!(parse_form(b"a=b\xFF", &lim), Ok(vec![pair("a", "b\u{FFFD}")]));
    assert_eq!(parse_form(b"\xFFa=b", &lim), Ok(vec![pair("\u{FFFD}a", "b")]));
    // A run of invalid bytes counts as one.
    assert_eq!(parse_form(b"a=\xFF\xFF\xFFb", &lim), Ok(vec![pair("a", "\u{FFFD}b")]));
    assert_eq!(
        parse_form(b"a=b&x=\xFF&c=d", &lim),
        Ok(vec![pair("a", "b"), pair("x", "\u{FFFD}"), pair("c", "d")])
    );
}

#[test]
fn valid_utf8_form_parses_like_query() {
    let lim = LimitsConfig::default();
    assert_eq!(
        parse_form(b"a=b&c=d", &lim),
        Ok(vec![("a".to_string(), "b".to_string()), ("c".to_string(), "d".to_string())])
    );
    // `+` → space (form convention, shared with query).
    assert_eq!(parse_form(b"a=x+y", &lim), Ok(vec![("a".to_string(), "x y".to_string())]));
}
