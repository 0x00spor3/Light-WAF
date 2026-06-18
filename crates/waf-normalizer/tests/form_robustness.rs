//! Form-urlencoded body robustness — Fase 8, target DEC 2 #7 (`parse_form_urlencoded`).
//!
//! The split/canonicalize/bound mechanics are SHARED with `parse_query` (#4) and not
//! re-proven from scratch — `parse_query` is reused as the oracle. The NEW surface is
//! the UTF-8 boundary: the body is raw `&[u8]`, decoded with
//! `from_utf8(body).unwrap_or("")`.
//!
//! Pinned invariants:
//!   (1) non-panic + bounded on ARBITRARY bytes (not just valid `&str` like #4);
//!   (2a) valid-UTF-8 body behaves EXACTLY like `parse_query` on the same text;
//!   (2b) ANY invalid byte → `Ok([])` — ALL-OR-NOTHING, never a partial parse of the
//!        valid prefix (a partial contract would let an attacker smuggle a param as
//!        "valid prefix + invalid byte");
//!   (2c) the boundary is `from_utf8` strict→empty, NOT `from_utf8_lossy`→replacement.
//!
//! Declared (verbale, like the cookie non-canonicalization in #6): the form body uses
//! **strict `from_utf8` → empty** on invalid UTF-8, which is the OPPOSITE policy of
//! the value canonicalizer (#1/#3), where overlong/invalid bytes become the
//! replacement char (lossy). Different boundaries, different policies — intentional.

use proptest::prelude::*;
use waf_core::{Bytes, LimitsConfig, ParsedBody};
use waf_normalizer::body::parse_body;
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
    LimitsConfig { max_params, ..LimitsConfig::default() }
}

proptest! {
    // (2a) valid UTF-8 → identical to parse_query (the #4-proven reference). Same
    // biased alphabet as #4 (delimiters, encoded delimiters, `+`).
    #[test]
    fn prop_form_valid_utf8_equals_query(s in "(&|=|%26|%3D|%25|[a-z0-9+]){0,60}") {
        let lim = limits(8);
        let form = parse_form(s.as_bytes(), &lim);
        let query = parse_query(&s, &lim).map(|(p, _)| p).map_err(|_| ());
        prop_assert_eq!(form, query);
    }
}

proptest! {
    // (1)+(2b) arbitrary BYTES: non-panic, bounded, and all-or-nothing on invalid UTF-8.
    #[test]
    fn prop_form_arbitrary_bytes_all_or_nothing(body in prop::collection::vec(any::<u8>(), 0..256)) {
        let lim = limits(8);
        let res = parse_form(&body, &lim);
        if let Ok(params) = &res {
            prop_assert!(params.len() <= lim.max_params);
        }
        // Invalid UTF-8 anywhere → the WHOLE body is dropped (empty), never partial.
        if std::str::from_utf8(&body).is_err() {
            prop_assert_eq!(res, Ok(Vec::new()));
        }
    }
}

#[test]
fn invalid_byte_drops_whole_body_not_partial() {
    let lim = LimitsConfig::default();
    // (2b) valid prefix + one invalid byte → [] (NOT [("a","b")]).
    assert_eq!(parse_form(b"a=b\xFF", &lim), Ok(Vec::new()));
    assert_eq!(parse_form(b"\xFFa=b", &lim), Ok(Vec::new()));
    assert_eq!(parse_form(b"a=b&c=d\xFF", &lim), Ok(Vec::new()));
    // (2c) NOT lossy: the invalid byte must NOT survive as a replacement char.
    let r = parse_form(b"a=b\xFF", &lim).unwrap();
    assert!(r.is_empty(), "strict→empty, not lossy replacement: {r:?}");
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
