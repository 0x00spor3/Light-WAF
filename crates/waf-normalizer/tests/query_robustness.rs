// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

//! Query parsing robustness — Fase 8, target DEC 2 #4 (`parse_query`: split `&`/`=`
//! on RAW bytes, then per-value `canonicalize_value`, with `max_params` enforced).
//!
//! Not a value-canonicalization re-test (that is #1). Here the invariants are about
//! COMPOSITION and the split/decode boundary:
//!   (1) non-panic on arbitrary input;
//!   (2) bounded: on `Ok`, #params <= max_params; degenerate separators (`&&&`, `=`,
//!       `&=&`) never inflate the count (empty pairs are skipped);
//!   (3) canonicalize is applied to EVERY key AND value (a key escaping it = a
//!       rule that matches on the parameter name could be evaded);
//!   (4) split happens on RAW `&`/`=` BEFORE decode: an encoded `%26`/`%3D` inside a
//!       value must NOT act as a delimiter (`a=b%26c` → ONE param `a` = `b&c`).
//!
//! The oracle is an independent split that reuses `canonicalize_value` (the function
//! #1 already covers): so this tests that `parse_query` splits correctly and applies
//! canonicalize to each piece — not the canonicalization itself.

use proptest::prelude::*;
use waf_core::LimitsConfig;
use waf_normalizer::url::{canonicalize_value, parse_query};

/// Independent split-then-canonicalize reference. Splits on raw `&`, then on the
/// first raw `=`, skips empty pairs, enforces `max_params` (reject on overflow),
/// and canonicalizes each key and value (query mode: `+` → space).
fn oracle(query: &str, max_params: usize) -> Result<Vec<(String, String)>, ()> {
    let mut out = Vec::new();
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        if out.len() >= max_params {
            return Err(());
        }
        let (k, v) = match pair.find('=') {
            Some(p) => (&pair[..p], &pair[p + 1..]),
            None => (pair, ""),
        };
        out.push((canonicalize_value(k, true).0, canonicalize_value(v, true).0));
    }
    Ok(out)
}

fn limits(max_params: usize) -> LimitsConfig {
    LimitsConfig { max_params, ..LimitsConfig::default() }
}

proptest! {
    // Biased toward delimiters (`&`/`=`), encoded delimiters (`%26`/`%3D`), double
    // encoding (`%25`) and param-flooding — pure arbitrary input does not stress the
    // split/decode boundary (the #3 lesson). Small max_params so the bound is hit.
    #[test]
    fn prop_query_matches_split_then_canonicalize(
        s in "(&|=|%26|%3D|%25|[a-z0-9]){0,60}",
    ) {
        let lim = limits(8);
        let ours = parse_query(&s, &lim).map(|(p, _, _)| p).map_err(|_| ());
        prop_assert_eq!(ours, oracle(&s, lim.max_params));
    }
}

proptest! {
    // Floor: arbitrary unicode, non-panic + the bound holds on Ok.
    #[test]
    fn prop_query_non_panic_and_bounded(s in ".{0,128}") {
        let lim = limits(8);
        if let Ok((params, _, _)) = parse_query(&s, &lim) {
            prop_assert!(params.len() <= lim.max_params);
        }
    }
}

#[test]
fn encoded_delimiters_stay_in_value() {
    let l = LimitsConfig::default();
    // (4) `%26` (&) inside a value is NOT a delimiter → one param, value "b&c".
    let (p, _, _) = parse_query("a=b%26c", &l).unwrap();
    assert_eq!(p, vec![("a".to_string(), "b&c".to_string())]);
    // (4) `%3D` (=) inside a value is NOT a delimiter → value "b=c".
    let (p, _, _) = parse_query("a=b%3Dc", &l).unwrap();
    assert_eq!(p, vec![("a".to_string(), "b=c".to_string())]);
    // First raw `=` splits; later raw `=` stays in the value.
    let (p, _, _) = parse_query("a=b=c", &l).unwrap();
    assert_eq!(p, vec![("a".to_string(), "b=c".to_string())]);
}

#[test]
fn degenerate_separators_do_not_inflate_count() {
    let l = LimitsConfig::default();
    // (2) only `&`s → all pairs empty → zero params (not N empty params).
    assert!(parse_query("&&&&", &l).unwrap().0.is_empty());
    // A lone `=` is one param ("", "").
    assert_eq!(parse_query("=", &l).unwrap().0, vec![("".to_string(), "".to_string())]);
    // Key without value.
    assert_eq!(parse_query("k", &l).unwrap().0, vec![("k".to_string(), "".to_string())]);
}

#[test]
fn over_limit_is_rejected_deterministically() {
    // (2) at the limit parse_query REJECTS (TooManyParams), it does not truncate.
    let lim = limits(3);
    assert!(parse_query("a&b&c", &lim).is_ok()); // exactly 3 → ok
    assert!(parse_query("a&b&c&d", &lim).is_err()); // 4 → reject
}
