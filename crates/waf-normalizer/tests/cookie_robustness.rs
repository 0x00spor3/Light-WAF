// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

//! Cookie parsing robustness — Fase 8, target DEC 2 #6 (`parse_cookies_limited`:
//! split on `;` (RFC 6265), first `=`, OWS-trimmed, `max_cookies` enforced).
//!
//! Close to #4 (query) but the RFC 6265 DIFFERENCES are where bypasses live:
//!   - delimiter is `;` (NOT `&`); name/value split on the FIRST `=` only (a value
//!     may contain `=`, e.g. base64 padding `==` or a JWT);
//!   - OWS after `;` is trimmed: `a=1; b=2` == `a=1;b=2`;
//!   - `+` is LITERAL in cookies (canonicalized downstream with plus=false), unlike
//!     query where `+` → space.
//!
//! Declared decision (sfumatura 3): `parse_cookies_limited` does NOT canonicalize —
//! it only splits and trims. Canonicalization (`canonicalize_value(_, false)`, `+`
//! literal) is applied DOWNSTREAM by the normalizer. This is intentional (cookie
//! names are restricted tokens), not an omission. The full-path `+`-literal behaviour
//! is pinned by `cookie_plus_is_literal_query_plus_is_space` below.
//!
//! The split differential reuses the #4 approach (it minimized an unforeseen
//! counterexample there); canonicalize_value itself is #1's job, not re-tested here.

use proptest::prelude::*;
use waf_core::{Bytes, LimitsConfig, Normalized, RequestContext};
use waf_normalizer::url::parse_cookies_limited;
use waf_normalizer::Normalizer;

/// Independent split: `;` → first `=` → trim. No canonicalization (matches the
/// production split layer).
fn oracle(header: &str, max: usize) -> Result<Vec<(String, String)>, ()> {
    let mut out = Vec::new();
    for pair in header.split(';') {
        let pair = pair.trim();
        if pair.is_empty() {
            continue;
        }
        if out.len() >= max {
            return Err(());
        }
        let (k, v) = match pair.find('=') {
            Some(p) => (pair[..p].trim(), pair[p + 1..].trim()),
            None => (pair, ""),
        };
        out.push((k.to_string(), v.to_string()));
    }
    Ok(out)
}

proptest! {
    // Biased toward `;`, `=`, internal `==`, OWS (space) and flooding — arbitrary
    // input does not stress the RFC boundary (the #3/#4 lesson). Small max so the
    // bound is hit.
    #[test]
    fn prop_cookies_matches_split_oracle(s in "(;| |=|==|[a-z0-9]){0,60}") {
        let max = 5;
        let ours = parse_cookies_limited(&s, max).map_err(|_| ());
        prop_assert_eq!(ours, oracle(&s, max));
    }
}

proptest! {
    #[test]
    fn prop_cookies_non_panic_and_bounded(s in ".{0,128}") {
        if let Ok(cookies) = parse_cookies_limited(&s, 5) {
            prop_assert!(cookies.len() <= 5);
        }
    }
}

#[test]
fn rfc6265_split_and_ows() {
    // (2) internal `=` stays in the value (base64 padding / JWT).
    assert_eq!(
        parse_cookies_limited("a=b=c", 10).unwrap(),
        vec![("a".to_string(), "b=c".to_string())]
    );
    // (2) OWS after `;` is trimmed → identical to the no-space form.
    assert_eq!(
        parse_cookies_limited("a=1; b=2", 10).unwrap(),
        parse_cookies_limited("a=1;b=2", 10).unwrap()
    );
    assert_eq!(
        parse_cookies_limited("a=1; b=2", 10).unwrap(),
        vec![("a".to_string(), "1".to_string()), ("b".to_string(), "2".to_string())]
    );
}

#[test]
fn cookie_degenerates_do_not_inflate() {
    assert!(parse_cookies_limited(";;;;", 10).unwrap().is_empty());
    assert!(parse_cookies_limited("; ; ;", 10).unwrap().is_empty());
    assert_eq!(parse_cookies_limited("=", 10).unwrap(), vec![("".to_string(), "".to_string())]);
    // RFC: a name-only cookie (no `=`) is accepted as name with empty value.
    assert_eq!(parse_cookies_limited("flag", 10).unwrap(), vec![("flag".to_string(), "".to_string())]);
    assert_eq!(parse_cookies_limited("a=", 10).unwrap(), vec![("a".to_string(), "".to_string())]);
}

#[test]
fn over_limit_rejects_deterministically() {
    assert!(parse_cookies_limited("a=1;b=2;c=3", 3).is_ok());
    assert!(parse_cookies_limited("a=1;b=2;c=3;d=4", 3).is_err());
}

// ── full path: `+` literal in cookies vs `+` → space in query ─────────────────

fn ctx() -> RequestContext {
    RequestContext {
        client_ip: "127.0.0.1".parse().unwrap(),
        request_id: "t".to_string(),
        timestamp: std::time::SystemTime::now(),
        method: "GET".to_string(),
        path: "/".to_string(),
        raw_path: "/".to_string(),
        query: None,
        http_version: "HTTP/1.1".to_string(),
        headers: vec![],
        cookies: vec![],
        body: Bytes::new(),
        normalized: Normalized::default(),
        score: 0,
        score_contributions: vec![],
    }
}

#[test]
fn cookie_plus_is_literal_query_plus_is_space() {
    let norm = Normalizer::new(&LimitsConfig::default());

    // Cookie: `+` is literal (RFC 6265, canonicalize_value plus=false).
    let mut c = ctx();
    c.headers = vec![("cookie".to_string(), "c=a+b".to_string())];
    norm.normalize(&mut c).unwrap();
    assert_eq!(c.normalized.cookies, vec![("c".to_string(), "a+b".to_string())]);

    // Query: `+` decodes to space (form convention).
    let mut q = ctx();
    q.query = Some("c=a+b".to_string());
    norm.normalize(&mut q).unwrap();
    assert_eq!(q.normalized.query_params, vec![("c".to_string(), "a b".to_string())]);
}
