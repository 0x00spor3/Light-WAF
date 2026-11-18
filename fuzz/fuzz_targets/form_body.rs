// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

#![no_main]
//! Fuzz target for form-urlencoded body parsing (DEC 2 #7): `parse_form_urlencoded`
//! via `parse_body`. The input is a RAW body, so the fuzzer feeds arbitrary bytes
//! (the UTF-8 boundary is the point — the body is read with `lossy_text`). libFuzzer +
//! ASan/UBSan hunt for panic/OOB/hang; the target re-checks the bound and that the
//! form parses exactly like `parse_query` on its lossy text, so an invalid byte never
//! hides a parameter.
//!
//! The composition/UTF-8 invariants are the always-on guard in
//! `waf-normalizer/tests/form_robustness.rs` (proptest, cross-platform).

use libfuzzer_sys::fuzz_target;
use waf_core::{Bytes, LimitsConfig, ParsedBody};
use waf_normalizer::body::{lossy_text, parse_body};
use waf_normalizer::url::parse_query;

fuzz_target!(|data: &[u8]| {
    // `LimitsConfig` is `#[non_exhaustive]`: build from the default, then tweak.
    let mut limits = LimitsConfig::default();
    limits.max_params = 8;
    let form = match parse_body(
        Some("application/x-www-form-urlencoded"),
        &Bytes::copy_from_slice(data),
        &limits,
    ) {
        Ok(ParsedBody::FormUrlEncoded(params)) => {
            assert!(params.len() <= limits.max_params);
            Ok(params)
        }
        Ok(other) => panic!("form content-type must yield FormUrlEncoded, got {other:?}"),
        Err(_) => Err(()),
    };
    // Invalid bytes are replaced, never a reason to drop the form or part of it.
    let query = parse_query(&lossy_text(data), &limits)
        .map(|(params, _, _)| params)
        .map_err(|_| ());
    assert_eq!(form, query);
});
