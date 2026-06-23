// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

#![no_main]
//! Fuzz target for form-urlencoded body parsing (DEC 2 #7): `parse_form_urlencoded`
//! via `parse_body`. The input is a RAW body, so the fuzzer feeds arbitrary bytes
//! (the UTF-8 boundary is the point — `from_utf8(body).unwrap_or("")`). libFuzzer +
//! ASan/UBSan hunt for panic/OOB/hang; the target re-checks the bound + the
//! all-or-nothing UTF-8 contract in process.
//!
//! The composition/UTF-8 invariants are the always-on guard in
//! `waf-normalizer/tests/form_robustness.rs` (proptest, cross-platform).

use libfuzzer_sys::fuzz_target;
use waf_core::{Bytes, LimitsConfig, ParsedBody};
use waf_normalizer::body::parse_body;

fuzz_target!(|data: &[u8]| {
    let limits = LimitsConfig { max_params: 8, ..LimitsConfig::default() };
    if let Ok(ParsedBody::FormUrlEncoded(params)) = parse_body(
        Some("application/x-www-form-urlencoded"),
        &Bytes::copy_from_slice(data),
        &limits,
    ) {
        assert!(params.len() <= limits.max_params);
        // All-or-nothing: invalid UTF-8 anywhere → empty, never a partial parse.
        if std::str::from_utf8(data).is_err() {
            assert!(params.is_empty());
        }
    }
});
