// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

#![no_main]
//! Fuzz target for cookie parsing (DEC 2 #6): `parse_cookies_limited` (split `;`,
//! first `=`, OWS-trim, `max_cookies`). libFuzzer + ASan/UBSan hunt for
//! panic/OOB/hang; the target re-checks the bound in process. Small `max_cookies`
//! so the limit path is exercised.
//!
//! The RFC 6265 split/OWS invariants and the composition differential are the
//! always-on guard in `waf-normalizer/tests/cookie_robustness.rs` (proptest).

use libfuzzer_sys::fuzz_target;
use waf_normalizer::url::parse_cookies_limited;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        const MAX: usize = 8;
        if let Ok(cookies) = parse_cookies_limited(s, MAX) {
            assert!(cookies.len() <= MAX);
        }
    }
});
