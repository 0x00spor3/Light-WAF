// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

#![no_main]
//! Fuzz target for query parsing (DEC 2 #4): `parse_query` (split `&`/`=` on raw
//! bytes, then per-value canonicalize, with `max_params`). libFuzzer + ASan/UBSan
//! hunt for panic/OOB/hang; the target also re-checks the bound in process. A small
//! `max_params` so the limit path is exercised by the mutator.
//!
//! The composition/order invariants are the always-on guard in
//! `waf-normalizer/tests/query_robustness.rs` (proptest, cross-platform).

use libfuzzer_sys::fuzz_target;
use waf_core::LimitsConfig;
use waf_normalizer::url::parse_query;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let limits = LimitsConfig { max_params: 8, ..LimitsConfig::default() };
        if let Ok((params, _)) = parse_query(s, &limits) {
            assert!(params.len() <= limits.max_params);
        }
    }
});
