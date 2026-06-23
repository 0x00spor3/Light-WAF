// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

#![no_main]
//! Fuzz target for the JSON flatten recursion (DEC 2 #5). The input bytes are parsed
//! as a JSON document via `parse_body` (the production path: serde_json parse, whose
//! depth is capped ~128, then our depth-limited `flatten_json`). libFuzzer +
//! ASan/UBSan hunt for panic/OOB/hang; the `-timeout` flag catches a runaway
//! recursion. A small `max_json_depth` so the depth guard is exercised.
//!
//! The recursion's depth-limit and leaf-count invariants are tested directly on
//! `serde_json::Value`s (bypassing serde's parse cap) in
//! `waf-normalizer/tests/json_robustness.rs` (proptest, cross-platform).

use libfuzzer_sys::fuzz_target;
use waf_core::{Bytes, LimitsConfig};
use waf_normalizer::body::parse_body;

fuzz_target!(|data: &[u8]| {
    let limits = LimitsConfig { max_json_depth: 6, ..LimitsConfig::default() };
    let _ = parse_body(Some("application/json"), &Bytes::copy_from_slice(data), &limits);
});
