// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

#![no_main]
//! Fuzz target for the custom binary multipart parser (DEC 2 #2): `parse_multipart`
//! / `find_bytes` / `parse_part_headers`. libFuzzer + ASan/UBSan + the `-timeout`
//! flag hunt for panic, OOB, overflow and HANGS (the parser is byte-indexed with
//! state — the classic place for non-terminating loops). The robustness invariants
//! (non-panic, #parts bounded) also live in
//! `waf-normalizer/tests/multipart_robustness.rs` (proptest, cross-platform).
//!
//! The fuzzer controls BOTH the boundary and the body, since both come from the
//! attacker (the Content-Type header and the request body).

use libfuzzer_sys::fuzz_target;
use waf_core::{Bytes, LimitsConfig};
use waf_normalizer::body::parse_body;

fuzz_target!(|data: &[u8]| {
    // Split the input: first byte picks a short boundary length, rest is the body.
    let (boundary, body) = match data.split_first() {
        Some((&n, rest)) => {
            let blen = (n as usize) % 16;
            let blen = blen.min(rest.len());
            let (b, body) = rest.split_at(blen);
            (String::from_utf8_lossy(b).into_owned(), body.to_vec())
        }
        None => (String::new(), Vec::new()),
    };
    let ct = format!("multipart/form-data; boundary={boundary}");
    let _ = parse_body(Some(&ct), &Bytes::from(body), &LimitsConfig::default());
});
