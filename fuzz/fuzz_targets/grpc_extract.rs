// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

#![no_main]
//! Fuzz target for the gRPC framing + protobuf extractor (gRPC phase): `grpc_extract` —
//! the 9th custom parser. libFuzzer + ASan/UBSan hunt for panic/OOB/hang on hostile binary
//! input (truncated frames, bogus lengths, overlong varints, deep/illegal wire types). The
//! parse is linear and bounded by `GrpcLimits` (recursion depth, field count, leaf count);
//! the input bytes are an arbitrary gRPC body.
//!
//! The framing/heuristic invariants (UTF-8 leaf vs sub-message recursion, depth cap,
//! benign-nesting trap) are pinned by the always-on unit tests in
//! `waf-normalizer/src/grpc.rs`.

use libfuzzer_sys::fuzz_target;
use waf_normalizer::grpc::{grpc_extract, GrpcLimits};

fuzz_target!(|data: &[u8]| {
    let limits = GrpcLimits::default();
    let ex = grpc_extract(data, limits);
    // Bounds the parser must always honour.
    assert!(ex.max_depth <= limits.max_depth);
    assert!(ex.leaves.len() <= limits.max_leaves);
    // Every frame consumes its own 5-byte header + payload → bounded by len.
    assert!(ex.messages as usize <= data.len());
});
