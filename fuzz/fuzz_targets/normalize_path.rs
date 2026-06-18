#![no_main]
//! Fuzz target for path canonicalization (DEC 2 #3): `normalize_path` (decode +
//! NFKC + null-strip + lowercase + `..`/`//` resolution). libFuzzer + ASan/UBSan
//! hunt for panic/OOB/hang; the target ALSO re-checks the security invariant in
//! process, so a coverage-guided input that produces a residual `..` aborts.
//!
//! The same invariants are the always-on guard in
//! `waf-normalizer/tests/path_robustness.rs` (proptest, cross-platform).

use libfuzzer_sys::fuzz_target;
use waf_normalizer::url::normalize_path;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let (out, _) = normalize_path(s);
        // Security invariant: no traversal residue may survive canonicalization.
        assert!(out.starts_with('/'));
        assert!(!out.split('/').any(|seg| seg == ".." || seg == "."));
        assert!(!out.contains('\0'));
    }
});
