#![no_main]
//! Fuzz target for the highest-risk custom parser (DEC 2 #1): the percent-decoder
//! and `canonicalize_value`. libFuzzer + ASan/UBSan hunt for panic, OOB, integer
//! overflow and hangs on adversarial input. The differential A/B/C invariants are
//! NOT here — they live in `waf-normalizer/tests/differential.rs` (proptest,
//! cross-platform). This target's job is crash/hang discovery via coverage-guided
//! mutation; a found crash is minimized and promoted to a permanent regression test.

use libfuzzer_sys::fuzz_target;
use waf_normalizer::url::{canonicalize_value, percent_decode};

fuzz_target!(|data: &[u8]| {
    // The production code receives a `&str` (hyper already validated UTF-8 framing
    // for header/query values); mirror that by only decoding valid UTF-8 slices.
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = percent_decode(s, true);
        let _ = percent_decode(s, false);
        let _ = canonicalize_value(s, true);
        let _ = canonicalize_value(s, false);
    }
});
