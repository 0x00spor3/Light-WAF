#![no_main]
//! Fuzz target for the GraphQL lexer (Phase 11): `graphql_lex` — the 8th custom
//! parser. libFuzzer + ASan/UBSan hunt for panic/OOB/hang on hostile query text
//! (unterminated strings/block-strings/comments, unbalanced braces/parens, lone
//! control bytes). Linear-time by construction (the cursor advances every step);
//! the structural counts are bounded by the input length, re-checked in process.
//!
//! The paren-aware depth / string-skip invariants are pinned by the always-on unit
//! tests in `waf-normalizer/src/graphql.rs`.

use libfuzzer_sys::fuzz_target;
use waf_normalizer::graphql::graphql_lex;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let st = graphql_lex(s);
        // every count increment consumes at least one byte → bounded by len.
        let n = s.len() as u32;
        assert!(st.max_depth <= n);
        assert!(st.aliases <= n);
        assert!(st.fields <= n);
        assert!(st.directives <= n);
    }
});
