//! Path normalization robustness — Fase 8, target DEC 2 #3 (`normalize_path` /
//! `resolve_path`: decode + NFKC + null-strip + lowercase + `..`/`//` resolution).
//!
//! Half differential, half robustness: there is no external oracle, but the RESOLVED
//! path must satisfy structural+security invariants that *characterize* a correct
//! canonicalization — in particular it can never carry a traversal residue:
//!   (i)   root-anchored: always starts with `/`;
//!   (ii)  NO residual `..` segment — `..` is always consumed (escape above root is
//!         clamped: `pop()` on an empty stack is a no-op, never goes negative);
//!   (iii) NO residual `.` segment;
//!   (iv)  NO `//` (empty segments collapsed);
//!   (v)   NO NUL byte (stripped);
//!   (vi)  NO ASCII uppercase (lowercased).
//! Plus (0) non-panic on arbitrary input.
//!
//! (ii) is the security invariant: if it ever fails, a `../` survived canonicalization
//! → path-traversal bypass. cargo-fuzz adds coverage-guided depth on Linux.

use proptest::prelude::*;
use waf_normalizer::url::normalize_path;

fn check_invariants(input: &str) {
    let (out, _) = normalize_path(input);
    assert!(out.starts_with('/'), "(i) not root-anchored: {out:?} from {input:?}");
    for seg in out.split('/') {
        assert_ne!(seg, "..", "(ii) residual traversal segment: {out:?} from {input:?}");
        assert_ne!(seg, ".", "(iii) residual dot segment: {out:?} from {input:?}");
    }
    assert!(!out.contains("//"), "(iv) double slash: {out:?} from {input:?}");
    assert!(!out.contains('\0'), "(v) NUL survived: {out:?} from {input:?}");
    assert!(
        !out.chars().any(|c| c.is_ascii_uppercase()),
        "(vi) ASCII uppercase survived: {out:?} from {input:?}"
    );
}

proptest! {
    // Path-token biased: stresses the `..`/`.`/`/` resolver with percent-encoding.
    #[test]
    fn prop_path_invariants_structured(
        s in "(/|\\.\\.|\\.|%[0-9a-fA-F]{0,2}|[a-zA-Z0-9_]){0,40}",
    ) {
        check_invariants(&s);
    }
}

proptest! {
    // Broad: arbitrary unicode (incl. NUL, fullwidth, combining) — non-panic + the
    // same invariants must still hold.
    #[test]
    fn prop_path_invariants_arbitrary(s in ".{0,64}") {
        check_invariants(&s);
    }
}

#[test]
fn known_traversal_is_neutralized() {
    // Fixed witnesses for (i)+(ii): traversal and over-popping are clamped to root.
    for (input, expect) in [
        ("/a/b/../c", "/a/c"),
        ("/../../../etc/passwd", "/etc/passwd"),
        ("/a/./b", "/a/b"),
        ("//a//b", "/a/b"),
        ("/%2e%2e/x", "/x"),       // encoded `..` is decoded then consumed
    ] {
        let (out, _) = normalize_path(input);
        assert_eq!(out, expect, "input {input:?}");
        assert!(!out.split('/').any(|s| s == ".."), "residual .. in {out:?}");
    }
}
