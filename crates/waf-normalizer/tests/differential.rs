//! Differential canonicalization — Fase 8, smoke (target DEC 2 #1: the custom
//! percent-decoder / `canonicalize_value`, the security-critical anti-evasion code).
//!
//! Cross-platform, runs in `cargo test` (the always-on guard; cargo-fuzz adds
//! coverage-guided depth in CI). The oracle is an INDEPENDENT naive decoder with no
//! shared code, so a shared bug cannot mask itself.
//!
//! Equivalence relation (the part where a bypass hides):
//!
//! - (A) single-pass decode == oracle, BYTE-EXACT — pure correctness of our loop.
//! - (B) the canonical is an NFKC fixed-point — proves NFKC was actually applied.
//! - (C) vs full `decode_until_stable`, our canonical is a fixed point bounded by
//!   `PIPELINE_CAP` (=5) shared passes (Fase 10c, was 2). It diverges from the
//!   unbounded oracle ONLY on inputs encoded >5 times. The test FALSIFIES this in
//!   both directions: `<=2`-encoded must NOT diverge (property), and a known
//!   6-level encoding MUST diverge as predicted — so the §6 cap is itself under test.
//!
//! Overlong UTF-8 (Fase 10c): `%C0%AE`→`.`, `%C0%AF`→`/` are now DECODED before the
//! lossy UTF-8 step (the overlong path-traversal evasion is closed). The oracle is
//! overlong-aware too (independent reimplementation), so it stays WAF==oracle.

use proptest::prelude::*;
use unicode_normalization::UnicodeNormalization;
use waf_normalizer::url::{canonicalize_value, percent_decode};

// ── independent oracle (no shared code with production) ───────────────────────

fn hexval(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Naive single-pass percent decoder. Uses slice `.get()` so its bounds logic does
/// not share production's `i + 2 < len` arithmetic — an off-by-one would surface.
fn naive_decode(input: &str, plus: bool) -> String {
    let b = input.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if plus && c == b'+' {
            out.push(b' ');
            i += 1;
        } else if c == b'%' {
            match (
                b.get(i + 1).copied().and_then(hexval),
                b.get(i + 2).copied().and_then(hexval),
            ) {
                (Some(h), Some(l)) => {
                    out.push((h << 4) | l);
                    i += 3;
                }
                _ => {
                    out.push(c);
                    i += 1;
                }
            }
        } else {
            out.push(c);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// True if another decode pass would still change the string (more `%XX` present).
fn has_decodable(s: &str) -> bool {
    naive_decode(s, false) != *s
}

/// Independent BYTE-LEVEL percent-decode (uses `.get()`, no shared bounds logic).
/// Keeps bytes so overlong sequences survive for `oracle_collapse_overlong`.
fn oracle_decode_bytes(input: &[u8], plus: bool) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        let c = input[i];
        if plus && c == b'+' {
            out.push(b' ');
            i += 1;
        } else if c == b'%' {
            match (input.get(i + 1).copied().and_then(hexval), input.get(i + 2).copied().and_then(hexval)) {
                (Some(h), Some(l)) => {
                    out.push((h << 4) | l);
                    i += 3;
                }
                _ => {
                    out.push(c);
                    i += 1;
                }
            }
        } else {
            out.push(c);
            i += 1;
        }
    }
    out
}

/// Independent overlong-UTF8 collapse (10c): 2-byte `0xC0/0xC1` overlong → ASCII byte.
fn oracle_collapse_overlong(bytes: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if (b == 0xC0 || b == 0xC1) && bytes.get(i + 1).is_some_and(|&n| (0x80..=0xBF).contains(&n)) {
            out.push(((b & 0x1F) << 6) | (bytes[i + 1] & 0x3F));
            i += 2;
        } else {
            out.push(b);
            i += 1;
        }
    }
    out
}

/// Full, UNBOUNDED canonicalization mirroring `canonicalize_value`'s NEW (10c)
/// semantics — percent + overlong to a fixed point (first pass honours `plus`), then
/// NFKC — but with NO cap, so the WAF (capped at `PIPELINE_CAP`) diverges from it
/// exactly on >cap-encoded inputs. Independent code (byte-level) from production.
fn oracle_full(input: &str, plus: bool) -> String {
    let mut bytes = input.as_bytes().to_vec();
    let mut first = true;
    loop {
        let next = oracle_collapse_overlong(&oracle_decode_bytes(&bytes, plus && first));
        first = false;
        if next == bytes {
            break;
        }
        bytes = next;
    }
    String::from_utf8_lossy(&bytes).nfkc().collect()
}

// ── (A) single-pass byte-exact equality ──────────────────────────────────────

proptest! {
    #[test]
    fn prop_a_single_pass_equals_oracle(
        s in "[%+0-9a-zA-Z<>'\"./ -]{0,48}",
        plus in any::<bool>(),
    ) {
        let (ours, _) = percent_decode(&s, plus);
        prop_assert_eq!(ours, naive_decode(&s, plus));
    }
}

// ── (B) canonical is an NFKC fixed-point ──────────────────────────────────────

proptest! {
    #[test]
    fn prop_b_canonical_is_nfkc_stable(
        // Include fullwidth forms (U+FF00..FF5E) so NFKC has work to do; if
        // canonicalize forgot NFKC, the re-normalization would differ.
        s in "[%+0-9a-zA-Z\u{ff10}-\u{ff5a}<>]{0,48}",
        plus in any::<bool>(),
    ) {
        let (canon, _) = canonicalize_value(&s, plus);
        let renorm: String = canon.nfkc().collect();
        prop_assert_eq!(canon, renorm);
    }
}

// ── (C) divergence is exactly the >2-encoded set ──────────────────────────────

proptest! {
    #[test]
    fn prop_c_le2_never_diverges(
        s in "[%+0-9a-zA-Z<>'./ ]{0,40}",
        plus in any::<bool>(),
    ) {
        // Does our bounded (<=2) decode already reach the stable form?
        let d1 = naive_decode(&s, plus);
        let converged = if has_decodable(&d1) {
            let d2 = naive_decode(&d1, false);
            !has_decodable(&d2)
        } else {
            true
        };
        // When the stable form is reached within 2 passes, the WAF canonical MUST
        // equal the full decode — no divergence allowed on <=2-encoded input.
        if converged {
            let (canon, _) = canonicalize_value(&s, plus);
            prop_assert_eq!(canon, oracle_full(&s, plus));
        }
    }
}

#[test]
fn prop_c_beyond_cap_must_diverge() {
    // 10c moved the bound 2 → PIPELINE_CAP (=5). A 5-level encoding still CONVERGES
    // (canonical == unbounded oracle); a 6-level encoding is where our bounded
    // canonical stops and the oracle goes further. The cap is itself under test.
    let l5 = "%2525252527"; // 5×-encoded `'`
    let (canon5, _) = canonicalize_value(l5, true);
    assert_eq!(canon5, "'", "5-level (<=cap) must fully converge, got {canon5:?}");
    assert_eq!(canon5, oracle_full(l5, true));

    let l6 = "%252525252527"; // 6×-encoded `'`
    let (canon6, _) = canonicalize_value(l6, true);
    assert_eq!(canon6, "%27", "6-level: bounded canonical stops at %27, got {canon6:?}");
    assert_eq!(oracle_full(l6, true), "'", "unbounded oracle reaches the quote");
    assert_ne!(canon6, oracle_full(l6, true), "the >cap divergence must exist");
}

#[test]
fn overlong_utf8_is_decoded_10c() {
    // 10c removes the §6 overlong limit: `%C0%AE` (overlong `.`) now DECODES to `.`
    // before from_utf8_lossy, closing the overlong path-traversal evasion. The
    // overlong-aware oracle agrees — no differential divergence.
    let (canon, _) = canonicalize_value("%C0%AE", true);
    assert_eq!(canon, ".", "overlong must now decode to '.', got {canon:?}");
    assert!(!canon.contains('\u{FFFD}'), "no replacement char, got {canon:?}");
    assert_eq!(canon, oracle_full("%C0%AE", true));
    // Double-encoded overlong resolves too: %25C0%25AE → %C0%AE → '.'
    let (canon2, _) = canonicalize_value("%25C0%25AE", true);
    assert_eq!(canon2, ".", "double-encoded overlong decodes too, got {canon2:?}");
}
