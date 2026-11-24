// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

//! Compiled-size margin of the content prefilter union (F1 M2 famiglia 3).
//!
//! `ContentPrefilter::new` and every module compile their `RegexSet` with the `regex`
//! crate's default `size_limit` and `expect` on failure, so a rule that grows the union
//! past the limit is a panic at startup, not a test failure. This test compiles the same
//! union (`content_rules_split`, the single source the prefilter uses) with HALF the
//! default limit: it fails in CI while there is still a 50% margin in production.

use std::time::Instant;

use regex::{RegexSet, RegexSetBuilder};
use waf_detection::{content_rules_split, xss};

/// `regex` 1.x default `RegexBuilder::size_limit` (10 MiB, see the crate docs).
const REGEX_DEFAULT_SIZE_LIMIT: usize = 10 * (1 << 20);

fn build(patterns: &[&str], size_limit: usize) -> Result<RegexSet, regex::Error> {
    RegexSetBuilder::new(patterns).size_limit(size_limit).build()
}

fn union_patterns(pl: u8) -> (Vec<&'static str>, Vec<&'static str>) {
    let (main, host) = content_rules_split(pl);
    (main.into_iter().map(|(_, p)| p).collect(), host.into_iter().map(|(_, p)| p).collect())
}

#[test]
fn prefilter_union_keeps_half_the_size_limit_free() {
    for pl in [1u8, 2, 3, 4] {
        let (main, host) = union_patterns(pl);
        for (bucket, patterns) in [("MAIN", &main), ("HOST", &host)] {
            if let Err(e) = build(patterns, REGEX_DEFAULT_SIZE_LIMIT / 2) {
                panic!(
                    "PL{pl} {bucket} prefilter union no longer compiles within 50% of the regex \
                     default size_limit ({} bytes): {e}",
                    REGEX_DEFAULT_SIZE_LIMIT / 2
                );
            }
        }
    }
}

/// Smallest `size_limit` (bytes) under which `patterns` still compiles.
fn min_size_limit(patterns: &[&str]) -> usize {
    let (mut lo, mut hi) = (1usize, REGEX_DEFAULT_SIZE_LIMIT);
    assert!(build(patterns, hi).is_ok(), "does not compile at the default limit");
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        if build(patterns, mid).is_ok() {
            hi = mid;
        } else {
            lo = mid + 1;
        }
    }
    lo
}

fn best_compile_ms(patterns: &[&str]) -> f64 {
    (0..5)
        .map(|_| {
            let t = Instant::now();
            build(patterns, REGEX_DEFAULT_SIZE_LIMIT).unwrap();
            t.elapsed().as_secs_f64() * 1e3
        })
        .fold(f64::INFINITY, f64::min)
}

#[test]
#[ignore = "size report: run with --ignored --nocapture"]
fn size_report() {
    let handler: Vec<&str> =
        xss::XSS_RULES.iter().filter(|r| r.id == "xss-event-handler").map(|r| r.pattern).collect();
    let js_proto: Vec<&str> =
        xss::XSS_RULES.iter().filter(|r| r.id == "xss-javascript-proto").map(|r| r.pattern).collect();
    let xss_all: Vec<&str> = xss::XSS_RULES.iter().map(|r| r.pattern).collect();
    println!();
    println!("| automa | size_limit minimo (B) | margine vs 10 MiB | compilazione (ms, best of 5) |");
    println!("|---|---|---|---|");
    let row =|name: &str, p: &[&str]| {
        let min = min_size_limit(p);
        let margin = 100.0 * (1.0 - min as f64 / REGEX_DEFAULT_SIZE_LIMIT as f64);
        println!("| {name} | {min} | {margin:.2}% | {:.2} |", best_compile_ms(p));
    };
    row("xss-event-handler", &handler);
    row("xss-javascript-proto", &js_proto);
    row("XSS_RULES (PL3)", &xss_all);
    for pl in [1u8, 3] {
        let (main, _) = union_patterns(pl);
        row(&format!("prefilter MAIN PL{pl}"), &main);
    }
}
