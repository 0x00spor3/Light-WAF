// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

//! F1 M2 famiglia 4 — `javascript:` scheme without a call paren, per-PL checks.
//!
//! The corpus runs at PL3 and a `Triggers` case passes on any match of its listed rule.
//! This test adds what the corpus does not assert for the `xss-f4-*` cases:
//! - every Trigger (accepted FPs included) blocks at C2 on PL1, PL2 and PL3, and the
//!   `xss` module ALONE reaches the threshold through `xss-javascript-proto` (so the block
//!   is not incidental: `rce-backtick`, `hdr-crlf-control-char`, … do not count);
//! - every Clean trap matches no rule at PL1-3;
//! - fast path ≡ full path on all of them (no unsound prefilter skip, same rules/score).
//!
//! Failures are collected and reported together, so a red run lists every case.

use waf_corpus::{
    cases::xss::CASES, run_case_fast, run_case_with, Case, CaseOutcome, Expect, Field, Module,
    RunResult, Verdict, RECOMMENDED_SEVERITY, RECOMMENDED_THRESHOLD,
};

const RULE: &str = "xss-javascript-proto";
const PLS: [u8; 3] = [1, 2, 3];

fn ran(r: RunResult, id: &str, pl: u8) -> CaseOutcome {
    match r {
        RunResult::Ran(o) => o,
        RunResult::Skipped => panic!("[{id}] skipped at PL{pl}"),
    }
}

fn family_cases(expect_triggers: bool) -> Vec<&'static Case> {
    let cases: Vec<&Case> = CASES
        .iter()
        .filter(|c| c.id.starts_with("xss-f4-"))
        .filter(|c| matches!(c.expect, Expect::Triggers) == expect_triggers)
        .collect();
    assert!(!cases.is_empty(), "no xss-f4-* cases (triggers = {expect_triggers})");
    cases
}

fn xss_points(o: &CaseOutcome) -> u32 {
    o.contributions.iter().filter(|c| c.module == "xss").map(|c| c.points).sum()
}

fn fast_drift(case: &Case, pl: u8, full: &CaseOutcome) -> Option<String> {
    let fast = ran(run_case_fast(case, pl, RECOMMENDED_SEVERITY), case.id, pl);
    if full.triggered && fast.fastpath_skipped {
        return Some(format!("[{}] PL{pl}: UNSOUND prefilter skip", case.id));
    }
    (full.score != fast.score || full.matched_rules != fast.matched_rules).then(|| {
        format!(
            "[{}] PL{pl}: fast/full drift: full {} {:?}, fast {} {:?}",
            case.id, full.score, full.matched_rules, fast.score, fast.matched_rules
        )
    })
}

fn report(failures: Vec<String>) {
    assert!(failures.is_empty(), "{} failure(s):\n{}", failures.len(), failures.join("\n"));
}

#[test]
fn javascript_scheme_triggers_block_at_every_pl_on_xss_merit() {
    let mut failures = Vec::new();
    for case in family_cases(true) {
        for pl in PLS {
            let full = ran(run_case_with(case, pl, RECOMMENDED_SEVERITY), case.id, pl);
            let blocked = full.verdict != Verdict::Allow || full.score >= RECOMMENDED_THRESHOLD;
            if !full.contributions.iter().any(|c| c.rule_id == RULE)
                || xss_points(&full) < RECOMMENDED_THRESHOLD
                || !blocked
            {
                failures.push(format!(
                    "[{}] PL{pl}: needs {RULE} and xss >= {RECOMMENDED_THRESHOLD}; got score {} \
                     (xss {}) rules {:?}",
                    case.id,
                    full.score,
                    xss_points(&full),
                    full.matched_rules
                ));
            }
            failures.extend(fast_drift(case, pl, &full));
        }
    }
    report(failures);
}

#[test]
fn javascript_scheme_traps_stay_clean_at_every_pl() {
    let mut failures = Vec::new();
    for case in family_cases(false) {
        for pl in PLS {
            let full = ran(run_case_with(case, pl, RECOMMENDED_SEVERITY), case.id, pl);
            if full.triggered {
                failures.push(format!(
                    "[{}] PL{pl}: false positive {:?} (score {})",
                    case.id, full.matched_rules, full.score
                ));
            }
            failures.extend(fast_drift(case, pl, &full));
        }
    }
    report(failures);
}

/// Traps that cannot be corpus `Clean` cases because a pre-existing, out-of-family rule
/// already matches them on the base code: `rfi-remote-url` (Notice/PL3) on any `https://`,
/// `rce-backtick` (Warning/PL2) on markdown backticks. Here only the XSS module is required
/// to stay silent.
#[test]
fn traps_with_preexisting_foreign_matches_trip_no_xss_rule() {
    let traps = [
        Case {
            id: "xss-f4-https-mdn-param",
            module: Module::Xss,
            field: Field::Query { name: "ref", value: "https://developer.mozilla.org/en-US/docs/Web/JavaScript" },
            min_pl: 1,
            expect: Expect::Clean,
            rules: &[],
            desc: "documentation URL",
        },
        Case {
            id: "xss-f4-https-lang-href",
            module: Module::Xss,
            field: Field::Query { name: "html", value: "<a href=\"https://example.com/?lang=javascript\">x</a>" },
            min_pl: 1,
            expect: Expect::Clean,
            rules: &[],
            desc: "href with `javascript` as a query value",
        },
        // Pre-existing, out-of-family: `rce-backtick` (Warning/PL2) already matches this on
        // the base code; only the XSS module must stay silent.
        Case {
            id: "xss-f4-markdown-backticks",
            module: Module::Xss,
            field: Field::Query { name: "q", value: "JavaScript: `let` e `const`" },
            min_pl: 1,
            expect: Expect::Clean,
            rules: &[],
            desc: "start of value: markdown inline code (backtick not right after an identifier)",
        },
    ];
    let mut failures = Vec::new();
    for case in &traps {
        for pl in PLS {
            let full = ran(run_case_with(case, pl, RECOMMENDED_SEVERITY), case.id, pl);
            if xss_points(&full) > 0 {
                failures.push(format!("[{}] PL{pl}: xss matched {:?}", case.id, full.matched_rules));
            }
            failures.extend(fast_drift(case, pl, &full));
        }
    }
    report(failures);
}
