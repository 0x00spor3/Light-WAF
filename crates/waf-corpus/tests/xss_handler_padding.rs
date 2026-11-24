// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

//! F1 M2 famiglia 3 — anti-padding Triggers for the tag-anchored branch of
//! `xss-event-handler`. The branch walks the attribute grammar of the open tag with
//! single-class stars (no counted repetition), so neither a long quoted value nor many
//! attributes before an out-of-list handler may push it out of reach. The payloads are
//! built at runtime (a 2000-char literal does not belong in the static corpus), and each
//! one must block at C2 on PL1-3 through an XSS rule, with fast path ≡ full path.

use waf_corpus::{
    run_case_fast, run_case_with, Case, CaseOutcome, Expect, Field, Module, RunResult, Verdict,
    RECOMMENDED_SEVERITY, RECOMMENDED_THRESHOLD,
};

fn leak(s: String) -> &'static str {
    Box::leak(s.into_boxed_str())
}

fn case(id: &'static str, value: String) -> Case {
    Case {
        id,
        module: Module::Xss,
        field: Field::Query { name: "q", value: leak(value) },
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["xss-event-handler"],
        desc: "anti-padding: out-of-list handler after padding inside the open tag",
    }
}

fn ran(r: RunResult, id: &str, pl: u8) -> CaseOutcome {
    match r {
        RunResult::Ran(o) => o,
        RunResult::Skipped => panic!("[{id}] skipped at PL{pl}"),
    }
}

fn assert_blocks(case: &Case) {
    for pl in [1u8, 2, 3] {
        let full = ran(run_case_with(case, pl, RECOMMENDED_SEVERITY), case.id, pl);
        let fast = ran(run_case_fast(case, pl, RECOMMENDED_SEVERITY), case.id, pl);
        assert!(
            full.contributions.iter().any(|c| c.rule_id == "xss-event-handler"),
            "[{}] PL{pl}: xss-event-handler must fire, matched {:?}",
            case.id,
            full.matched_rules
        );
        assert!(
            full.verdict != Verdict::Allow || full.score >= RECOMMENDED_THRESHOLD,
            "[{}] PL{pl}: must block at C2, score {}",
            case.id,
            full.score
        );
        assert!(!fast.fastpath_skipped, "[{}] PL{pl}: UNSOUND prefilter skip", case.id);
        assert_eq!(full.score, fast.score, "[{}] PL{pl}: fast/full score drift", case.id);
        assert_eq!(full.matched_rules, fast.matched_rules, "[{}] PL{pl}: fast/full rules drift", case.id);
    }
}

#[test]
fn long_quoted_value_before_handler() {
    let pad = "A".repeat(2000);
    assert_blocks(&case(
        "xss-f3-pad-long-value",
        format!("<body title=\"{pad}\" onpageshow=print()>"),
    ));
}

#[test]
fn many_attributes_before_handler() {
    let attrs = (0..50).map(|i| format!("a{i}=1 ")).collect::<String>();
    assert_blocks(&case(
        "xss-f3-pad-many-attrs",
        format!("<x {attrs}onfocusin=print() tabindex=1 autofocus>"),
    ));
}
