// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

//! Smoke test for the corpus boundaries (Fase 7 / Pilastro 1, step 3).
//!
//! Two cases only — one malicious that must trigger, one benign that must not —
//! to validate the full path (testkit raw build → real normalizer → pipeline →
//! evaluate) before harvesting the ~90-120 real cases. Not the full validation
//! suite; that comes after the harvest.

use waf_corpus::Case;
use waf_corpus::{
    evaluate, run_case, CaseResult, Expect, Field, Module, RunResult, Verdict, BASELINE_PARANOIA,
};

/// Malicious: a UNION SELECT in a query parameter must fire `sqli-union-select`.
const SMOKE_MALICIOUS: Case = Case {
    id: "smoke-sqli-union-query",
    module: Module::Sqli,
    field: Field::Query {
        name: "id",
        value: "1 UNION SELECT username,password FROM users--",
    },
    min_pl: 1,
    expect: Expect::Triggers,
    rules: &["sqli-union-select"],
    desc: "classic UNION-based SQLi in a query parameter",
};

/// Benign: a sentence that merely contains the word 'select' must not fire. This
/// is one of the existing SQLi no-FP corpus entries.
const SMOKE_BENIGN: Case = Case {
    id: "smoke-sqli-benign-select-word",
    module: Module::Sqli,
    field: Field::Query {
        name: "q",
        value: "the best select occasions",
    },
    min_pl: 1,
    expect: Expect::Clean,
    rules: &[],
    desc: "'select' as an English word, not a SQL keyword sequence",
};

#[test]
fn smoke_malicious_triggers_with_expected_rule() {
    let result = run_case(&SMOKE_MALICIOUS, BASELINE_PARANOIA);
    let RunResult::Ran(outcome) = &result else {
        panic!("case should run at baseline PL, got {result:?}");
    };
    assert!(outcome.triggered, "malicious case should trigger: {outcome:?}");
    assert!(
        outcome.matched_rules.iter().any(|r| r == "sqli-union-select"),
        "expected sqli-union-select, got {:?}",
        outcome.matched_rules
    );
    assert!(outcome.score > 0, "malicious case should accumulate score");
    assert_eq!(evaluate(&SMOKE_MALICIOUS, &result), CaseResult::Pass);
}

#[test]
fn smoke_benign_stays_clean() {
    let result = run_case(&SMOKE_BENIGN, BASELINE_PARANOIA);
    let RunResult::Ran(outcome) = &result else {
        panic!("case should run at baseline PL, got {result:?}");
    };
    assert!(
        !outcome.triggered,
        "benign case must not trigger, matched {:?}",
        outcome.matched_rules
    );
    assert_eq!(outcome.verdict, Verdict::Allow);
    assert_eq!(outcome.score, 0);
    assert_eq!(evaluate(&SMOKE_BENIGN, &result), CaseResult::Pass);
}

#[test]
fn smoke_case_below_min_pl_is_skipped() {
    // A PL3-only rule case must be skipped when run at PL1 (not counted).
    const PL3_CASE: Case = Case {
        id: "smoke-pl3-skip",
        module: Module::Sqli,
        field: Field::Query { name: "id", value: "CAST(x AS int)" },
        min_pl: 3,
        expect: Expect::Triggers,
        rules: &["sqli-cast-convert"],
        desc: "cast-convert is PL3; below that the case is skipped",
    };
    assert!(matches!(run_case(&PL3_CASE, 1), RunResult::Skipped));
    assert_eq!(evaluate(&PL3_CASE, &RunResult::Skipped), CaseResult::Skipped);
}
