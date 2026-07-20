// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

//! End-to-end regression for the DVWA pentest finding **D-1** documented in
//! `WAF-DVWA-Report.md` and closed in v0.5.3. Each case runs the REAL pipeline
//! (`run_case` → `corpus_pipeline`) and asserts the vector is now caught:
//!   D-1  error-based SQLi `extractvalue(…)` / `updatexml(…)`   → `sqli-error-based-fn`
//!   D-1  error-based overflow `exp(~(SELECT …))`               → `sqli-error-exp-overflow`
//!   D-1  boolean subquery `EXISTS(SELECT …)`                   → `sqli-subquery-exists`
//!
//! Root cause: a `… AND <function>(…)` predicate carries no UNION/OR/comment/numeric-
//! tautology token, so the pre-0.5.3 SQLi rules missed it — the WAF passed the request
//! (HTTP 200) and DVWA leaked the admin password hash through the XPATH error channel.
//!
//! Per-module coverage + FP-traps for these vectors also live in the static corpus
//! (`cases/sqli.rs`); this file is the consolidated report-level guard. D-2 (bare
//! remote-URL RFI) and D-3 (loopback FP) were accepted design tradeoffs — no rule change.

use waf_corpus::{evaluate, run_case, Case, CaseResult, Expect, Field, Module, BASELINE_PARANOIA};

/// Assert a case reaches its expected outcome through the real pipeline.
fn assert_case_passes(case: &Case) {
    let result = run_case(case, BASELINE_PARANOIA);
    match evaluate(case, &result) {
        CaseResult::Pass => {}
        CaseResult::Fail { reason } => panic!("[{}] regressed: {reason}", case.id),
        CaseResult::Skipped => panic!("[{}] unexpectedly skipped (min_pl > baseline)", case.id),
    }
}

// ── D-1: error-based XPATH functions (confirmed exfiltration channel) ────────────

#[test]
fn d1_error_based_function_triggers() {
    // The exact vector proven to leak `~admin:5f4dcc3b…` through the WAF at PL3.
    assert_case_passes(&Case {
        id: "d1-extractvalue-exfil",
        module: Module::Sqli,
        field: Field::Query {
            name: "id",
            value: "1' AND extractvalue(1,concat(0x7e,(SELECT concat(user,0x3a,password) FROM users LIMIT 1)))-- -",
        },
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["sqli-error-based-fn"],
        desc: "D-1: extractvalue() error-based exfiltration must be caught",
    });
    assert_case_passes(&Case {
        id: "d1-updatexml",
        module: Module::Sqli,
        field: Field::JsonBody(r#"{"id":"1' AND updatexml(1,concat(0x7e,user()),1)-- -"}"#),
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["sqli-error-based-fn"],
        desc: "D-1: updatexml() error-based SQLi in a JSON body must be caught",
    });
}

// ── D-1: arithmetic-overflow error-based ────────────────────────────────────────

#[test]
fn d1_exp_overflow_triggers() {
    assert_case_passes(&Case {
        id: "d1-exp-overflow",
        module: Module::Sqli,
        field: Field::Query { name: "id", value: "1' AND exp(~(SELECT * FROM(SELECT version())a))-- -" },
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["sqli-error-exp-overflow"],
        desc: "D-1: exp(~(subquery)) overflow error-based SQLi must be caught",
    });
}

// ── D-1: boolean subquery ───────────────────────────────────────────────────────

#[test]
fn d1_subquery_exists_triggers() {
    assert_case_passes(&Case {
        id: "d1-exists-subquery",
        module: Module::Sqli,
        field: Field::FormBody("id=1' AND EXISTS(SELECT * FROM users)-- -"),
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["sqli-subquery-exists"],
        desc: "D-1: EXISTS(SELECT …) boolean subquery must be caught",
    });
}
