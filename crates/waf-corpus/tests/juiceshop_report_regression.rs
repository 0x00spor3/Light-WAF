// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

//! End-to-end regression for the three gaps found in `WAF-JuiceShop-Report.md` and
//! closed in v0.5.0. Each case runs the REAL pipeline (`run_case` → `corpus_pipeline`)
//! and asserts the vector is now caught:
//!   F-1  null-byte double-encoded path (`%2500`) → `evasion-null-byte`
//!   F-2  SSTI ERB `<%=7*7%>`                     → `ssti-erb-jsp-arithmetic`
//!   F-3  Shellshock `() { :;}` (UA / cookie)     → `rce-shellshock`
//!
//! Per-module coverage + FP-traps for these vectors also live in the static corpus
//! (`cases/ssti.rs`, `cases/rce.rs`) and the `evasion` unit tests
//! (`waf-detection/tests/evasion.rs`); this file is the consolidated report-level guard.

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

// ── F-1: null-byte double-encoded in the URL path (REAL disclosure) ─────────────

/// `GET /ftp/package.json.bak%2500.md` — `%2500` double-decodes to a NUL the normalizer
/// strips silently; the `evasion` module surfaces it (Critical) from the pre-strip flag.
#[test]
fn f1_null_byte_double_encoded_path_triggers() {
    let case = Case {
        id: "evasion-null-byte-path-bak",
        module: Module::PathTraversal,
        field: Field::Path("/ftp/package.json.bak%2500.md"),
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["evasion-null-byte"],
        desc: "double-encoded NUL (%2500) in path serves the .bak — must leave a Critical trace",
    };
    assert_case_passes(&case);
}

// ── F-2: SSTI ERB/JSP `<%…%>` arithmetic ────────────────────────────────────────

#[test]
fn f2_ssti_erb_arithmetic_triggers() {
    let case = Case {
        id: "ssti-erb-arithmetic-query",
        module: Module::Ssti,
        field: Field::Query { name: "q", value: "<%=7*7%>" },
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["ssti-erb-jsp-arithmetic"],
        desc: "ERB `<%=7*7%>` arithmetic probe — new delimiter family for the SSTI module",
    };
    assert_case_passes(&case);
}

// ── F-3: Shellshock `() { …;}` in headers ───────────────────────────────────────

/// User-Agent `() { :;}; …` — the canonical CVE-2014-6271 vector; UA is deny-listed for
/// general inspection, so this exercises the module's dedicated single-pattern scan.
#[test]
fn f3_shellshock_user_agent_triggers() {
    let case = Case {
        id: "rce-shellshock-user-agent",
        module: Module::Rce,
        field: Field::Header { name: "user-agent", value: "() { :;}; echo vulnerable" },
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["rce-shellshock"],
        desc: "Shellshock function-def in User-Agent — the classic CVE-2014-6271 surface",
    };
    assert_case_passes(&case);
}

/// Cookie `() { :;}; …` — covered by the main `rce-shellshock` rule via the parsed-cookie
/// channel (no special handling; the header deny-list only blocks raw-header-text).
#[test]
fn f3_shellshock_cookie_triggers() {
    let case = Case {
        id: "rce-shellshock-cookie",
        module: Module::Rce,
        field: Field::Cookie("m=() { :;}; echo vulnerable"),
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["rce-shellshock"],
        desc: "Shellshock in a cookie value — covered by the main RCE rule via the parsed channel",
    };
    assert_case_passes(&case);
}
