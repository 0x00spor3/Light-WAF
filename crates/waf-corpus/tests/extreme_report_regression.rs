// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

//! End-to-end regression for the EXTREME close-out follow-ons found in
//! `WAF-JuiceShop-Report-v2-extreme.md` and closed in v0.5.2. Each case runs the REAL
//! pipeline (`run_case` → `corpus_pipeline`) and asserts the vector is now caught:
//!   E-2  tautology beyond `=`/int (`OR 1<2`, `OR 1 LIKE 1`, hex/sci) → `sqli-tautology-or`
//!   E-3a IPv6 loopback `[::1]` / `[0:0:…:1]`                         → `ssrf-loopback`
//!   E-4  Thymeleaf `*{7*7}` / Razor `@(1+2)` / `{%print(7*7)%}` / Smarty `{php}` → SSTI rules
//!   E-4  prototype pollution `{"__proto__":…}` / `constructor.prototype` → `proto-pollution-key`
//!
//! E-3b (homoglyph `①②⑦.0.0.1`) was VERIFIED already covered by NFKC folding — no new rule;
//! its lock lives in `waf-detection/tests/ssrf.rs`
//! (`ssrf_homoglyph_loopback_folded_by_nfkc_and_caught`).
//!
//! Per-module coverage + FP-traps for these vectors also live in the static corpus
//! (`cases/sqli.rs`, `cases/ssrf.rs`, `cases/ssti.rs`, `cases/nosql.rs`); this file is the
//! consolidated report-level guard.

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

// ── E-2: tautology beyond `=` / integers ────────────────────────────────────────

#[test]
fn e2_tautology_comparison_and_like_triggers() {
    for (id, value) in [
        ("e2-like", "1 OR 1 LIKE 1"),
        ("e2-lessthan", "1 OR 1<2"),
        ("e2-scientific", "1 OR 1.0e1=1e1"),
        ("e2-hex", "1 OR 0x1=0x1"),
    ] {
        assert_case_passes(&Case {
            id,
            module: Module::Sqli,
            field: Field::Query { name: "q", value },
            min_pl: 1,
            expect: Expect::Triggers,
            rules: &["sqli-tautology-or"],
            desc: "E-2: non-`=`/numeric tautology must be caught",
        });
    }
}

// ── E-3a: IPv6 loopback (`[::1]` dead-branch fix + expanded form) ────────────────

#[test]
fn e3a_ipv6_loopback_triggers() {
    for (id, value) in [
        ("e3a-compressed", "http://[::1]:6379/"),
        ("e3a-expanded", "http://[0:0:0:0:0:0:0:1]/"),
    ] {
        assert_case_passes(&Case {
            id,
            module: Module::Ssrf,
            field: Field::Query { name: "url", value },
            min_pl: 2,
            expect: Expect::Triggers,
            rules: &["ssrf-loopback"],
            desc: "E-3a: bracketed IPv6 loopback must be caught",
        });
    }
}

// ── E-4: template-engine coverage ───────────────────────────────────────────────

#[test]
fn e4_template_engine_coverage_triggers() {
    fn ssti(id: &'static str, value: &'static str, rules: &'static [&'static str]) -> Case {
        Case {
            id,
            module: Module::Ssti,
            field: Field::Query { name: "q", value },
            min_pl: 1,
            expect: Expect::Triggers,
            rules,
            desc: "E-4: additional template engine must be caught",
        }
    }
    assert_case_passes(&ssti("e4-thymeleaf", "*{7*7}", &["ssti-template-arithmetic"]));
    assert_case_passes(&ssti("e4-razor", "@(1+2)", &["ssti-template-arithmetic"]));
    assert_case_passes(&ssti("e4-print-paren", "{%print(7*7)%}", &["ssti-template-statement"]));
    assert_case_passes(&ssti("e4-smarty", "{php}phpinfo();{/php}", &["ssti-smarty-php"]));
}

// ── E-4: prototype pollution in key position ────────────────────────────────────

#[test]
fn e4_prototype_pollution_key_triggers() {
    assert_case_passes(&Case {
        id: "e4-proto-underscore",
        module: Module::Nosql,
        field: Field::JsonBody(r#"{"__proto__":{"isAdmin":true}}"#),
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["proto-pollution-key"],
        desc: "E-4: `__proto__` JSON key pollution must be caught",
    });
    assert_case_passes(&Case {
        id: "e4-proto-constructor",
        module: Module::Nosql,
        field: Field::JsonBody(r#"{"constructor":{"prototype":{"polluted":true}}}"#),
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["proto-pollution-key"],
        desc: "E-4: `constructor.prototype` chain pollution must be caught",
    });
}
