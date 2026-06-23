// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

//! Fase 9 / DEC 4 — relative-regression GATE for the pinned inspection baseline.
//!
//! This is the always-green CI guard for inspection latency. It does NOT assert an
//! absolute `<1 ms` (CI runners vary 3–10× → an absolute number there is noise, DEC 4).
//! It compares the CANDIDATE against a versioned baseline measured **on the same runner**
//! and fails only on a statistically-significant relative **regression** beyond budget.
//!
//! Keyed to the single pinned case `inspect_worst_case_pl3` (~2 µs), NOT the aggregate
//! (which drifts with the corpus) and NOT `max` (scheduler jitter, not a code property).
//! p99/p99.9/max are on-demand report only (`examples/latency_distribution.rs`).
//!
//! Workflow (same runner, two commits):
//!   # on the baseline commit (e.g. main):
//!   cargo bench -p waf-corpus --bench inspection -- --save-baseline pinned
//!   # on the candidate commit (e.g. the PR):
//!   cargo bench -p waf-corpus --bench inspection -- --baseline pinned
//!   # then the gate (exit 1 on regression):
//!   cargo run -p waf-corpus --example regression_gate
//!
//! Robustness: criterion computes the relative change with a 95% CI; the gate fails only
//! when the CI **lower bound** (the optimistic end of the measured change) is itself above
//! the budget — so run-to-run noise cannot trip it, only a real regression does.

use std::process::ExitCode;

/// The pinned single-case reference (ARCHITECTURE §11). criterion sanitizes the id into
/// a directory name (`/` → `_`); this case has no `/`, so the dir matches the bench name.
const BENCH_ID: &str = "inspect_worst_case_pl3";

/// Relative regression budget vs the versioned baseline (DEC 4 "es. >10%").
const THRESHOLD: f64 = 0.10;

fn field(v: &serde_json::Value, k: &str) -> f64 {
    v[k].as_f64().unwrap_or_else(|| panic!("criterion change JSON missing `{k}`"))
}

fn main() -> ExitCode {
    let change_path = format!("target/criterion/{BENCH_ID}/change/estimates.json");
    let raw = match std::fs::read_to_string(&change_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("regression gate: cannot read {change_path}: {e}");
            eprintln!("establish a baseline and compare first:");
            eprintln!("  cargo bench -p waf-corpus --bench inspection -- --save-baseline pinned");
            eprintln!("  cargo bench -p waf-corpus --bench inspection -- --baseline pinned");
            return ExitCode::FAILURE;
        }
    };
    let v: serde_json::Value = serde_json::from_str(&raw).expect("valid criterion change JSON");
    let median = &v["median"];
    let point = field(median, "point_estimate");
    let ci = &median["confidence_interval"];
    let lower = field(ci, "lower_bound");
    let upper = field(ci, "upper_bound");

    println!("== regression gate: {BENCH_ID} (relative, vs versioned baseline) ==");
    println!(
        "  median change: {:+.2}%   CI95 [{:+.2}%, {:+.2}%]",
        point * 100.0,
        lower * 100.0,
        upper * 100.0
    );
    println!("  budget: regression < +{:.0}%", THRESHOLD * 100.0);
    println!("  (gate ignores the aggregate and `max` by construction — single pinned case only)");

    // Fail only on a statistically-significant regression: even the optimistic end of the
    // measured change (CI lower bound) exceeds the budget.
    if lower > THRESHOLD {
        eprintln!(
            "FAIL: inspection latency regressed beyond budget (CI lower bound {:+.2}% > +{:.0}%).",
            lower * 100.0,
            THRESHOLD * 100.0
        );
        ExitCode::FAILURE
    } else {
        println!("PASS: no significant regression beyond budget.");
        ExitCode::SUCCESS
    }
}
