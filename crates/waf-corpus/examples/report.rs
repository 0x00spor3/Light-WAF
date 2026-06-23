//! Full metrics report for the validation corpus (Fase 7 / Pilastro 1).
//!
//! Per-module recall / FP-rate (attributed to `case.module`) + aggregate, the real
//! cumulative score-distribution for malicious cases (overlaps included, for
//! Pilastro 2), the observed declared overlaps, and the ExpectedMiss status.
//! Run: `cargo run -p waf-corpus --example report`.

use waf_corpus::metrics::Report;
use waf_corpus::BASELINE_PARANOIA;

fn main() {
    let report = Report::run(BASELINE_PARANOIA);

    println!("== Validation metrics @ PL{} ==\n", report.execution_pl);

    // ── per-module recall / FP ─────────────────────────────────────────────────
    println!(
        "{:<18} {:>14} {:>8}   {:>12} {:>8}   {:>7}",
        "module", "recall", "(mal)", "fp-rate", "(ben)", "skipped"
    );
    println!("{}", "-".repeat(78));
    for m in &report.modules {
        println!(
            "{:<18} {:>12.1}% {:>3}/{:<3}   {:>10.1}% {:>3}/{:<3}   {:>7}",
            m.module.name(),
            m.recall() * 100.0,
            m.malicious_detected,
            m.malicious_total,
            m.fp_rate() * 100.0,
            m.benign_fp,
            m.benign_total,
            m.skipped,
        );
    }
    let agg = report.aggregate();
    println!("{}", "-".repeat(78));
    println!(
        "{:<18} {:>12.1}% {:>3}/{:<3}   {:>10.1}% {:>3}/{:<3}   {:>7}",
        "AGGREGATE",
        agg.recall() * 100.0,
        agg.malicious_detected,
        agg.malicious_total,
        agg.fp_rate() * 100.0,
        agg.benign_fp,
        agg.benign_total,
        agg.skipped,
    );

    // ── trigger failures / false positives (should be empty at baseline) ───────
    let trigger_fails: Vec<&String> =
        report.modules.iter().flat_map(|m| &m.trigger_failures).collect();
    let fps: Vec<&(String, Vec<String>)> =
        report.modules.iter().flat_map(|m| &m.false_positives).collect();
    if !trigger_fails.is_empty() || !fps.is_empty() {
        println!("\n== Mismatches ==");
        for t in &trigger_fails {
            println!("  TRIGGER-FAIL  {t}");
        }
        for (id, rules) in &fps {
            println!("  FALSE-POSITIVE {id} -> {rules:?}");
        }
    }

    // ── score-distribution (real cumulative score, overlaps included) ──────────
    println!("\n== Score distribution (malicious; real ctx.score, overlaps included) ==");
    let mut points: Vec<_> = report.score_points.iter().collect();
    points.sort_by(|a, b| {
        a.module
            .name()
            .cmp(b.module.name())
            .then(b.score.cmp(&a.score))
    });
    for p in points {
        println!(
            "  {:<18} {:<34} score={:<3} rules={:?}",
            p.module.name(),
            p.case_id,
            p.score,
            p.matched_rules
        );
    }

    // ── overlaps (declared §8) ─────────────────────────────────────────────────
    println!("\n== Observed overlaps (extra rules beyond the expected set) ==");
    if report.overlaps.is_empty() {
        println!("  (none)");
    }
    for o in &report.overlaps {
        println!(
            "  {:<18} {:<34} expected={:?} extra={:?}",
            o.module.name(),
            o.case_id,
            o.expected,
            o.extra
        );
    }

    // ── ExpectedMiss (§8 gaps) ─────────────────────────────────────────────────
    let (still, total) = report.expected_miss_still_missed();
    println!("\n== ExpectedMiss (known §8 gaps) ==");
    println!("  {still}/{total} still missed (as per §8)");
    for e in &report.expected_miss {
        let status = if e.still_missed { "still missed" } else { "NOW CAUGHT" };
        println!("  {:<34} {status}", e.case_id);
    }
}
