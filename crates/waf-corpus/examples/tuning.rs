// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

//! Threshold-tuning sweep (Fase 7 / Pilastro 2). On-demand, exploratory.
//! `cargo run -p waf-corpus --example tuning`.
//!
//! Detection is FROZEN and the 79-case corpus is UNCHANGED: this only varies the
//! config knobs (`severity_scores`, `block_threshold`) and re-runs the corpus as
//! the oracle. With benign cases all scoring 0, the threshold is NOT justified by
//! benign/malicious separation (trivial here) but by the ACCUMULATION semantics;
//! P1's 100% recall was DETECTION recall, this measures BLOCKING recall ex novo.

use std::collections::BTreeSet;

use waf_corpus::metrics::{BlockingReport, ScoringConfig};
use waf_core::SeverityScores;

const PLS: &[u8] = &[1, 2, 3, 4]; // PL4 = PL3 (forward-compatible, no extra rules)

fn sev(critical: u32, error: u32, warning: u32, notice: u32) -> SeverityScores {
    SeverityScores { critical, error, warning, notice }
}

fn configs() -> Vec<ScoringConfig> {
    vec![
        ScoringConfig { label: "C0 CRS default (5/4/3/2, T5)", severity: sev(5, 4, 3, 2), threshold: 5 },
        ScoringConfig { label: "C1 lower threshold (5/4/3/2, T4)", severity: sev(5, 4, 3, 2), threshold: 4 },
        ScoringConfig { label: "C2 raise critical (6/4/3/2, T5)", severity: sev(6, 4, 3, 2), threshold: 5 },
        ScoringConfig { label: "C3 rescale (10/7/4/2, T8)", severity: sev(10, 7, 4, 2), threshold: 8 },
    ]
}

fn fmt_margin(m: Option<i64>) -> String {
    m.map_or_else(|| "  n/a".to_string(), |v| format!("{v:+}"))
}

fn main() {
    println!("== Pilastro 2 — tuning sweep (corpus as oracle; detection frozen) ==\n");

    for cfg in configs() {
        println!("### {}", cfg.label);
        println!(
            "  {:<4} {:>16} {:>16} {:>9} {:>11} {:>11}",
            "PL", "block-recall own", "block-recall tot", "benign-blk", "margin_own", "margin_ben"
        );
        for &pl in PLS {
            let r = BlockingReport::run(cfg, pl);
            println!(
                "  PL{:<2} {:>11.0}% {:>3}/{:<2} {:>11.0}% {:>3}/{:<2} {:>9} {:>11} {:>11}",
                pl,
                r.blocking_recall_own() * 100.0,
                r.blocked_own(),
                r.malicious_total(),
                r.blocking_recall_total() * 100.0,
                r.blocked_total(),
                r.malicious_total(),
                r.benign_blocked(),
                fmt_margin(r.block_margin_own()),
                format!("{:+}", r.benign_margin()),
            );
        }

        // Overlap-masking (first-class output): cases that block on total but NOT
        // on own merit — named, at the PL where they appear (PL3).
        let r3 = BlockingReport::run(cfg, 3);
        if r3.masked.is_empty() {
            println!("  overlap-masked @PL3: none");
        } else {
            println!("  overlap-masked @PL3 (block only via cross-module overlap):");
            for m in &r3.masked {
                println!(
                    "    {:<30} own={} total={} via {:?}",
                    m.case_id, m.own_score, m.total_score, m.overlap_rules
                );
            }
        }
        println!();
    }

    // ── C2 side-effect verification vs C0 (requested explicitly) ───────────────
    println!("== C2 side-effect check (raise critical 5->6, T unchanged) vs C0 ==");
    let c0 = configs()[0];
    let c2 = configs()[2];
    let mut clean = true;
    for &pl in PLS {
        let r0 = BlockingReport::run(c0, pl);
        let r2 = BlockingReport::run(c2, pl);
        let b0: BTreeSet<_> = r0.blocking_ids.iter().cloned().collect();
        let b2: BTreeSet<_> = r2.blocking_ids.iter().cloned().collect();
        let new_blockers: Vec<_> = b2.difference(&b0).cloned().collect();
        let lost_blockers: Vec<_> = b0.difference(&b2).cloned().collect();
        if !new_blockers.is_empty() {
            clean = false;
            println!("  PL{pl}: NEW blockers under C2 (unexpected): {new_blockers:?}");
        }
        if !lost_blockers.is_empty() {
            clean = false;
            println!("  PL{pl}: LOST blockers under C2 (unexpected): {lost_blockers:?}");
        }
        if r2.benign_blocked() != 0 {
            clean = false;
            println!("  PL{pl}: benign blocked under C2: {:?}", r2.benign_blocking_ids);
        }
    }
    if clean {
        println!("  CLEAN: same blocking set as C0, benign-blocking 0 at all PL,");
        println!("         only effect is the wider own-merit margin on Critical cases.");
    }
}
