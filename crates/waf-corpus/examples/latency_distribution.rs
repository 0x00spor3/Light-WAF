// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

//! Fase 9 / DEC 2 — latency DISTRIBUTION over the worst-case corpus payloads.
//! `cargo run --release -p waf-corpus --example latency_distribution`.
//!
//! criterion gives a robust CENTRAL estimate (the DEC 4 regression gate), but NOT tail
//! percentiles. This artifact collects raw per-iteration samples of the isolated
//! inspection path (`enqueue→verdetto`) and emits **p50 / p99 / p99.9 / max** — the
//! distribution, not a point (DEC 2). p99.9 is the early-warning: where a WAF tends to
//! crack (alloc, lock, regex worst-case). Only p99 is the contract; p99.9/max are report.
//!
//! Three precisions this harness pins, so the number cannot lie:
//!   1. WORST-CASE, not mean: only the P2-flagged most-accumulated-rules cases (PL3
//!      cross-module overlaps), NOT the indiscriminate corpus — a mean would dilute the
//!      tail and report a falsely low p99.
//!   2. CANDIDATE traffic (ARCHITECTURE §13 anti-pattern): every payload is asserted a
//!      prefilter candidate, so what we bench is the path production actually takes for
//!      it. A non-candidate would be skipped in prod → benching it would be optimistically
//!      false. The full path is forced (`inspect = true`) AND tied to candidacy by assert.
//!   3. BASELINE anchor: the per-case numbers are printed next to the ~2 µs pinned
//!      baseline (`inspect_worst_case_pl3`). A p99 far from ~2 µs means understand WHY
//!      before trusting it (heavier case? or harness measuring the wrong thing?).

use std::time::Instant;

use waf_core::RequestContext;
use waf_corpus::{cases, corpus_pipeline, prepared_ctx, RECOMMENDED_SEVERITY};
use waf_detection::ContentPrefilter;

const PL: u8 = 3;
const SAMPLES: usize = 200_000;
const WARMUP: usize = 2_000;

/// Pinned baseline (~2 µs) — the DEC 4 reference and DEC 1 headroom anchor.
const BASELINE_NS: f64 = 2_000.0;

/// The P2-flagged worst-case set (most accumulated rules at PL3). First is the pinned
/// baseline case; `ssrf-cloud-metadata-query` is the heaviest (3 rules).
const WORST_CASE_IDS: &[&str] = &[
    "lfi-rfi-remote-script-query",
    "ssrf-cloud-metadata-query",
    "ssrf-loopback-query",
    "ssrf-ip-obfuscation-query",
    "ssrf-private-ip-query",
    "rce-download-exec-query",
];

/// Nearest-rank percentile on an ascending-sorted slice.
fn percentile(sorted: &[u64], p: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let rank = (p / 100.0 * sorted.len() as f64).ceil() as usize;
    sorted[rank.saturating_sub(1).min(sorted.len() - 1)]
}

/// Collect `SAMPLES` per-iteration latencies (ns) of the isolated inspection path.
fn collect(pipeline: &waf_pipeline::Pipeline, ctx: &mut RequestContext) -> Vec<u64> {
    for _ in 0..WARMUP {
        ctx.score = 0;
        ctx.score_contributions.clear();
        std::hint::black_box(pipeline.run_inspection_gated(ctx, true));
    }
    let mut samples = Vec::with_capacity(SAMPLES);
    for _ in 0..SAMPLES {
        // Reset OUTSIDE the timed region: only run_inspection_gated is measured.
        ctx.score = 0;
        ctx.score_contributions.clear();
        let t = Instant::now();
        std::hint::black_box(pipeline.run_inspection_gated(std::hint::black_box(ctx), true));
        samples.push(t.elapsed().as_nanos() as u64);
    }
    samples
}

fn main() {
    let sev = RECOMMENDED_SEVERITY;
    let pipeline = corpus_pipeline(PL, sev);
    let prefilter = ContentPrefilter::new(PL);
    let all = cases::all();

    println!("== Worst-case inspection latency distribution @ C2 / PL{PL} ({SAMPLES} samples/case) ==");
    println!("   baseline (inspect_worst_case_pl3) = ~{BASELINE_NS:.0} ns\n");
    println!("{:<30} {:>8} {:>8} {:>8} {:>8}", "case", "p50", "p99", "p99.9", "max");

    let mut aggregate: Vec<u64> = Vec::with_capacity(SAMPLES * WORST_CASE_IDS.len());
    for id in WORST_CASE_IDS {
        let case = all
            .iter()
            .find(|c| c.id == *id)
            .unwrap_or_else(|| panic!("corpus case {id} must exist"));
        let mut ctx = prepared_ctx(&case.field, PL, sev)
            .unwrap_or_else(|| panic!("{id} has an inspectable path"));
        // Precision 2: assert candidacy — never assume the path under measure is reached.
        assert!(
            prefilter.is_candidate(&ctx),
            "{id}: not a prefilter candidate — benching the wrong path"
        );

        let mut s = collect(&pipeline, &mut ctx);
        aggregate.extend_from_slice(&s);
        s.sort_unstable();
        println!(
            "{:<30} {:>7}n {:>7}n {:>7}n {:>7}n",
            id,
            percentile(&s, 50.0),
            percentile(&s, 99.0),
            percentile(&s, 99.9),
            *s.last().unwrap(),
        );
    }

    aggregate.sort_unstable();
    println!("{:-<64}", "");
    println!(
        "{:<30} {:>7}n {:>7}n {:>7}n {:>7}n",
        "AGGREGATE (worst-case set)",
        percentile(&aggregate, 50.0),
        percentile(&aggregate, 99.0),
        percentile(&aggregate, 99.9),
        *aggregate.last().unwrap(),
    );
    let p99 = percentile(&aggregate, 99.0) as f64;
    println!(
        "\nAnchor: aggregate p99 {:.0} ns vs baseline ~{:.0} ns ({:.1}x); vs p99 1 ms contract → {:.0}x headroom.",
        p99,
        BASELINE_NS,
        p99 / BASELINE_NS,
        1_000_000.0 / p99,
    );
    println!("Note: per-sample Instant adds ~tens of ns of clock overhead INTO each sample (conservative).");
}
