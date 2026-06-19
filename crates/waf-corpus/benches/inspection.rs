//! Fase 9 / DEC 1 — microbench of the **isolated inspection path** (`enqueue→verdetto`).
//!
//! This is the number that depends ONLY on our code: the cost of running the content
//! modules over an already-built, already-normalized context, with no upstream and no
//! network in the path. The connection phase + normalization are done ONCE up front
//! (via [`prepared_ctx`]); the timed routine is purely `run_inspection_gated`. The only
//! per-iteration setup is resetting `score`/`score_contributions` (a couple of ns), the
//! same in-place reset `examples/fastpath_bench.rs` uses — `RequestContext` is not
//! `Clone`, and a clone would dwarf the inspection it is meant to measure.
//!
//! **Worst-case payload, not the mean** (DEC 2): the PL3 ladder-binding corpus case
//! `lfi-rfi-remote-script-query`, which fires `rfi-remote-script` (Warning) AND overlaps
//! `rfi-remote-url` (Notice) — the most-accumulated-rules case from P2's score
//! distribution (ARCHITECTURE §7). Benching the worst case, not a clean/average request.
//!
//! **Instrument check (the bench-analog of the bite-test):** the reported time must land
//! in the ns-to-sub-µs regime consistent with `fastpath_bench.rs` (full-path inspection
//! was ~1520 ns @ C2/PL3). If this comes back in tens of µs, the harness is accidentally
//! timing setup/alloc, not inspection — the number would be measuring the wrong thing.
//!
//! On-demand, NOT a CI gate (DEC 4): `cargo bench -p waf-corpus`. The absolute `<1ms p99`
//! is declared on pinned hardware from this artifact; CI guards regressions relatively.
//!
//! **Pinned baseline (DEC 4 regression reference):** ~2 µs worst-case PL3. This is the
//! versioned reference the relative-regression gate compares against — NOT an absolute
//! assertion. **Headroom (DEC 1):** ~2 µs worst-case vs the p99 1 ms contract ≈ 500×
//! margin; the number depends only on our code, isolated from upstream/network.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use waf_corpus::{cases, corpus_pipeline, prepared_ctx, RECOMMENDED_SEVERITY};
use waf_core::RequestContext;
use waf_detection::ContentPrefilter;

/// Worst-case paranoia: every shipped rule active (most work per request).
const PL: u8 = 3;

/// The PL3 most-accumulated-rules case (ARCHITECTURE §7 ladder-binding worst case).
/// This bench id is the **pinned baseline reference** (~2 µs) for DEC 4 — do not rename.
const BASELINE_CASE_ID: &str = "lfi-rfi-remote-script-query";

/// The P2-flagged worst-case SET: PL3 cases with the most accumulated rules (declared
/// cross-module overlaps, ARCHITECTURE §7/§8). `ssrf-cloud-metadata-query` is the
/// heaviest (Critical + Notice link-local + rfi-remote-url = 3 rules). Benching the
/// worst case set, NOT the indiscriminate corpus mean (DEC 2).
const WORST_CASE_SET: &[&str] = &[
    "ssrf-cloud-metadata-query",
    "ssrf-loopback-query",
    "ssrf-ip-obfuscation-query",
    "ssrf-private-ip-query",
    "rce-download-exec-query",
];

/// Build + normalize a context for `id` ONCE, asserting it is a prefilter CANDIDATE.
/// The assert is the anti-pattern guard (ARCHITECTURE §13): if a payload were not a
/// candidate, production would skip inspection and this would bench a path real traffic
/// never takes — an optimistically false number.
fn prepared_candidate(id: &str, prefilter: &ContentPrefilter) -> RequestContext {
    let case = cases::all()
        .into_iter()
        .find(|c| c.id == id)
        .unwrap_or_else(|| panic!("corpus case {id} must exist"));
    let ctx = prepared_ctx(&case.field, PL, RECOMMENDED_SEVERITY)
        .unwrap_or_else(|| panic!("{id} has an inspectable path (no connection-phase reject)"));
    assert!(
        prefilter.is_candidate(&ctx),
        "{id}: not a prefilter candidate — benching the wrong path"
    );
    ctx
}

fn bench_inspection(c: &mut Criterion, name: &str, pipeline: &waf_pipeline::Pipeline, ctx: &mut RequestContext) {
    c.bench_function(name, |b| {
        b.iter(|| {
            // Reset the per-request accumulators so each iteration inspects from a clean
            // slate; cheap (ns) and identical to fastpath_bench's loop. `inspect = true`
            // forces the full enqueue→verdetto path (the payload is candidate-asserted).
            ctx.score = 0;
            ctx.score_contributions.clear();
            black_box(pipeline.run_inspection_gated(black_box(ctx), true));
        });
    });
}

fn inspect_worst_case(c: &mut Criterion) {
    let pipeline = corpus_pipeline(PL, RECOMMENDED_SEVERITY);
    let prefilter = ContentPrefilter::new(PL);

    // The pinned baseline (~2 µs, DEC 4 regression reference).
    let mut base = prepared_candidate(BASELINE_CASE_ID, &prefilter);
    bench_inspection(c, "inspect_worst_case_pl3", &pipeline, &mut base);

    // The rest of the P2 worst-case set, so the gate guards each — not a single point.
    for id in WORST_CASE_SET {
        let mut ctx = prepared_candidate(id, &prefilter);
        bench_inspection(c, &format!("inspect_worst_case/{id}"), &pipeline, &mut ctx);
    }
}

criterion_group!(benches, inspect_worst_case);
criterion_main!(benches);
