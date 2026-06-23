//! Fast-path micro-benchmark (Fase 7 / Pilastro 3). On-demand, no extra deps.
//! `cargo run --release -p waf-corpus --example fastpath_bench`.
//!
//! Measures the REAL gain of the prefilter skip, not a claim by eye. Pipeline,
//! prefilter and normalized contexts are built ONCE; only inspection vs prefilter
//! is timed. Reports, at the production config C2 / PL3:
//!   - how many corpus cases are skip-eligible (prefilter-clean) vs not;
//!   - on eligible (benign) traffic: full inspection time vs prefilter time → speedup;
//!   - the prefilter OVERHEAD added on non-eligible (malicious) traffic.
//!
//! Net benefit depends on the benign:malicious ratio (production is mostly benign).

use std::time::Instant;

use waf_corpus::{cases, corpus_pipeline, prepared_ctx, RECOMMENDED_SEVERITY};
use waf_core::RequestContext;
use waf_detection::ContentPrefilter;

const PL: u8 = 3;
const ITERS: u32 = 20_000;

fn time_full(pipeline: &waf_pipeline::Pipeline, ctxs: &mut [RequestContext]) -> f64 {
    let start = Instant::now();
    for _ in 0..ITERS {
        for ctx in ctxs.iter_mut() {
            ctx.score = 0;
            ctx.score_contributions.clear();
            std::hint::black_box(pipeline.run_inspection(ctx));
        }
    }
    let n = (ITERS as usize * ctxs.len()) as f64;
    start.elapsed().as_nanos() as f64 / n
}

fn time_prefilter(pf: &ContentPrefilter, ctxs: &[RequestContext]) -> f64 {
    let start = Instant::now();
    for _ in 0..ITERS {
        for ctx in ctxs {
            std::hint::black_box(pf.is_candidate(ctx));
        }
    }
    let n = (ITERS as usize * ctxs.len()) as f64;
    start.elapsed().as_nanos() as f64 / n
}

fn main() {
    let sev = RECOMMENDED_SEVERITY;
    let pipeline = corpus_pipeline(PL, sev);
    let prefilter = ContentPrefilter::new(PL);

    // Prepare normalized contexts once, split by prefilter eligibility.
    let mut eligible: Vec<RequestContext> = Vec::new(); // prefilter-clean → skippable
    let mut not_eligible: Vec<RequestContext> = Vec::new(); // prefilter hit → full path
    let mut total = 0usize;
    for case in cases::all() {
        if let Some(ctx) = prepared_ctx(&case.field, PL, sev) {
            total += 1;
            if prefilter.is_candidate(&ctx) {
                not_eligible.push(ctx);
            } else {
                eligible.push(ctx);
            }
        }
    }

    println!("== Fast-path bench @ C2 / PL{PL} ({ITERS} iters) ==\n");
    println!(
        "skip-eligible (prefilter-clean): {}/{}   not-eligible: {}",
        eligible.len(),
        total,
        not_eligible.len()
    );

    // Benign (eligible) traffic: full inspection vs prefilter-only (the skip cost).
    if eligible.is_empty() {
        println!("\n-- eligible/benign traffic: NONE eligible --");
        println!("   The union prefilter never skips: hdr-host-injection's pattern");
        println!("   `[/@]` (scoped to host headers in the module) matches the `/` in");
        println!("   every path / content-type when applied globally → always a candidate.");
    } else {
        let full_benign = time_full(&pipeline, &mut eligible);
        let pref_benign = time_prefilter(&prefilter, &eligible);
        println!("\n-- eligible/benign traffic (per request) --");
        println!("  full inspection : {full_benign:8.1} ns");
        println!("  prefilter+skip  : {pref_benign:8.1} ns");
        println!("  speedup         : {:8.2}x", full_benign / pref_benign);
        println!("  saved           : {:8.1} ns/req", full_benign - pref_benign);
    }

    // Malicious (not-eligible) traffic: the prefilter is pure overhead (then the
    // full path runs anyway). Report the added cost.
    if !not_eligible.is_empty() {
        let pref_mal = time_prefilter(&prefilter, &not_eligible);
        let full_mal = time_full(&pipeline, &mut not_eligible);
        println!("\n-- not-eligible/malicious traffic (per request) --");
        println!("  full inspection : {full_mal:8.1} ns");
        println!("  prefilter overhead added before full path: {pref_mal:8.1} ns");
        println!(
            "  relative overhead on malicious: {:.1}%",
            100.0 * pref_mal / full_mal
        );
    }

    println!("\nNet benefit = (eligible share) x (saved/req) - (malicious share) x (prefilter overhead).");
    println!("Production traffic is predominantly benign → eligible share dominates.");
}
