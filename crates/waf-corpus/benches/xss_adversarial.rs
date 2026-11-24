// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

//! F1 M2 famiglia 3 — adversarial latency of the tag-anchored `xss-event-handler` branch
//! (famiglia 4 adds the `js-*` inputs for the URL-context branches of `xss-javascript-proto`).
//!
//! The branch walks the attribute grammar of an open tag with single-class stars, so its
//! worst inputs are the ones that keep the lazy DFA inside a tag: many unclosed attribute
//! openings, thousands of attributes, an unclosed quote followed by free text, a handler
//! after a huge value. Each input is a raw `text/plain` body just under the default 1 MiB
//! `max_body_size`, timed three ways: the XSS module alone, the content prefilter, and
//! the full inspection path (`run_inspection_gated`).
//!
//! On-demand, not a CI gate, separate from the pinned `inspection` bench:
//! `cargo bench -p waf-corpus --bench xss_adversarial -- --save-baseline <name>`.

use std::hint::black_box;
use std::time::Duration;

use criterion::{criterion_group, criterion_main, Criterion};
use waf_corpus::{corpus_pipeline, prepared_ctx, Field, RECOMMENDED_SEVERITY};
use waf_core::{Config, RequestContext, WafModule};
use waf_detection::{xss::XssModule, ContentPrefilter};

const PL: u8 = 3;
/// Just under the default `max_body_size` (1 MiB), so normalization accepts the body.
const BODY_BYTES: usize = 1_000_000;

fn fill(unit: &str, prefix: &str, suffix: &str) -> &'static str {
    let n = (BODY_BYTES - prefix.len() - suffix.len()) / unit.len();
    let s = format!("{prefix}{}{suffix}", unit.repeat(n));
    Box::leak(s.into_boxed_str())
}

fn inputs() -> Vec<(&'static str, &'static str)> {
    vec![
        ("unclosed-attr-repeat", fill("<a a=\"", "", "")),
        ("many-attrs-no-handler", fill("a=1 ", "<x ", ">")),
        ("unclosed-quote-text", fill("compra online = subito ", "<p title=\"", "")),
        ("handler-after-huge-value", fill("A", "<body title=\"", "\" onpageshow=print()>")),
        // F1 M2 famiglia 4 — `xss-javascript-proto` URL-context branches.
        ("js-scheme-no-indicator", fill("javascript: x ", "", "")),
        ("js-url-attr-no-scheme", fill("href=\" ", "", "")),
        ("js-split-scheme-no-colon", fill("j	a	v	a	s	c	r	i	p	t	", "", "")),
        ("js-leading-ws-no-colon", fill("	", "", "javascript")),
    ]
}

fn ctx_for(body: &'static str) -> RequestContext {
    let field = Field::RawBody { content_type: "text/plain", body };
    prepared_ctx(&field, PL, RECOMMENDED_SEVERITY).expect("body within limits must normalize")
}

fn bench(c: &mut Criterion) {
    let mut cfg = Config::default();
    cfg.waf.paranoia_level = PL;
    let mut xss = XssModule::new();
    xss.init(&cfg);
    let prefilter = ContentPrefilter::new(PL);
    let pipeline = corpus_pipeline(PL, RECOMMENDED_SEVERITY);

    let mut g = c.benchmark_group("xss_adversarial");
    g.sample_size(20).measurement_time(Duration::from_secs(5)).warm_up_time(Duration::from_secs(1));
    for (name, body) in inputs() {
        let mut ctx = ctx_for(body);
        g.bench_function(format!("module/{name}"), |b| b.iter(|| black_box(xss.inspect(black_box(&ctx)))));
        g.bench_function(format!("prefilter/{name}"), |b| {
            b.iter(|| black_box(prefilter.is_candidate(black_box(&ctx))))
        });
        g.bench_function(format!("pipeline/{name}"), |b| {
            b.iter(|| {
                ctx.score = 0;
                ctx.score_contributions.clear();
                black_box(pipeline.run_inspection_gated(black_box(&mut ctx), true));
            })
        });
    }
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
