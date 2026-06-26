// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

//! B2 performance characterization (paletto #2). `CrsModule` is `structural()`, so it runs
//! on EVERY request — bypassing the §7 content fast-path. This measures the per-request
//! `inspect()` cost as the rule count grows, to confirm the `(vars, t:)` bucketing keeps the
//! cost tied to the number of BUCKETS, not the number of rules.
//!
//! Run: `cargo run -p waf-detection --release --example crs_bench`

use std::time::Instant;

use waf_core::{Bytes, Normalized, RequestContext, WafModule};
use waf_detection::crs::CrsModule;

fn ctx() -> RequestContext {
    RequestContext {
        client_ip: "127.0.0.1".parse().unwrap(),
        request_id: "b".to_string(),
        timestamp: std::time::SystemTime::now(),
        method: "GET".to_string(),
        path: "/shop/item".to_string(),
        raw_path: "/shop/item".to_string(),
        // A realistic benign request with a few args, none matching the rules.
        query: Some("id=4821&ref=homepage&utm=spring_sale&q=blue+running+shoes".to_string()),
        http_version: "HTTP/1.1".to_string(),
        headers: vec![
            ("host".to_string(), "shop.example".to_string()),
            ("user-agent".to_string(), "Mozilla/5.0".to_string()),
        ],
        cookies: vec![("sid".to_string(), "abc123".to_string())],
        body: Bytes::new(),
        normalized: Normalized::default(),
        score: 0,
        score_contributions: vec![],
    }
}

/// `n` single-link `@rx ARGS` rules sharing one `(vars, t:)` bucket → one RegexSet.
fn one_bucket(n: usize) -> String {
    let mut s = String::new();
    for i in 0..n {
        s.push_str(&format!(
            "SecRule ARGS \"@rx (?i)attacktoken{i}\\b\" \"id:{},phase:2,severity:CRITICAL,t:lowercase,t:urlDecode\"\n",
            10_000 + i
        ));
    }
    s
}

/// `n` rules spread across 5 FIXED buckets (5 distinct transform pipelines). Comparing
/// this to `one_bucket` at the same `n` shows the cost tracks the bucket COUNT (≈5×), not
/// the rule count: 500 rules in 1 bucket are cheaper than 50 rules in 5 buckets.
fn many_buckets(n: usize) -> String {
    let tfms = ["t:lowercase", "t:urlDecode", "t:lowercase,t:urlDecode", "t:none", "t:htmlEntityDecode"];
    let mut s = String::new();
    for i in 0..n {
        s.push_str(&format!(
            "SecRule ARGS \"@rx (?i)attacktoken{i}\\b\" \"id:{},phase:2,severity:CRITICAL,{}\"\n",
            20_000 + i,
            tfms[i % tfms.len()]
        ));
    }
    s
}

fn time(label: &str, module: &CrsModule, iters: u32) {
    let ctx = ctx();
    // warm-up
    for _ in 0..1_000 {
        std::hint::black_box(module.inspect(std::hint::black_box(&ctx)));
    }
    let start = Instant::now();
    for _ in 0..iters {
        std::hint::black_box(module.inspect(std::hint::black_box(&ctx)));
    }
    let per = start.elapsed().as_nanos() as f64 / iters as f64;
    println!(
        "{label:<34} loaded={:<5} {per:>8.0} ns/req  ({:.2} µs)",
        module.loaded_count(),
        per / 1000.0
    );
}

fn main() {
    let iters = 50_000;
    println!("CRS inspect() cost on a benign 4-arg request ({iters} iters each)\n");

    println!("— one shared (ARGS, t:) bucket → one RegexSet pass —");
    for n in [50usize, 200, 500] {
        time(&format!("one_bucket n={n}"), &CrsModule::from_source(&one_bucket(n)), iters);
    }

    println!("\n— n rules over 5 fixed buckets → 5 value-extractions + 5 RegexSet passes —");
    for n in [50usize, 200, 500] {
        time(&format!("5_buckets n={n}"), &CrsModule::from_source(&many_buckets(n)), iters);
    }
}
