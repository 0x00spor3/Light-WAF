// SPDX-License-Identifier: Apache-2.0
//! Quick latency bench for the WASM module on the hot path (paletto #2: fuel is a LATENCY
//! ceiling, so the number that matters is p99 of a benign request with a FULL fuel budget —
//! the plugin that always burns near its budget without trapping, not the one that traps).
//!
//! Run: `cargo run -p waf-wasm --release --example wasm_bench`

use std::time::Instant;

use waf_core::testkit::Request;
use waf_core::WafModule;
use waf_wasm::{WasmModule, WasmOptions};

// A guest that, on every request, reads the header map (reentrant alloc into guest memory)
// and scans it — representative work for a content-inspecting filter.
const BLOCK_WAT: &str = r#"
(module
  (import "env" "proxy_get_header_map_pairs" (func $get_headers (param i32 i32 i32) (result i32)))
  (import "env" "proxy_send_local_response" (func $send (param i32 i32 i32 i32 i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (global $bump (mut i32) (i32.const 1024))
  (func (export "proxy_on_memory_allocate") (param $n i32) (result i32)
    (local $p i32) (local $need i32)
    (local.set $p (global.get $bump))
    (local.set $need (i32.add (local.get $p) (local.get $n)))
    (global.set $bump (local.get $need))
    (block $d (loop $g
      (br_if $d (i32.le_u (local.get $need) (i32.mul (memory.size) (i32.const 65536))))
      (if (i32.eq (memory.grow (i32.const 1)) (i32.const -1)) (then (return (i32.const -1))))
      (br $g)))
    (local.get $p))
  (func (export "proxy_on_context_create") (param i32 i32))
  (func (export "proxy_on_request_headers") (param i32 i32 i32) (result i32)
    (local $ptr i32) (local $size i32) (local $i i32) (local $base i32)
    (global.set $bump (i32.const 1024))  ;; reset the bump allocator each request (no leak)
    (drop (call $get_headers (i32.const 0) (i32.const 0) (i32.const 4)))
    (local.set $ptr (i32.load (i32.const 0)))
    (local.set $size (i32.load (i32.const 4)))
    (local.set $i (i32.const 0))
    (block $found (block $notfound
      (loop $scan
        (br_if $notfound (i32.gt_s (local.get $i) (i32.sub (local.get $size) (i32.const 3))))
        (local.set $base (i32.add (local.get $ptr) (local.get $i)))
        (if (i32.and (i32.and
              (i32.eq (i32.load8_u (local.get $base)) (i32.const 120))
              (i32.eq (i32.load8_u (i32.add (local.get $base) (i32.const 1))) (i32.const 45)))
              (i32.eq (i32.load8_u (i32.add (local.get $base) (i32.const 2))) (i32.const 98)))
          (then (br $found)))
        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (br $scan)))
      (return (i32.const 0)))
    (drop (call $send (i32.const 403) (i32.const 0) (i32.const 0)
                      (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 0)))
    (i32.const 1))
  (func (export "proxy_on_request_body") (param i32 i32 i32) (result i32) (i32.const 0))
  (func (export "proxy_on_done") (param i32) (result i32) (i32.const 1))
  (func (export "proxy_on_delete") (param i32)))
"#;

fn main() {
    let wasm = wat::parse_str(BLOCK_WAT).expect("wat");
    let (m, _r) = WasmModule::from_bytes("bench", &wasm, b"", &WasmOptions::default()).expect("build");
    // A representative benign request: several headers, so the header-map work is non-trivial.
    let ctx = Request::new()
        .header("host", "example.test")
        .header("user-agent", "bench/1.0")
        .header("accept", "text/html,application/xhtml+xml")
        .header("accept-language", "en-US,en;q=0.9")
        .header("cookie", "sid=abc123; theme=dark")
        .build();

    for _ in 0..2_000 {
        std::hint::black_box(m.inspect(&ctx));
    }
    let n = 200_000usize;
    let mut times = Vec::with_capacity(n);
    for _ in 0..n {
        let t = Instant::now();
        std::hint::black_box(m.inspect(&ctx));
        times.push(t.elapsed().as_nanos() as u64);
    }
    times.sort_unstable();
    let pct = |q: f64| times[((n as f64 * q) as usize).min(n - 1)];
    let mean = times.iter().sum::<u64>() / n as u64;
    println!(
        "wasm inspect ({n} iters): mean={mean}ns p50={}ns p90={}ns p99={}ns p99.9={}ns max={}ns",
        pct(0.50),
        pct(0.90),
        pct(0.99),
        pct(0.999),
        times[n - 1],
    );
}
