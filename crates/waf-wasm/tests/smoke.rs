// SPDX-License-Identifier: Apache-2.0
//! Env-gated ABI-fidelity smoke: load a REAL Proxy-Wasm SDK filter (built separately, see
//! `tests/fixtures/README.md`) and prove the host runs it unchanged. Skipped unless
//! `WAF_WASM_FIXTURE` points at a `.wasm` file — same pattern as the repo's other env-gated
//! oracles (gotestwaf, real CRS). The deterministic in-CI coverage lives in `runtime.rs`.

use waf_core::testkit::Request;
use waf_core::{Decision, WafModule};
use waf_wasm::{WasmModule, WasmOptions};

#[test]
fn real_proxy_wasm_filter_blocks_and_allows() {
    let Ok(path) = std::env::var("WAF_WASM_FIXTURE") else {
        eprintln!("WAF_WASM_FIXTURE unset — skipping real-filter ABI smoke (see fixtures/README.md)");
        return;
    };
    let wasm = std::fs::read(&path).expect("read fixture .wasm");
    let (module, report) =
        WasmModule::from_bytes("block_filter", &wasm, b"", &WasmOptions::default())
            .expect("the real SDK filter must load on our host");
    eprintln!("import report: {}", report.summary());

    // Trigger: an x-block header -> the filter sends a 403 local response.
    let blocked = module.inspect(&Request::new().header("x-block", "1").build());
    assert!(matches!(blocked, Decision::Block { .. }), "expected Block, got {blocked:?}");

    // Benign -> Allow.
    let allowed = module.inspect(&Request::new().header("accept", "text/html").build());
    assert_eq!(allowed, Decision::Allow);
}
