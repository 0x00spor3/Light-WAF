// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: BUSL-1.1

//! STEP-5 bite-test (§4-C), **env-gated** on `WAF_WASM_FIXTURE` = a path to a REAL Proxy-Wasm plugin
//! `.wasm` (e.g. `examples/wasm-plugin/target/wasm32-unknown-unknown/release/waf_wasm_example.wasm`).
//! Same posture as the OPEN B3 WASM smoke.
//!
//! Proves the §4-C contract end-to-end with a real plugin: a VALID signature loads the plugin and
//! its verdict flows on the REAL pipeline (the example blocks on the `X-Block` kill-switch); a
//! TAMPERED plugin or a WRONG key is refused by the gate (fail-closed, K5) — the runtime never sees it.

use std::io::Cursor;

use minisign::KeyPair;
use waf_core::{Bytes, Config, Normalized, RequestContext, WafMode};
use waf_marketplace::{load_verified_plugin, verify_signature, WasmOptions};
use waf_pipeline::{Pipeline, PipelineVerdict};

fn fixture() -> Option<Vec<u8>> {
    let path = std::env::var("WAF_WASM_FIXTURE").ok()?;
    Some(std::fs::read(path).expect("WAF_WASM_FIXTURE unreadable"))
}

/// Sign `data`, returning `(minisig_text, pubkey_base64)`.
fn sign(data: &[u8]) -> (String, String) {
    let kp = KeyPair::generate_unencrypted_keypair().unwrap();
    let sig = minisign::sign(None, &kp.sk, Cursor::new(data), None, None).unwrap();
    (sig.into_string(), kp.pk.to_base64())
}

/// Runbook convenience (no `minisign` CLI needed): sign `$WAF_WASM_IN`, write the `.minisig` to
/// `$WAF_SIG_OUT` (default `<in>.minisig`) and print the base64 public key for `trusted_keys`.
/// Run: `WAF_WASM_IN=plugin.wasm cargo test -p waf-marketplace sign_plugin -- --ignored --nocapture`
#[test]
#[ignore]
fn sign_plugin() {
    let wasm_in = std::env::var("WAF_WASM_IN").expect("set WAF_WASM_IN to the .wasm to sign");
    let sig_out = std::env::var("WAF_SIG_OUT").unwrap_or_else(|_| format!("{wasm_in}.minisig"));
    let wasm = std::fs::read(&wasm_in).expect("WAF_WASM_IN unreadable");
    let (sig, pk) = sign(&wasm);
    std::fs::write(&sig_out, sig).expect("cannot write signature");
    eprintln!("wrote signature to {sig_out}");
    eprintln!("trusted_keys = [\"{pk}\"]");
}

fn request(headers: &[(&str, &str)]) -> RequestContext {
    let owned: Vec<(String, String)> =
        headers.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
    let normalized =
        Normalized { headers: owned.clone(), path: "/".to_string(), ..Default::default() };
    RequestContext {
        client_ip: "203.0.113.10".parse().unwrap(),
        request_id: "bite".to_string(),
        timestamp: std::time::SystemTime::now(),
        method: "GET".to_string(),
        path: "/".to_string(),
        raw_path: "/".to_string(),
        query: None,
        http_version: "HTTP/1.1".to_string(),
        headers: owned,
        cookies: vec![],
        body: Bytes::new(),
        normalized,
        score: 0,
        score_contributions: vec![],
    }
}

#[test]
fn verified_plugin_blocks_on_the_pipeline_and_tampering_is_refused() {
    let Some(wasm) = fixture() else {
        eprintln!("WAF_WASM_FIXTURE not set — skipping real-plugin bite-test");
        return;
    };
    let (sig, pk) = sign(&wasm);
    let opts = WasmOptions::default();

    // Valid signature → the plugin loads through the gate.
    let module = load_verified_plugin("denylist", &wasm, &sig, std::slice::from_ref(&pk), b"", &opts)
        .expect("a validly-signed plugin must load");

    let mut config = Config::default();
    config.waf.mode = WafMode::Blocking;
    let pipe = Pipeline::new(&config, vec![Box::new(module)]);

    // The example plugin's `X-Block` kill-switch → the verdict flows to a block on the datapath.
    let mut ctx = request(&[("x-block", "1")]);
    assert!(
        !matches!(pipe.run(&mut ctx), PipelineVerdict::Allow),
        "the verified plugin's block verdict must flow on the pipeline"
    );

    // A benign request passes (the plugin doesn't block everything).
    let mut benign = request(&[("user-agent", "curl/8.4.0")]);
    assert!(matches!(pipe.run(&mut benign), PipelineVerdict::Allow), "benign request must pass");

    // TAMPERED bytes → the gate refuses before the runtime (fail-closed, K5).
    let mut tampered = wasm.clone();
    let n = tampered.len() / 2;
    tampered[n] ^= 0xff;
    assert!(verify_signature(&tampered, &sig, std::slice::from_ref(&pk)).is_err(), "tampering must be caught");
    assert!(
        load_verified_plugin("denylist", &tampered, &sig, &[pk], b"", &opts).is_err(),
        "a tampered plugin must never load"
    );

    // WRONG key → refused.
    let (_s, other_key) = sign(&wasm);
    assert!(
        load_verified_plugin("denylist", &wasm, &sig, &[other_key], b"", &opts).is_err(),
        "an untrusted key must never load the plugin"
    );
}
