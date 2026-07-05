// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: BUSL-1.1

//! Signed WASM plugin loader (§4-C). The OPEN Proxy-Wasm runtime (`waf-wasm`) loads UNSIGNED plugins
//! from `[modules.wasm]` (skip-on-error). This tier adds the **trust gate**: verify a detached
//! **minisign** (ed25519) signature over the exact `.wasm` bytes against configured trusted public
//! keys BEFORE delegating to the OPEN `WasmModule::from_bytes` — zero core changes.
//!
//! **Posture divergence (deliberate, K5).** Unlike the OPEN loader (a missing/broken unsigned plugin
//! is skipped, degrading coverage), a signed plugin whose signature does NOT verify is
//! indistinguishable from tampering → **fail-closed / boot-fatal**, never a silent skip.
//!
//! **STEP 1 (scaffold).** The crate stands up the two public seams — [`verify_signature`] (minisign
//! detached-signature verification against trusted keys) and [`load_verified_plugin`] (verify → the
//! OPEN `WasmModule::from_bytes`) — proven by unit tests. There is no `rule_id` registry: a WASM
//! plugin's verdict comes from the plugin via the OPEN runtime, not from this loader (K7). The
//! `[enterprise.wasm]` config + wiring + the real-plugin datapath land in later steps.

use std::io::Cursor;

use minisign::{PublicKey, SignatureBox};
use waf_wasm::WasmModule;

// Re-export so the enterprise wiring builds runtime options without depending on `waf-wasm` directly.
pub use waf_wasm::WasmOptions;

/// Verify a detached minisign `signature` (the `.minisig` text) over `wasm`, accepting it if it
/// verifies against ANY of the base64 `trusted_pubkeys` (the key line of a minisign `.pub`).
/// Fail-closed: unknown key, malformed signature, or tampered bytes all return `Err`.
pub fn verify_signature(
    wasm: &[u8],
    signature: &str,
    trusted_pubkeys: &[String],
) -> Result<(), String> {
    let sig_box =
        SignatureBox::from_string(signature).map_err(|e| format!("malformed signature: {e}"))?;
    if trusted_pubkeys.is_empty() {
        return Err("no trusted_keys configured".to_string());
    }
    for key_b64 in trusted_pubkeys {
        let Ok(pk) = PublicKey::from_base64(key_b64) else {
            continue; // a malformed configured key can't be the one that trusts this plugin
        };
        if minisign::verify(&pk, &sig_box, Cursor::new(wasm), true, false, false).is_ok() {
            return Ok(());
        }
    }
    Err("signature does not verify against any trusted key".to_string())
}

/// Verify the plugin's signature and, ONLY if it verifies, delegate to the OPEN
/// `WasmModule::from_bytes`. The **same `wasm` buffer** is verified and loaded (no TOCTOU, K4). A
/// signature failure returns before the runtime ever compiles the bytes (fail-closed gate, K5).
pub fn load_verified_plugin(
    name: &str,
    wasm: &[u8],
    signature: &str,
    trusted_pubkeys: &[String],
    config: &[u8],
    opts: &WasmOptions,
) -> Result<WasmModule, String> {
    verify_signature(wasm, signature, trusted_pubkeys)?;
    let (module, _report) = WasmModule::from_bytes(name, wasm, config, opts)
        .map_err(|e| format!("verified plugin {name:?} failed to load: {e}"))?;
    Ok(module)
}

#[cfg(test)]
mod tests {
    use super::*;
    use minisign::KeyPair;

    /// Sign `data`, returning `(minisig_text, pubkey_base64)`.
    fn sign(data: &[u8]) -> (String, String) {
        let kp = KeyPair::generate_unencrypted_keypair().unwrap();
        let sig_box = minisign::sign(None, &kp.sk, Cursor::new(data), None, None).unwrap();
        (sig_box.into_string(), kp.pk.to_base64())
    }

    const WASM: &[u8] = b"\x00asm\x01\x00\x00\x00 pretend this is a plugin";

    #[test]
    fn valid_signature_verifies() {
        let (sig, pk) = sign(WASM);
        assert!(verify_signature(WASM, &sig, &[pk]).is_ok());
    }

    #[test]
    fn tampered_bytes_fail() {
        let (sig, pk) = sign(WASM);
        let mut tampered = WASM.to_vec();
        tampered[10] ^= 0xff;
        assert!(verify_signature(&tampered, &sig, &[pk]).is_err());
    }

    #[test]
    fn wrong_key_fails() {
        let (sig, _pk) = sign(WASM);
        let (_sig2, other_pk) = sign(WASM); // a different keypair
        assert!(verify_signature(WASM, &sig, &[other_pk]).is_err());
    }

    #[test]
    fn malformed_signature_fails() {
        assert!(verify_signature(WASM, "not a minisig", &["x".to_string()]).is_err());
    }

    #[test]
    fn no_trusted_keys_fails() {
        let (sig, _pk) = sign(WASM);
        assert!(verify_signature(WASM, &sig, &[]).is_err());
    }

    #[test]
    fn verifies_against_any_of_several_keys() {
        let (sig, pk) = sign(WASM);
        let (_s, other) = sign(WASM);
        // The trusted set contains an unrelated key AND the right one → accepted.
        assert!(verify_signature(WASM, &sig, &[other, pk]).is_ok());
    }

    fn opts() -> WasmOptions {
        WasmOptions::default()
    }

    #[test]
    fn load_gate_rejects_bad_signature_before_touching_the_runtime() {
        // A real (minimal) wasm module, but an UNTRUSTED signature → must fail at the gate.
        let wasm = wat::parse_str("(module)").unwrap();
        let (sig, _pk) = sign(&wasm);
        let (_s, other) = sign(&wasm); // sign is fine; the key is not trusted
        match load_verified_plugin("p", &wasm, &sig, &[other], b"", &opts()) {
            Ok(_) => panic!("an untrusted signature must not load"),
            Err(e) => assert!(e.contains("verify") || e.contains("trusted"), "gate error, got: {e}"),
        }
    }

    #[test]
    fn load_with_valid_signature_reaches_the_runtime() {
        // Same wasm, TRUSTED signature → the gate passes and control reaches `from_bytes`. Whatever
        // the runtime decides about a bare `(module)`, the error (if any) is NOT a signature error.
        let wasm = wat::parse_str("(module)").unwrap();
        let (sig, pk) = sign(&wasm);
        match load_verified_plugin("p", &wasm, &sig, &[pk], b"", &opts()) {
            Ok(_) => {} // loaded
            Err(e) => assert!(
                !e.contains("verify") && !e.contains("trusted"),
                "must fail (if at all) at the runtime, not the gate: {e}"
            ),
        }
    }
}
