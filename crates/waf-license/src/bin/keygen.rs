// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: BUSL-1.1

//! `waf-license-keygen` — mint a fresh Ed25519 keypair for signing demo licenses.
//!
//! Run this ONCE (offline). Keep the seed secret (it signs licenses); paste the public key into
//! `LICENSE_PUBKEY_HEX` in `waf-license/src/lib.rs`, then cut the demo build.

use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{Ed25519KeyPair, KeyPair};

fn main() {
    let rng = SystemRandom::new();
    let mut seed = [0u8; 32];
    rng.fill(&mut seed).expect("system RNG");
    let key_pair = Ed25519KeyPair::from_seed_unchecked(&seed).expect("valid seed");

    println!("# Light WAF — demo-license keypair (generated offline)");
    println!("# KEEP THE SEED SECRET — it signs licenses. Do NOT commit it or ship it in a binary.");
    println!("# Paste PUBKEY into LICENSE_PUBKEY_HEX (waf-license/src/lib.rs), then build the demo.");
    println!("WAF_LICENSE_SIGNING_KEY={}", hex::encode(seed));
    println!("LICENSE_PUBKEY_HEX={}", hex::encode(key_pair.public_key().as_ref()));
}
