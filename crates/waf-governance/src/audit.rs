// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: BUSL-1.1

//! Tamper-evident audit log primitives: a SHA-256 **hash chain** (each record commits to the
//! previous record's hash) with an **Ed25519 signature** over each record's hash. Altering or
//! dropping any record breaks the chain (detectable) and forging a record needs the signing key
//! (non-repudiable). Pure functions here; persistence is in [`crate::store`].

use ring::signature::{Ed25519KeyPair, KeyPair, UnparsedPublicKey, ED25519};
use time::OffsetDateTime;

use crate::error::{Error, Result};
use crate::model::AuditRecord;

/// `prev_hash` of the first (genesis) record — a fixed all-zero digest.
pub const GENESIS_PREV: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// The record timestamp as integer microseconds since the Unix epoch — the form used in the hash,
/// chosen so it round-trips through Postgres `TIMESTAMPTZ` (microsecond precision) exactly.
pub fn ts_micros(ts: OffsetDateTime) -> i64 {
    (ts.unix_timestamp_nanos() / 1_000) as i64
}

fn feed(ctx: &mut ring::digest::Context, field: &[u8]) {
    ctx.update(&(field.len() as u64).to_be_bytes());
    ctx.update(field);
}

/// Compute the hex SHA-256 hash of one record's content, length-prefixing the variable fields so no
/// concatenation ambiguity is possible.
pub fn compute_hash(
    seq: i64,
    ts_micros: i64,
    actor: &str,
    action: &str,
    target: Option<&str>,
    details: &str,
    prev_hash: &str,
) -> String {
    let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
    ctx.update(&seq.to_be_bytes());
    ctx.update(&ts_micros.to_be_bytes());
    feed(&mut ctx, actor.as_bytes());
    feed(&mut ctx, action.as_bytes());
    feed(&mut ctx, target.unwrap_or("").as_bytes());
    feed(&mut ctx, details.as_bytes());
    feed(&mut ctx, prev_hash.as_bytes());
    hex::encode(ctx.finish().as_ref())
}

/// Hex SHA-256 of an arbitrary byte blob — the digest used to sign a derived artifact (e.g. a
/// compliance report bundle) with [`AuditSigner::sign_hash`], reusing the audit trust anchor.
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(ring::digest::digest(&ring::digest::SHA256, bytes).as_ref())
}

/// Holds the Ed25519 signing key (secret in memory; public key exported for verifiers).
pub struct AuditSigner {
    key_pair: Ed25519KeyPair,
    public_key_hex: String,
}

impl AuditSigner {
    /// Build from a 32-byte Ed25519 seed given as 64 hex chars (e.g. env `WAF_CP_AUDIT_KEY`).
    pub fn from_hex_seed(seed_hex: &str) -> Result<Self> {
        let seed = hex::decode(seed_hex.trim())
            .map_err(|_| Error::Config("audit key must be hex".into()))?;
        if seed.len() != 32 {
            return Err(Error::Config("audit key must be 32 bytes (64 hex chars)".into()));
        }
        let key_pair = Ed25519KeyPair::from_seed_unchecked(&seed)
            .map_err(|_| Error::Crypto("invalid audit key seed".into()))?;
        let public_key_hex = hex::encode(key_pair.public_key().as_ref());
        Ok(Self { key_pair, public_key_hex })
    }

    /// The public key (hex) — publish this so anyone can verify the chain.
    pub fn public_key_hex(&self) -> &str {
        &self.public_key_hex
    }

    /// Sign a record's hex hash, returning the signature as hex.
    pub fn sign_hash(&self, hash_hex: &str) -> String {
        hex::encode(self.key_pair.sign(hash_hex.as_bytes()).as_ref())
    }
}

/// Verify one signature: `sig_hex` over `hash_hex` under `pubkey_hex`.
pub fn verify_signature(pubkey_hex: &str, hash_hex: &str, sig_hex: &str) -> bool {
    let (Ok(pk), Ok(sig)) = (hex::decode(pubkey_hex), hex::decode(sig_hex)) else {
        return false;
    };
    UnparsedPublicKey::new(&ED25519, &pk).verify(hash_hex.as_bytes(), &sig).is_ok()
}

/// Why a chain failed verification, and where.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainBreak {
    /// Index into the slice (0-based) of the first bad record.
    pub index: usize,
    /// The `seq` of that record.
    pub seq: i64,
    /// What was wrong.
    pub reason: &'static str,
}

/// Verify a full chain (records **ordered by ascending `seq`**) against `pubkey_hex`: continuity
/// (each `prev_hash` links the previous record's `hash`, starting at [`GENESIS_PREV`]), integrity
/// (each stored `hash` matches a recomputation), and authenticity (each signature verifies).
pub fn verify_chain(
    records: &[AuditRecord],
    pubkey_hex: &str,
) -> std::result::Result<(), ChainBreak> {
    let mut prev = GENESIS_PREV.to_string();
    for (index, r) in records.iter().enumerate() {
        let brk = |reason| ChainBreak { index, seq: r.seq, reason };
        if r.prev_hash != prev {
            return Err(brk("prev_hash does not link the previous record"));
        }
        let recomputed = compute_hash(
            r.seq,
            ts_micros(r.ts),
            &r.actor,
            &r.action,
            r.target.as_deref(),
            &r.details,
            &r.prev_hash,
        );
        if recomputed != r.hash {
            return Err(brk("hash does not match record content"));
        }
        if !verify_signature(pubkey_hex, &r.hash, &r.signature) {
            return Err(brk("signature does not verify"));
        }
        prev = r.hash.clone();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // A deterministic test seed (NOT a real key).
    const SEED: &str = "0101010101010101010101010101010101010101010101010101010101010101";

    fn rec(signer: &AuditSigner, seq: i64, prev: &str, action: &str) -> AuditRecord {
        let ts = OffsetDateTime::from_unix_timestamp(1_700_000_000 + seq).unwrap();
        let details = format!("{{\"n\":{seq}}}");
        let hash = compute_hash(seq, ts_micros(ts), "admin", action, None, &details, prev);
        let signature = signer.sign_hash(&hash);
        AuditRecord {
            seq,
            ts,
            actor: "admin".into(),
            action: action.into(),
            target: None,
            details,
            prev_hash: prev.into(),
            hash,
            signature,
        }
    }

    fn build_chain(signer: &AuditSigner, n: i64) -> Vec<AuditRecord> {
        let mut out = Vec::new();
        let mut prev = GENESIS_PREV.to_string();
        for seq in 1..=n {
            let r = rec(signer, seq, &prev, "act");
            prev = r.hash.clone();
            out.push(r);
        }
        out
    }

    #[test]
    fn key_and_signature_roundtrip() {
        let s = AuditSigner::from_hex_seed(SEED).unwrap();
        let h = compute_hash(1, 42, "admin", "login", None, "{}", GENESIS_PREV);
        let sig = s.sign_hash(&h);
        assert!(verify_signature(s.public_key_hex(), &h, &sig));
        assert!(!verify_signature(s.public_key_hex(), &h, &s.sign_hash("different")));
    }

    #[test]
    fn valid_chain_verifies() {
        let s = AuditSigner::from_hex_seed(SEED).unwrap();
        let chain = build_chain(&s, 5);
        assert!(verify_chain(&chain, s.public_key_hex()).is_ok());
    }

    #[test]
    fn tampered_details_breaks_chain() {
        let s = AuditSigner::from_hex_seed(SEED).unwrap();
        let mut chain = build_chain(&s, 5);
        // Alter a record's content WITHOUT recomputing its hash → hash mismatch at that seq.
        chain[2].details = "{\"n\":999}".to_string();
        let brk = verify_chain(&chain, s.public_key_hex()).unwrap_err();
        assert_eq!(brk.seq, 3);
        assert_eq!(brk.reason, "hash does not match record content");
    }

    #[test]
    fn dropped_record_breaks_continuity() {
        let s = AuditSigner::from_hex_seed(SEED).unwrap();
        let mut chain = build_chain(&s, 5);
        chain.remove(2); // now record 4's prev_hash points at the removed record 3
        let brk = verify_chain(&chain, s.public_key_hex()).unwrap_err();
        assert_eq!(brk.reason, "prev_hash does not link the previous record");
    }

    #[test]
    fn forged_signature_breaks_chain() {
        let s = AuditSigner::from_hex_seed(SEED).unwrap();
        let mut chain = build_chain(&s, 3);
        // Re-hash tampered content so continuity/hash pass, but sign with the WRONG key.
        let other = AuditSigner::from_hex_seed(
            "0202020202020202020202020202020202020202020202020202020202020202",
        )
        .unwrap();
        chain[1].signature = other.sign_hash(&chain[1].hash);
        let brk = verify_chain(&chain, s.public_key_hex()).unwrap_err();
        assert_eq!(brk.reason, "signature does not verify");
    }

    #[test]
    fn bad_seed_rejected() {
        assert!(AuditSigner::from_hex_seed("zz").is_err());
        assert!(AuditSigner::from_hex_seed("00").is_err()); // wrong length
    }
}
