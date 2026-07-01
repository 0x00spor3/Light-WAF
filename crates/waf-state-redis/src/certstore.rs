// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: BUSL-1.1

//! [`SharedCertStore`] — the THIRD capability on the same [`RedisStore`] pool (after
//! `StateStore` and `ReputationStore`): a cluster-wide store for ACME-managed TLS certs plus a
//! single-writer issuance lock. It closes the "certs are per-node, not coordinated" gap so N
//! WAF nodes issue ONE cert (not N×, no LE rate-limit pressure, one account) and all serve it.
//!
//! Modelled on Caddy/CertMagic: **shared storage** for the cert+key, a **distributed lock** so
//! exactly one node issues at a time. Enterprise-only, zero core: the driver in
//! `waf-tls-managed` consumes `dyn SharedCertStore` and keeps the `TlsCertSource::resolver()`
//! seam unchanged.
//!
//! ## Security posture
//! Serving one cert on N nodes inherently means the private KEY travels through Redis. It is
//! therefore **encrypted at rest** ([`CertCipher`], AES-256-GCM, key = HKDF-SHA256 of the
//! operator secret `WAF_CERT_STORE_KEY`) BEFORE it enters Redis — a plaintext key in a shared
//! store would fail any compliance audit. A **fresh random 96-bit nonce per write** (prepended
//! to the ciphertext) is mandatory: GCM is catastrophic under nonce reuse with a fixed key.
//!
//! ## Lock discipline (same atomicity rigor as the token bucket)
//! - `try_lock` = `SET k v NX PX ttl` (only one holder).
//! - `unlock` / `extend_lock` = Lua **compare-and-(del|pexpire)**: touch the lock ONLY if we
//!   still own it, so we never steal another leader's re-acquired lock after our TTL lapsed.
//! - `store_cert` = Lua **compare-and-set**: write the cert blob ONLY while we hold the lock, so
//!   a buggy follower or a race can't overwrite a valid cert (defense in depth, ~zero cost).
//! - Single-Redis lock (not multi-master Redlock) — consistent with the rate-limit assumption.

use std::time::Duration;

use base64::Engine as _;
use redis::Script;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, NONCE_LEN};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::{pool_to_redis_err, RedisStore};

/// A managed TLS certificate as the driver sees it: the issued chain, OUR private key, and the
/// cert's expiry. `key_pem` is the PLAINTEXT key — the type deliberately does NOT derive
/// `Serialize`, so it can never be persisted in the clear by accident (the on-wire [`StoredBlob`]
/// carries the encrypted key instead).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharedCert {
    pub chain_pem: String,
    pub key_pem: String,
    pub not_after_unix: i64,
}

/// The on-wire (Redis) representation: chain and expiry in the clear (chain is public anyway),
/// the private key **encrypted** (base64 of `nonce||ciphertext||tag`).
#[derive(Serialize, Deserialize)]
struct StoredBlob {
    chain_pem: String,
    key_pem_enc: String,
    not_after_unix: i64,
}

/// Cluster-wide TLS cert storage + single-writer issuance lock — the enterprise injection seam
/// the DNS-01 driver consumes (the cert analogue of `StateStore`). `key` is the caller's logical
/// identifier (the sorted-domain-set hash); the store owns the Redis keyspace derived from it.
pub trait SharedCertStore: Send + Sync {
    /// The currently stored cert for `key`, or `None` if absent / unreadable / undecryptable.
    fn load_cert(&self, key: &str) -> Option<SharedCert>;
    /// Store `cert` for `key`, but ONLY if we still hold the issuance lock as `holder` (atomic
    /// compare-and-set). Returns `true` iff the blob was written.
    fn store_cert(&self, key: &str, holder: &str, cert: &SharedCert) -> bool;
    /// Try to become the single writer for `key` (`SET NX PX`). `true` iff acquired.
    fn try_lock(&self, key: &str, holder: &str, ttl: Duration) -> bool;
    /// Extend our lock's TTL, ONLY if we still own it (compare-and-pexpire). `false` (lock lost)
    /// is the signal for the leader to ABORT the in-flight issuance and retry later.
    fn extend_lock(&self, key: &str, holder: &str, ttl: Duration) -> bool;
    /// Release the lock, ONLY if we still own it (compare-and-delete).
    fn unlock(&self, key: &str, holder: &str);
}

/// `GET k == holder ? PEXPIRE k ttl : 0` — extend only our own lock.
const EXTEND_LUA: &str = r#"
if redis.call('GET', KEYS[1]) == ARGV[1] then
  return redis.call('PEXPIRE', KEYS[1], ARGV[2])
else
  return 0
end
"#;

/// `GET k == holder ? DEL k : 0` — delete only our own lock.
const UNLOCK_LUA: &str = r#"
if redis.call('GET', KEYS[1]) == ARGV[1] then
  return redis.call('DEL', KEYS[1])
else
  return 0
end
"#;

/// `GET lock == holder ? SET cert blob, 1 : 0` — write the cert blob only while we hold the lock.
const STORE_LUA: &str = r#"
if redis.call('GET', KEYS[1]) == ARGV[1] then
  redis.call('SET', KEYS[2], ARGV[2])
  return 1
else
  return 0
end
"#;

fn cert_key(key: &str) -> String {
    format!("cert:{key}")
}
fn lock_key(key: &str) -> String {
    format!("issuance_lock:{key}")
}

/// Run a blocking Redis closure, yielding the worker for the round-trip when a multi-thread
/// runtime is present (same sync-on-async discipline as `StateStore`/`ReputationStore`).
fn blocking<T>(f: impl FnOnce() -> T) -> T {
    match tokio::runtime::Handle::try_current() {
        Ok(_) => tokio::task::block_in_place(f),
        Err(_) => f(),
    }
}

impl SharedCertStore for RedisStore {
    fn load_cert(&self, key: &str) -> Option<SharedCert> {
        let cipher = self.cert_cipher.as_ref().or_else(|| {
            warn!("SharedCertStore.load_cert called without WAF_CERT_STORE_KEY configured");
            None
        })?;
        let ck = cert_key(key);
        let result = blocking(|| -> redis::RedisResult<Option<String>> {
            let mut conn = self.pool.get().map_err(pool_to_redis_err)?;
            redis::cmd("GET").arg(&ck).query::<Option<String>>(&mut *conn)
        });
        let json = match result {
            Ok(Some(j)) => j,
            Ok(None) => return None,
            Err(e) => {
                warn!(error = %e, key = %key, "SharedCertStore.load_cert Redis error");
                return None;
            }
        };
        let blob: StoredBlob = match serde_json::from_str(&json) {
            Ok(b) => b,
            Err(e) => {
                warn!(error = %e, key = %key, "SharedCertStore.load_cert: malformed blob");
                return None;
            }
        };
        let key_pem = match cipher.decrypt_b64(&blob.key_pem_enc) {
            Ok(bytes) => match String::from_utf8(bytes) {
                Ok(s) => s,
                Err(_) => {
                    warn!(key = %key, "SharedCertStore.load_cert: decrypted key not UTF-8");
                    return None;
                }
            },
            Err(_) => {
                warn!(key = %key, "SharedCertStore.load_cert: key decryption failed (wrong WAF_CERT_STORE_KEY?)");
                return None;
            }
        };
        Some(SharedCert { chain_pem: blob.chain_pem, key_pem, not_after_unix: blob.not_after_unix })
    }

    fn store_cert(&self, key: &str, holder: &str, cert: &SharedCert) -> bool {
        let Some(cipher) = self.cert_cipher.as_ref() else {
            warn!("SharedCertStore.store_cert called without WAF_CERT_STORE_KEY configured");
            return false;
        };
        let blob = StoredBlob {
            chain_pem: cert.chain_pem.clone(),
            key_pem_enc: cipher.encrypt_b64(cert.key_pem.as_bytes()),
            not_after_unix: cert.not_after_unix,
        };
        let json = match serde_json::to_string(&blob) {
            Ok(j) => j,
            Err(e) => {
                warn!(error = %e, key = %key, "SharedCertStore.store_cert: serialize failed");
                return false;
            }
        };
        let (lk, ck) = (lock_key(key), cert_key(key));
        let script = Script::new(STORE_LUA);
        let result = blocking(|| -> redis::RedisResult<i64> {
            let mut conn = self.pool.get().map_err(pool_to_redis_err)?;
            script.key(&lk).key(&ck).arg(holder).arg(&json).invoke::<i64>(&mut *conn)
        });
        match result {
            Ok(1) => true,
            Ok(_) => {
                warn!(key = %key, holder = %holder, "SharedCertStore.store_cert: lock not held, blob NOT written");
                false
            }
            Err(e) => {
                warn!(error = %e, key = %key, "SharedCertStore.store_cert Redis error");
                false
            }
        }
    }

    fn try_lock(&self, key: &str, holder: &str, ttl: Duration) -> bool {
        let lk = lock_key(key);
        let ttl_ms = ttl.as_millis().max(1) as u64;
        let result = blocking(|| -> redis::RedisResult<Option<String>> {
            let mut conn = self.pool.get().map_err(pool_to_redis_err)?;
            redis::cmd("SET")
                .arg(&lk)
                .arg(holder)
                .arg("NX")
                .arg("PX")
                .arg(ttl_ms)
                .query::<Option<String>>(&mut *conn)
        });
        match result {
            Ok(Some(_)) => true, // "OK" ⇒ acquired
            Ok(None) => false,   // held by someone else
            Err(e) => {
                // Fail-safe: cannot confirm ownership ⇒ do NOT claim the lock (avoids two leaders).
                warn!(error = %e, key = %key, "SharedCertStore.try_lock Redis error — treating as NOT acquired");
                false
            }
        }
    }

    fn extend_lock(&self, key: &str, holder: &str, ttl: Duration) -> bool {
        let lk = lock_key(key);
        let ttl_ms = ttl.as_millis().max(1) as u64;
        let script = Script::new(EXTEND_LUA);
        let result = blocking(|| -> redis::RedisResult<i64> {
            let mut conn = self.pool.get().map_err(pool_to_redis_err)?;
            script.key(&lk).arg(holder).arg(ttl_ms).invoke::<i64>(&mut *conn)
        });
        matches!(result, Ok(1))
    }

    fn unlock(&self, key: &str, holder: &str) {
        let lk = lock_key(key);
        let script = Script::new(UNLOCK_LUA);
        let result = blocking(|| -> redis::RedisResult<i64> {
            let mut conn = self.pool.get().map_err(pool_to_redis_err)?;
            script.key(&lk).arg(holder).invoke::<i64>(&mut *conn)
        });
        if let Err(e) = result {
            warn!(error = %e, key = %key, "SharedCertStore.unlock Redis error (lock will expire via TTL)");
        }
    }
}

// ── Encryption at rest for the private key ──────────────────────────────────────

/// HKDF context values. Bumping the version string rotates all derived keys (and invalidates old
/// blobs), which is the intended "cache is invalid, re-issue" behaviour.
const HKDF_SALT: &[u8] = b"waf-sharedcertstore-v1";
const HKDF_INFO: &[u8] = b"aes-256-gcm-key";
const AES_256_KEY_LEN: usize = 32;

/// Length hint for `ring::hkdf::Prk::expand` (ring expands into a type that reports its length).
struct HkdfLen(usize);
impl ring::hkdf::KeyType for HkdfLen {
    fn len(&self) -> usize {
        self.0
    }
}

/// AES-256-GCM authenticated encryption for the stored private key. The key is derived from the
/// operator secret via HKDF-SHA256; a fresh random 96-bit nonce is generated per encryption and
/// prepended to the ciphertext. Storing the derived key (not the passphrase) keeps the passphrase
/// out of memory after construction.
pub struct CertCipher {
    key: LessSafeKey,
    rng: SystemRandom,
}

/// Decryption failed (wrong key, or tampered / truncated ciphertext).
#[derive(Debug)]
pub struct DecryptError;

impl std::fmt::Display for DecryptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "cert key decryption failed")
    }
}
impl std::error::Error for DecryptError {}

impl CertCipher {
    /// Derive the AES-256-GCM key from an operator secret (the `WAF_CERT_STORE_KEY` env value).
    pub fn from_secret(secret: &str) -> Self {
        let salt = ring::hkdf::Salt::new(ring::hkdf::HKDF_SHA256, HKDF_SALT);
        let prk = salt.extract(secret.as_bytes());
        let okm = prk
            .expand(&[HKDF_INFO], HkdfLen(AES_256_KEY_LEN))
            .expect("HKDF expand to a fixed 32-byte length cannot fail");
        let mut key_bytes = [0u8; AES_256_KEY_LEN];
        okm.fill(&mut key_bytes).expect("HKDF fill of 32 bytes cannot fail");
        let unbound = UnboundKey::new(&AES_256_GCM, &key_bytes)
            .expect("AES-256-GCM key from 32 bytes cannot fail");
        Self { key: LessSafeKey::new(unbound), rng: SystemRandom::new() }
    }

    /// Encrypt `plaintext` → `base64(nonce || ciphertext || tag)`. A fresh random nonce per call
    /// (never reused) is the load-bearing safety property for GCM.
    fn encrypt_b64(&self, plaintext: &[u8]) -> String {
        let mut nonce_bytes = [0u8; NONCE_LEN];
        self.rng.fill(&mut nonce_bytes).expect("system RNG failed");
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);
        let mut in_out = plaintext.to_vec();
        self.key
            .seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out)
            .expect("AES-GCM seal cannot fail");
        let mut blob = Vec::with_capacity(NONCE_LEN + in_out.len());
        blob.extend_from_slice(&nonce_bytes);
        blob.extend_from_slice(&in_out);
        base64::engine::general_purpose::STANDARD.encode(blob)
    }

    /// Inverse of [`Self::encrypt_b64`]. Any error (bad base64, wrong key, tamper, truncation)
    /// collapses to [`DecryptError`] — the caller treats a bad blob as "no cert".
    fn decrypt_b64(&self, b64: &str) -> Result<Vec<u8>, DecryptError> {
        let blob = base64::engine::general_purpose::STANDARD
            .decode(b64)
            .map_err(|_| DecryptError)?;
        // At least a nonce + a GCM tag (16 bytes) must be present.
        if blob.len() < NONCE_LEN + AES_256_GCM.tag_len() {
            return Err(DecryptError);
        }
        let (nonce_bytes, ct) = blob.split_at(NONCE_LEN);
        let nonce = Nonce::try_assume_unique_for_key(nonce_bytes).map_err(|_| DecryptError)?;
        let mut in_out = ct.to_vec();
        let plaintext = self
            .key
            .open_in_place(nonce, Aad::empty(), &mut in_out)
            .map_err(|_| DecryptError)?;
        Ok(plaintext.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_then_decrypt_round_trips() {
        let c = CertCipher::from_secret("correct horse battery staple");
        let pt = b"-----BEGIN PRIVATE KEY-----\nMIIabc...\n-----END PRIVATE KEY-----\n";
        let blob = c.encrypt_b64(pt);
        assert_eq!(c.decrypt_b64(&blob).unwrap(), pt);
    }

    #[test]
    fn each_encryption_uses_a_fresh_nonce() {
        // Same plaintext + same key MUST yield different ciphertexts (random nonce), else a
        // nonce is being reused — the catastrophic GCM failure mode.
        let c = CertCipher::from_secret("s3cret");
        let pt = b"same input every time";
        assert_ne!(c.encrypt_b64(pt), c.encrypt_b64(pt), "nonce reuse detected");
    }

    #[test]
    fn wrong_secret_fails_to_decrypt() {
        let a = CertCipher::from_secret("secret-A");
        let b = CertCipher::from_secret("secret-B");
        let blob = a.encrypt_b64(b"top secret key material");
        assert!(b.decrypt_b64(&blob).is_err(), "a different secret must not decrypt");
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let c = CertCipher::from_secret("s3cret");
        let blob = c.encrypt_b64(b"authentic");
        let mut raw = base64::engine::general_purpose::STANDARD.decode(&blob).unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 0xff; // flip a byte in the tag → auth must fail
        let tampered = base64::engine::general_purpose::STANDARD.encode(raw);
        assert!(c.decrypt_b64(&tampered).is_err(), "GCM must reject tampering");
    }

    #[test]
    fn truncated_blob_is_rejected() {
        let c = CertCipher::from_secret("s3cret");
        assert!(c.decrypt_b64("").is_err());
        assert!(c.decrypt_b64("AAAA").is_err()); // shorter than nonce+tag
    }

    #[test]
    fn cert_and_lock_keys_are_namespaced() {
        assert_eq!(cert_key("abc"), "cert:abc");
        assert_eq!(lock_key("abc"), "issuance_lock:abc");
    }
}
