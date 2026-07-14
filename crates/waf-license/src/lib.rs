// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: BUSL-1.1

//! Demo/trial license gate for the Light WAF **enterprise binaries**.
//!
//! A demo build (compiled with each binary's `demo-license` feature) ships with **every enterprise
//! feature unlocked** but refuses to run past a signed expiry date, logging `licenza demo scaduta`.
//!
//! # Trust model
//! The license is a single JSON document signed with **Ed25519** by the vendor's private key. Only
//! the matching public key is compiled into the binary ([`LICENSE_PUBKEY_HEX`]); the private seed
//! lives with the vendor and is used offline by the `waf-license-sign` tool. A prospect therefore
//! cannot change the expiry (that breaks the signature) nor mint their own license (they lack the
//! seed). This is a **client-side** gate: someone who controls the machine, its clock and the
//! binary can still bypass it — the intent is to stop *casual* continued use of a demo, not a
//! determined attacker. No obfuscation, no phone-home.
//!
//! # Shape
//! ```json
//! {
//!   "license_version": 1,
//!   "edition": "demo",
//!   "issued_to": "Acme Corp — POC",
//!   "issued_at": "2026-07-13T00:00:00Z",
//!   "expires_at": "2026-08-13T00:00:00Z",
//!   "features": ["*"],
//!   "signature": "<hex Ed25519 over SHA-256 of the canonical body without `signature`>"
//! }
//! ```
//!
//! The signature covers the SHA-256 of the JSON body with the `signature` field removed and object
//! keys sorted (serde_json's `Map` is a `BTreeMap`), so verification is independent of field order
//! and survives a JSON round-trip — the same canonical-body discipline as the compliance bundle.

use std::path::{Path, PathBuf};
use std::time::Duration;

use ring::signature::{Ed25519KeyPair, UnparsedPublicKey, ED25519};
use serde::{Deserialize, Serialize};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

/// The Ed25519 **public key** (64 hex chars) a valid license must be signed with — the compiled-in
/// trust anchor. The matching private seed is held ONLY by the vendor.
///
/// Set it one of two ways before cutting a demo build (both from `waf-license-keygen`):
/// - build with the env var `WAF_LICENSE_PUBKEY=<hex>` (baked in at compile time), **or**
/// - edit the fallback literal below.
///
/// The default all-zero value verifies nothing (fail-closed by construction), so a demo build that
/// forgets to set a real key simply never accepts any license.
pub const LICENSE_PUBKEY_HEX: &str = match option_env!("WAF_LICENSE_PUBKEY") {
    Some(k) => k,
    None => "0000000000000000000000000000000000000000000000000000000000000000",
};

/// Default license file path (override with `WAF_LICENSE_FILE`).
pub const DEFAULT_LICENSE_FILE: &str = "license.json";
/// Default heartbeat state path (override with `WAF_LICENSE_STATE`).
pub const DEFAULT_STATE_FILE: &str = ".license.state";

/// Backward clock skew tolerated before the heartbeat is treated as a rollback (5 minutes).
const ROLLBACK_SKEW: Duration = Duration::from_secs(300);

/// A parsed demo license. Signature-verified before the fields are trusted (see [`verify`]).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct License {
    /// Schema version of the license document (currently `1`).
    pub license_version: u32,
    /// Edition tag, e.g. `"demo"`.
    pub edition: String,
    /// Human label for who the license was issued to (shown in logs).
    pub issued_to: String,
    /// When the license was issued.
    #[serde(with = "time::serde::rfc3339")]
    pub issued_at: OffsetDateTime,
    /// When the license stops being valid.
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
    /// Enabled features. `["*"]` = everything (v1 only enforces expiry; this is informational).
    #[serde(default)]
    pub features: Vec<String>,
    /// Hex Ed25519 signature over the canonical body.
    pub signature: String,
}

/// Why a license failed to load or validate.
#[derive(Debug, thiserror::Error)]
pub enum LicenseError {
    /// The license file is missing or unreadable.
    #[error("license file not found or unreadable: {0}")]
    NotFound(String),
    /// The JSON is malformed or fields are missing/wrong-typed.
    #[error("license is malformed: {0}")]
    Malformed(String),
    /// The signature does not verify against the compiled-in trust anchor.
    #[error("license signature is not valid")]
    BadSignature,
    /// The license is past its expiry.
    #[error("license expired at {0}")]
    Expired(OffsetDateTime),
    /// The system clock appears to have moved backwards (heartbeat rollback).
    #[error("system clock moved backwards — license state tampered")]
    ClockRollback,
}

/// The time-status of a signature-valid license.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LicenseStatus {
    /// Still within its validity window.
    Valid {
        /// When it will expire.
        expires_at: OffsetDateTime,
    },
    /// Past expiry.
    Expired {
        /// When it expired.
        expires_at: OffsetDateTime,
    },
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(ring::digest::digest(&ring::digest::SHA256, bytes).as_ref())
}

fn verify_signature(pubkey_hex: &str, msg: &str, sig_hex: &str) -> bool {
    let (Ok(pk), Ok(sig)) = (hex::decode(pubkey_hex), hex::decode(sig_hex)) else {
        return false;
    };
    UnparsedPublicKey::new(&ED25519, &pk)
        .verify(msg.as_bytes(), &sig)
        .is_ok()
}

/// SHA-256 hex of the canonical body: the JSON object with the `signature` field removed and keys
/// sorted (serde_json `Map` = `BTreeMap`). Both signing and verification hash the same bytes.
fn body_hash(obj: &serde_json::Value) -> String {
    let mut body = obj.clone();
    if let Some(map) = body.as_object_mut() {
        map.remove("signature");
    }
    sha256_hex(&serde_json::to_vec(&body).unwrap_or_default())
}

/// Verify raw license bytes against a **given** public key, returning the parsed license if the
/// signature checks out. Does NOT check expiry — see [`evaluate`]. Used by tests; production code
/// uses [`verify`] (compiled-in anchor).
pub fn verify_with_key(bytes: &[u8], pubkey_hex: &str) -> Result<License, LicenseError> {
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|e| LicenseError::Malformed(e.to_string()))?;
    let sig = value
        .get("signature")
        .and_then(|v| v.as_str())
        .ok_or_else(|| LicenseError::Malformed("missing `signature`".into()))?;
    if !verify_signature(pubkey_hex, &body_hash(&value), sig) {
        return Err(LicenseError::BadSignature);
    }
    serde_json::from_value(value).map_err(|e| LicenseError::Malformed(e.to_string()))
}

/// Verify raw license bytes against the compiled-in trust anchor [`LICENSE_PUBKEY_HEX`].
pub fn verify(bytes: &[u8]) -> Result<License, LicenseError> {
    verify_with_key(bytes, LICENSE_PUBKEY_HEX)
}

/// Classify a signature-valid license by time.
pub fn evaluate(license: &License, now: OffsetDateTime) -> LicenseStatus {
    if now <= license.expires_at {
        LicenseStatus::Valid { expires_at: license.expires_at }
    } else {
        LicenseStatus::Expired { expires_at: license.expires_at }
    }
}

/// Mint a signed license JSON (pretty bytes) from its fields, signing with a 32-byte Ed25519 seed
/// (64 hex chars). Used by the `waf-license-sign` tool and by tests.
pub fn sign_license(
    edition: &str,
    issued_to: &str,
    issued_at: OffsetDateTime,
    expires_at: OffsetDateTime,
    features: Vec<String>,
    seed_hex: &str,
) -> Result<Vec<u8>, LicenseError> {
    let seed = hex::decode(seed_hex.trim())
        .map_err(|_| LicenseError::Malformed("signing seed is not hex".into()))?;
    let key_pair = Ed25519KeyPair::from_seed_unchecked(&seed)
        .map_err(|_| LicenseError::Malformed("signing seed must be 32 bytes (64 hex)".into()))?;
    let fmt = |t: OffsetDateTime| {
        t.format(&Rfc3339)
            .map_err(|e| LicenseError::Malformed(e.to_string()))
    };
    let mut obj = serde_json::json!({
        "license_version": 1,
        "edition": edition,
        "issued_to": issued_to,
        "issued_at": fmt(issued_at)?,
        "expires_at": fmt(expires_at)?,
        "features": features,
    });
    let signature = {
        let hash = body_hash(&obj);
        hex::encode(key_pair.sign(hash.as_bytes()).as_ref())
    };
    obj.as_object_mut()
        .expect("json object")
        .insert("signature".into(), serde_json::Value::String(signature));
    serde_json::to_vec_pretty(&obj).map_err(|e| LicenseError::Malformed(e.to_string()))
}

/// Update the monotonic heartbeat file, failing if `now` is meaningfully before the last-seen
/// timestamp (a naive clock rollback). Best-effort: an attacker with disk access can edit the file.
fn touch_heartbeat(state_path: &Path, now: OffsetDateTime) -> Result<(), LicenseError> {
    let now_us: i128 = now.unix_timestamp_nanos() / 1_000;
    if let Ok(prev) = std::fs::read_to_string(state_path) {
        if let Ok(last) = prev.trim().parse::<i128>() {
            if now_us + (ROLLBACK_SKEW.as_micros() as i128) < last {
                return Err(LicenseError::ClockRollback);
            }
            if last > now_us {
                // Within skew but slightly behind: keep the high-water mark, don't downgrade it.
                return Ok(());
            }
        }
    }
    let _ = std::fs::write(state_path, now_us.to_string());
    Ok(())
}

/// Full check used at boot and by the watchdog: read → verify signature → anti-rollback → expiry.
/// Returns the license only if it is signature-valid AND unexpired.
pub fn check(
    license_path: &Path,
    state_path: &Path,
    now: OffsetDateTime,
) -> Result<License, LicenseError> {
    let bytes = std::fs::read(license_path).map_err(|e| LicenseError::NotFound(e.to_string()))?;
    let license = verify(&bytes)?;
    touch_heartbeat(state_path, now)?;
    match evaluate(&license, now) {
        LicenseStatus::Valid { .. } => Ok(license),
        LicenseStatus::Expired { expires_at } => Err(LicenseError::Expired(expires_at)),
    }
}

/// Resolve the license file path (`WAF_LICENSE_FILE` or [`DEFAULT_LICENSE_FILE`]).
pub fn license_path() -> PathBuf {
    std::env::var_os("WAF_LICENSE_FILE")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_LICENSE_FILE))
}

/// Resolve the heartbeat state path (`WAF_LICENSE_STATE` or [`DEFAULT_STATE_FILE`]).
pub fn state_path() -> PathBuf {
    std::env::var_os("WAF_LICENSE_STATE")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_STATE_FILE))
}

/// Boot gate for a demo binary: verify the license or **terminate the process** (fail-closed).
/// Returns the license on success. Call once, right after loading config.
pub fn enforce_boot() -> License {
    match check(&license_path(), &state_path(), OffsetDateTime::now_utc()) {
        Ok(license) => {
            tracing::info!(
                edition = %license.edition,
                issued_to = %license.issued_to,
                expires_at = %license.expires_at,
                "licenza demo valida"
            );
            license
        }
        Err(LicenseError::Expired(_)) => {
            tracing::error!("licenza demo scaduta");
            std::process::exit(2);
        }
        Err(err) => {
            tracing::error!(error = %err, "licenza demo non valida");
            std::process::exit(2);
        }
    }
}

/// Background watchdog: re-check the license every `interval`; on expiry or tampering, log
/// `licenza demo scaduta` and terminate the process. `spawn` this from the binary's runtime. A
/// month can elapse while the service runs, so the boot gate alone is not enough. Never returns.
pub async fn watchdog(interval: Duration) -> ! {
    loop {
        tokio::time::sleep(interval).await;
        match check(&license_path(), &state_path(), OffsetDateTime::now_utc()) {
            Ok(_) => {}
            Err(LicenseError::Expired(_)) => {
                tracing::error!("licenza demo scaduta");
                std::process::exit(2);
            }
            Err(err) => {
                tracing::error!(error = %err, "licenza demo non valida");
                std::process::exit(2);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::signature::KeyPair;

    // A deterministic test seed (NOT a real signing key).
    const SEED: &str = "0202020202020202020202020202020202020202020202020202020202020202";

    fn pubkey_of(seed_hex: &str) -> String {
        let seed = hex::decode(seed_hex).unwrap();
        let kp = Ed25519KeyPair::from_seed_unchecked(&seed).unwrap();
        hex::encode(kp.public_key().as_ref())
    }

    fn issue(days: i64) -> Vec<u8> {
        let now = OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap();
        let expires = now + time::Duration::days(days);
        sign_license("demo", "Acme — POC", now, expires, vec!["*".into()], SEED).unwrap()
    }

    #[test]
    fn sign_then_verify_roundtrips_fields() {
        let bytes = issue(30);
        let lic = verify_with_key(&bytes, &pubkey_of(SEED)).unwrap();
        assert_eq!(lic.edition, "demo");
        assert_eq!(lic.issued_to, "Acme — POC");
        assert_eq!(lic.features, vec!["*".to_string()]);
        assert_eq!(lic.license_version, 1);
    }

    #[test]
    fn tampered_body_fails_signature() {
        let bytes = issue(30);
        let s = String::from_utf8(bytes).unwrap().replace("Acme — POC", "Evil Corp");
        assert!(matches!(
            verify_with_key(s.as_bytes(), &pubkey_of(SEED)),
            Err(LicenseError::BadSignature)
        ));
    }

    #[test]
    fn tampered_expiry_fails_signature() {
        // Bump the year in expires_at → signature no longer covers it.
        let bytes = issue(30);
        let s = String::from_utf8(bytes).unwrap();
        // 1_800_000_000 + 30d lands in 2027; push it to 2099.
        let s = s.replacen("2027", "2099", 1);
        assert!(matches!(
            verify_with_key(s.as_bytes(), &pubkey_of(SEED)),
            Err(LicenseError::BadSignature)
        ));
    }

    #[test]
    fn wrong_key_fails_signature() {
        let bytes = issue(30);
        let other = "0303030303030303030303030303030303030303030303030303030303030303";
        assert!(matches!(
            verify_with_key(&bytes, &pubkey_of(other)),
            Err(LicenseError::BadSignature)
        ));
    }

    #[test]
    fn missing_signature_is_malformed() {
        let bytes = br#"{"license_version":1,"edition":"demo"}"#;
        assert!(matches!(
            verify_with_key(bytes, &pubkey_of(SEED)),
            Err(LicenseError::Malformed(_))
        ));
    }

    #[test]
    fn evaluate_before_and_after_expiry() {
        let bytes = issue(30);
        let lic = verify_with_key(&bytes, &pubkey_of(SEED)).unwrap();
        let before = lic.expires_at - time::Duration::days(1);
        let after = lic.expires_at + time::Duration::days(1);
        assert!(matches!(evaluate(&lic, before), LicenseStatus::Valid { .. }));
        assert!(matches!(evaluate(&lic, after), LicenseStatus::Expired { .. }));
    }

    #[test]
    fn heartbeat_detects_rollback() {
        let dir = std::env::temp_dir().join(format!("waf-lic-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let state = dir.join("hb.state");
        let now = OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap();
        // First touch records now.
        touch_heartbeat(&state, now).unwrap();
        // A far-future touch advances the high-water mark.
        let future = now + time::Duration::days(10);
        touch_heartbeat(&state, future).unwrap();
        // Coming back to `now` (10 days behind the mark, well past skew) is a rollback.
        assert!(matches!(
            touch_heartbeat(&state, now),
            Err(LicenseError::ClockRollback)
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
