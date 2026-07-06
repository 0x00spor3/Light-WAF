// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: BUSL-1.1

//! Opaque secret generation (256 bits from the system CSPRNG, hex-encoded) for session ids and API
//! service tokens, plus the token hashing used to store service tokens.

use ring::rand::{SecureRandom, SystemRandom};

fn random_hex_256() -> String {
    let rng = SystemRandom::new();
    let mut bytes = [0u8; 32];
    rng.fill(&mut bytes).expect("system CSPRNG failed");
    hex::encode(bytes)
}

/// A fresh, unguessable session id (32 random bytes → 64 hex chars).
pub fn generate_session_id() -> String {
    random_hex_256()
}

/// A fresh, unguessable API service-token secret (shown once at creation; only its hash is stored).
pub fn generate_token() -> String {
    random_hex_256()
}

/// The stored form of a service token — SHA-256 of the presented secret, hex-encoded. Deterministic
/// (no salt) so a presented bearer can be looked up by hash on every request.
pub fn hash_token(token: &str) -> String {
    hex::encode(ring::digest::digest(&ring::digest::SHA256, token.as_bytes()).as_ref())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_unique_and_sized() {
        let a = generate_session_id();
        let b = generate_session_id();
        assert_eq!(a.len(), 64);
        assert_ne!(a, b);
    }

    #[test]
    fn token_hash_is_deterministic_and_distinct() {
        let t = generate_token();
        assert_eq!(t.len(), 64);
        assert_eq!(hash_token(&t), hash_token(&t), "same token → same hash");
        assert_ne!(hash_token("a"), hash_token("b"));
        assert_eq!(hash_token("a").len(), 64); // SHA-256 hex
    }
}
