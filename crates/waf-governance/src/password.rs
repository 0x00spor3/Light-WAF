// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

//! Password hashing (argon2id). Hashes are PHC strings (algorithm + params + random salt embedded),
//! so verification needs only the stored string.

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use rand_core::OsRng;

use crate::error::{Error, Result};

/// Hash a password with argon2id (default params) and a fresh random salt. Returns a PHC string.
pub fn hash_password(password: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| Error::Password(e.to_string()))
}

/// Verify a password against a stored PHC hash. `Ok(false)` = wrong password; `Err` = a malformed
/// stored hash (never treat that as a match).
pub fn verify_password(password: &str, phc_hash: &str) -> Result<bool> {
    let parsed = PasswordHash::new(phc_hash).map_err(|e| Error::Password(e.to_string()))?;
    match Argon2::default().verify_password(password.as_bytes(), &parsed) {
        Ok(()) => Ok(true),
        Err(argon2::password_hash::Error::Password) => Ok(false),
        Err(e) => Err(Error::Password(e.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_then_verify() {
        let h = hash_password("correct horse battery staple").unwrap();
        assert!(verify_password("correct horse battery staple", &h).unwrap());
        assert!(!verify_password("wrong password", &h).unwrap());
    }

    #[test]
    fn same_password_hashes_differ() {
        // Random salt → two hashes of the same password must not be equal.
        let a = hash_password("hunter2").unwrap();
        let b = hash_password("hunter2").unwrap();
        assert_ne!(a, b);
        assert!(verify_password("hunter2", &a).unwrap());
        assert!(verify_password("hunter2", &b).unwrap());
    }

    #[test]
    fn malformed_hash_is_error_not_match() {
        assert!(verify_password("whatever", "not-a-phc-string").is_err());
    }
}
