// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

//! Error type for the governance crate.

/// Governance errors.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Database / query failure.
    #[error("database error: {0}")]
    Db(#[from] sqlx::Error),
    /// Password hashing/verification failure.
    #[error("password error: {0}")]
    Password(String),
    /// Crypto / key material failure (audit signing).
    #[error("crypto error: {0}")]
    Crypto(String),
    /// Invalid configuration (e.g. a malformed audit key).
    #[error("config error: {0}")]
    Config(String),
    /// A uniqueness constraint was violated (e.g. duplicate username).
    #[error("already exists: {0}")]
    Conflict(String),
}

/// Convenience alias.
pub type Result<T> = std::result::Result<T, Error>;
