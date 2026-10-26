// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

//! Control-plane error type. One variant per failure surface (config vs database vs (de)serialize),
//! so a caller/operator can tell a bad config from a dead database.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    /// Invalid or missing configuration (bad TOML, missing required field/secret).
    #[error("control-plane config: {0}")]
    Config(String),
    /// A database query/connection error.
    #[error("control-plane database: {0}")]
    Db(#[from] sqlx::Error),
    /// A schema migration failed to apply.
    #[error("control-plane migrate: {0}")]
    Migrate(#[from] sqlx::migrate::MigrateError),
    /// (De)serialization of the JSONB contributions payload failed.
    #[error("control-plane json: {0}")]
    Json(#[from] serde_json::Error),
    /// Binding the API listener / serving failed.
    #[error("control-plane io: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
