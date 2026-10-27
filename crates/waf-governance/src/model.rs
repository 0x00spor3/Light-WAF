// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

//! Governance data model: operator accounts, sessions and audit records.

use serde::Serialize;
use time::OffsetDateTime;

use crate::rbac::Role;

/// An operator account (without the password hash — safe to serialize to the API). `auth_source` is
/// `"local"` (argon2 password) or `"oidc"` (federated, no local password).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct User {
    pub id: i64,
    pub username: String,
    pub role: Role,
    pub disabled: bool,
    pub auth_source: String,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

/// A user plus the stored password hash — internal (login path only), never serialized. `None` for
/// OIDC-federated users (they have no local password).
#[derive(Debug, Clone)]
pub struct UserWithHash {
    pub user: User,
    pub password_hash: Option<String>,
}

/// Service-token metadata (v2) — never carries the secret (only its hash is stored).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ServiceToken {
    pub id: i64,
    pub name: String,
    pub role: Role,
    pub revoked: bool,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

/// A server-side session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    pub id: String,
    pub user_id: i64,
    pub created_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
}

/// A stored audit record. The hash is over `(seq, ts_micros, actor, action, target, details,
/// prev_hash)`; `signature` is Ed25519 over the hash. See [`crate::audit`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuditRecord {
    pub seq: i64,
    #[serde(with = "time::serde::rfc3339")]
    pub ts: OffsetDateTime,
    pub actor: String,
    pub action: String,
    pub target: Option<String>,
    /// The exact canonical JSON string that was hashed (stored as TEXT for byte-exact verification).
    pub details: String,
    pub prev_hash: String,
    pub hash: String,
    pub signature: String,
}

/// A new audit entry to append (the chain fields — seq/ts/hashes/signature — are filled in by
/// [`crate::store::append_audit`]).
#[derive(Debug, Clone)]
pub struct NewAudit {
    pub actor: String,
    pub action: String,
    pub target: Option<String>,
    /// Canonical JSON string for the structured detail (build via [`NewAudit::new`]).
    pub details: String,
}

impl NewAudit {
    /// Build an entry with `details` serialized from any serializable value (compact JSON). The
    /// exact serialized string is what gets hashed and stored, so verification round-trips.
    pub fn new(
        actor: impl Into<String>,
        action: impl Into<String>,
        target: Option<String>,
        details: &impl Serialize,
    ) -> Self {
        let details = serde_json::to_string(details).unwrap_or_else(|_| "{}".to_string());
        Self { actor: actor.into(), action: action.into(), target, details }
    }
}
