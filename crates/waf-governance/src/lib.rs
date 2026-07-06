// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: BUSL-1.1

//! Governance for the Light WAF control plane (§8): **RBAC**, **local authentication** and a
//! **tamper-evident signed audit log**. This is a control-plane **library** — it never touches the
//! datapath and does not depend on `waf-core` (zero-core, zero-datapath). It operates on the control
//! plane's Postgres (`&PgPool`) and owns its own schema ([`store::apply_schema`]).
//!
//! v1 scope: local user accounts (argon2id) + server-side sessions + the three RBAC roles
//! ([`rbac::Role`]) + the signed audit chain ([`audit`]). SSO/OIDC, a governance UI, and rule
//! management (the §7 write path) build on top of this.
//!
//! ```
//! use waf_governance::rbac::{Role, Permission};
//! assert!(Role::Admin.allows(Permission::ManageUsers));
//! assert!(!Role::Viewer.allows(Permission::ManageUsers));
//! ```

pub mod audit;
pub mod error;
pub mod model;
pub mod password;
pub mod rbac;
pub mod store;
pub mod throttle;
pub mod token;

pub use error::{Error, Result};
pub use rbac::{Permission, Role};
pub use throttle::LoginThrottle;
pub use token::{generate_session_id, generate_token, hash_token};
