// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: BUSL-1.1

//! Role-based access control. Three fixed v1 roles and a pure permission matrix; the control plane
//! maps each protected route to a required [`Permission`] and calls [`Role::allows`].

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// The fixed RBAC roles (v1). Ordering is by privilege (Viewer < Operator < Admin).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// Read-only access to the observability API.
    Viewer,
    /// Viewer + operational write actions (alert ack, rule actions — reserved for the write path).
    Operator,
    /// Everything: user management, audit access, governance configuration.
    Admin,
}

impl Role {
    /// The role's wire/string form (as stored in the `role` column).
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Viewer => "viewer",
            Role::Operator => "operator",
            Role::Admin => "admin",
        }
    }

    /// Whether this role is granted `perm`.
    pub fn allows(self, perm: Permission) -> bool {
        match perm {
            // Everyone who can log in can read the observability API.
            Permission::ReadObservability => true,
            // Operator-and-up: operational write actions (wired as the write path lands).
            Permission::ManageAlerts | Permission::ManageRules => self >= Role::Operator,
            // Admin-only: user management, service tokens, audit access, governance config.
            Permission::ManageUsers
            | Permission::ManageTokens
            | Permission::ViewAudit
            | Permission::ManageConfig => self == Role::Admin,
        }
    }
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Role {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        match s {
            "viewer" => Ok(Role::Viewer),
            "operator" => Ok(Role::Operator),
            "admin" => Ok(Role::Admin),
            other => Err(Error::Config(format!("unknown role {other:?}"))),
        }
    }
}

/// Map a set of IdP claim values (e.g. `groups`) to a role using a `(claim_value → Role)` table,
/// returning the **highest-privilege** matched role (v2 OIDC). `None` when nothing matches (the
/// caller then applies a configured default, or denies the login).
pub fn map_claims_to_role(claim_values: &[String], role_map: &[(String, Role)]) -> Option<Role> {
    claim_values
        .iter()
        .filter_map(|v| role_map.iter().find(|(k, _)| k == v).map(|(_, r)| *r))
        .max()
}

/// A capability a route can require. The route→permission mapping lives in the control plane; the
/// role→permission grant lives here ([`Role::allows`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Permission {
    /// Read the observability API (cluster/volumes/latency/events/alerts).
    ReadObservability,
    /// Acknowledge / manage alerts (reserved; wired when alert actions land).
    ManageAlerts,
    /// Create/disable users and assign roles.
    ManageUsers,
    /// Create/revoke named API service tokens.
    ManageTokens,
    /// View the audit log.
    ViewAudit,
    /// Change governance configuration.
    ManageConfig,
    /// Edit/version rules and push them to nodes (reserved for the §7 write path, v3).
    ManageRules,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matrix_viewer() {
        assert!(Role::Viewer.allows(Permission::ReadObservability));
        assert!(!Role::Viewer.allows(Permission::ManageAlerts));
        assert!(!Role::Viewer.allows(Permission::ManageUsers));
        assert!(!Role::Viewer.allows(Permission::ViewAudit));
        assert!(!Role::Viewer.allows(Permission::ManageRules));
    }

    #[test]
    fn matrix_operator() {
        assert!(Role::Operator.allows(Permission::ReadObservability));
        assert!(Role::Operator.allows(Permission::ManageAlerts));
        assert!(Role::Operator.allows(Permission::ManageRules));
        // Still not an admin.
        assert!(!Role::Operator.allows(Permission::ManageUsers));
        assert!(!Role::Operator.allows(Permission::ManageTokens));
        assert!(!Role::Operator.allows(Permission::ViewAudit));
        assert!(!Role::Operator.allows(Permission::ManageConfig));
    }

    #[test]
    fn matrix_admin() {
        for p in [
            Permission::ReadObservability,
            Permission::ManageAlerts,
            Permission::ManageUsers,
            Permission::ManageTokens,
            Permission::ViewAudit,
            Permission::ManageConfig,
            Permission::ManageRules,
        ] {
            assert!(Role::Admin.allows(p), "admin must be granted {p:?}");
        }
    }

    #[test]
    fn role_string_roundtrip() {
        for r in [Role::Viewer, Role::Operator, Role::Admin] {
            assert_eq!(Role::from_str(r.as_str()).unwrap(), r);
        }
        assert!(Role::from_str("root").is_err());
    }

    #[test]
    fn privilege_ordering() {
        assert!(Role::Admin > Role::Operator);
        assert!(Role::Operator > Role::Viewer);
    }

    #[test]
    fn claim_role_mapping_picks_highest() {
        let map = vec![
            ("waf-admins".to_string(), Role::Admin),
            ("waf-ops".to_string(), Role::Operator),
            ("staff".to_string(), Role::Viewer),
        ];
        // Multiple matches → highest privilege wins.
        let claims = vec!["staff".to_string(), "waf-ops".to_string()];
        assert_eq!(map_claims_to_role(&claims, &map), Some(Role::Operator));
        assert_eq!(map_claims_to_role(&["waf-admins".into(), "staff".into()], &map), Some(Role::Admin));
        // No match → None (caller applies default or denies).
        assert_eq!(map_claims_to_role(&["random".into()], &map), None);
        assert_eq!(map_claims_to_role(&[], &map), None);
    }
}
