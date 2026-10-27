// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

//! Control-plane configuration (`controlplane.toml`). Secrets (database URL, ingest/API token) are
//! read from the environment in preference to the file, so the file can be committed safely.

use serde::{Deserialize, Serialize};
use waf_governance::rbac::Role;

use crate::error::{Error, Result};

/// Env var overriding `[controlplane].database_url` (secrets out of the file).
pub const ENV_DATABASE_URL: &str = "WAF_CP_DATABASE_URL";
/// Env var overriding `[controlplane].api_token`.
pub const ENV_API_TOKEN: &str = "WAF_CP_API_TOKEN";
/// Env var overriding `[controlplane.alerting].webhook_url`.
pub const ENV_ALERT_WEBHOOK: &str = "WAF_CP_ALERT_WEBHOOK";
/// Env var holding the audit-log Ed25519 signing seed (64 hex chars). Required when governance is
/// enabled — it must persist across restarts so the chain stays verifiable under a stable pubkey.
pub const ENV_AUDIT_KEY: &str = "WAF_CP_AUDIT_KEY";
/// Env var holding the bootstrap admin's initial password (used once, if no users exist).
pub const ENV_BOOTSTRAP_ADMIN_PASSWORD: &str = "WAF_CP_BOOTSTRAP_ADMIN_PASSWORD";
/// Env var holding the OIDC client secret (preferred over `[controlplane.governance.oidc].client_secret`).
pub const ENV_OIDC_CLIENT_SECRET: &str = "WAF_CP_OIDC_CLIENT_SECRET";
/// Prefix for the per-SIEM-destination auth header env var: `WAF_CP_SIEM_AUTH_<NAME>` (name
/// upper-cased, non-alphanumerics → `_`) overrides `[[controlplane.siem.destinations]].auth_header`.
pub const ENV_SIEM_AUTH_PREFIX: &str = "WAF_CP_SIEM_AUTH_";

fn default_listen() -> String {
    "127.0.0.1:9600".to_string()
}
fn default_retention_days() -> u32 {
    30
}
fn default_capture_retention_hours() -> u32 {
    168 // 7 days — shorter than telemetry retention; captures hold raw request material.
}
fn default_scrape_interval() -> u64 {
    15
}

/// A WAF node whose Prometheus `/metrics` the scraper polls (Phase 2). `name` labels the node in
/// stored rollups and ingested events (node identity is supplied here / by the shipper, never by
/// the core — zero-core).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct NodeConfig {
    pub name: String,
    /// Full URL of the node's metrics endpoint, e.g. `http://10.0.0.1:9090/metrics`.
    pub metrics_url: String,
}

/// How an alert rule groups matching events before comparing to the threshold (v2). `None` counts
/// all matches together; `ClientIp`/`RuleId` count per distinct value (e.g. per-IP burst detection).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GroupBy {
    #[default]
    None,
    ClientIp,
    RuleId,
}

impl GroupBy {
    /// The `decision_events` column to `GROUP BY`, or `None` for a single ungrouped count. The
    /// value is a fixed literal from this enum — never user input — so it is safe to inline in SQL.
    pub fn column(self) -> Option<&'static str> {
        match self {
            GroupBy::None => None,
            GroupBy::ClientIp => Some("client_ip"),
            GroupBy::RuleId => Some("rule_id"),
        }
    }
}

fn default_severity() -> String {
    "warning".to_string()
}
fn default_cooldown() -> u64 {
    300
}
fn default_eval_interval() -> u64 {
    30
}

/// One alert rule (v2): fire when the count of denied `decision_events` matching the optional
/// filters, within `window_seconds`, reaches `threshold` — per group when `group_by` is set.
/// `Serialize` so the configured rules are exposable via `GET /api/alerts/rules`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertRule {
    /// Unique rule name (identity in the stored alert + dedup key).
    pub name: String,
    /// Optional filters (all ANDed; `None` matches everything).
    #[serde(default)]
    pub decision: Option<String>,
    #[serde(default)]
    pub rule_id: Option<String>,
    #[serde(default)]
    pub client_ip: Option<String>,
    /// Group matches before comparing to `threshold`.
    #[serde(default)]
    pub group_by: GroupBy,
    /// Look-back window (seconds).
    pub window_seconds: u64,
    /// Fire when the (per-group) count reaches this.
    pub threshold: i64,
    /// Severity label carried on the fired alert.
    #[serde(default = "default_severity")]
    pub severity: String,
    /// Do not re-fire the same (rule, group) within this many seconds.
    #[serde(default = "default_cooldown")]
    pub cooldown_seconds: u64,
}

/// `[controlplane.alerting]` — the evaluator + delivery settings. Default OFF.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct AlertingConfig {
    pub enabled: bool,
    /// Seconds between evaluation cycles.
    pub eval_interval_seconds: u64,
    /// Generic webhook to POST fired alerts to (JSON). Prefer the `WAF_CP_ALERT_WEBHOOK` env var.
    pub webhook_url: Option<String>,
}

impl Default for AlertingConfig {
    fn default() -> Self {
        Self { enabled: false, eval_interval_seconds: default_eval_interval(), webhook_url: None }
    }
}

/// One `claim value → role` mapping entry for OIDC (`[[controlplane.governance.oidc.role_map]]`).
#[derive(Debug, Clone, Deserialize)]
pub struct RoleMapEntry {
    /// The value of the configured `role_claim` (e.g. an IdP group name).
    pub claim: String,
    /// The role granted when the token carries this claim value.
    pub role: Role,
}

fn default_oidc_scopes() -> Vec<String> {
    vec!["openid".to_string(), "email".to_string(), "profile".to_string()]
}
fn default_role_claim() -> String {
    "groups".to_string()
}

/// `[controlplane.governance.oidc]` — SSO via OpenID Connect (§8 v2). Absent = OIDC disabled.
#[derive(Debug, Clone, Deserialize)]
pub struct OidcConfig {
    /// The IdP issuer URL (discovery = `<issuer>/.well-known/openid-configuration`).
    pub issuer_url: String,
    pub client_id: String,
    /// Client secret — prefer the `WAF_CP_OIDC_CLIENT_SECRET` env var over the file.
    #[serde(default)]
    pub client_secret: Option<String>,
    /// This control plane's callback URL (must be registered at the IdP), e.g.
    /// `https://cp.example/api/auth/oidc/callback`.
    pub redirect_url: String,
    #[serde(default = "default_oidc_scopes")]
    pub scopes: Vec<String>,
    /// The id_token claim to read roles from (default `groups`).
    #[serde(default = "default_role_claim")]
    pub role_claim: String,
    /// `claim value → role` mappings; the highest-privilege match wins.
    #[serde(default)]
    pub role_map: Vec<RoleMapEntry>,
    /// Role for an authenticated user that matched no mapping. `None` → deny such logins.
    #[serde(default)]
    pub default_role: Option<Role>,
}

/// A SIEM event stream (§9). The cursor for each is keyed by `(destination, this)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SiemStream {
    /// Denied WAF verdicts (`decision_events`, cursor = `id`).
    Decisions,
    /// Signed governance audit actions (`gov_audit_log`, cursor = `seq`).
    Audit,
    /// Fired alerts (`alerts`, cursor = `id`).
    Alerts,
}

impl SiemStream {
    /// The stable string form (stored in `siem_cursors.stream`).
    pub fn as_str(self) -> &'static str {
        match self {
            SiemStream::Decisions => "decisions",
            SiemStream::Audit => "audit",
            SiemStream::Alerts => "alerts",
        }
    }
}

/// The wire format a destination expects (§9). v1 ships only ECS-like NDJSON; CEF/LEEF/syslog and
/// vendor adapters are follow-on variants over the SAME normalized event (they never touch the forwarder).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SiemFormat {
    /// Versioned, ECS-like JSON, one event per line (`application/x-ndjson`).
    #[default]
    Ecs,
}

fn default_siem_streams() -> Vec<SiemStream> {
    vec![SiemStream::Decisions, SiemStream::Audit, SiemStream::Alerts]
}

/// One SIEM sink (`[[controlplane.siem.destinations]]`). The cursor per stream is tracked separately,
/// so several destinations each export at their own pace.
#[derive(Debug, Clone, Deserialize)]
pub struct SiemDestination {
    /// Unique destination name (used as the cursor key + the auth env var suffix).
    pub name: String,
    /// The HTTP endpoint that ingests events (e.g. a Splunk HEC / Elastic / collector URL).
    pub endpoint: String,
    /// Full `Authorization` (or vendor) header VALUE, e.g. `Splunk <token>`. Prefer the
    /// `WAF_CP_SIEM_AUTH_<NAME>` env var over the file.
    #[serde(default)]
    pub auth_header: Option<String>,
    #[serde(default)]
    pub format: SiemFormat,
    /// Which streams to export to this destination.
    #[serde(default = "default_siem_streams")]
    pub streams: Vec<SiemStream>,
}

fn default_flush_interval() -> u64 {
    10
}
fn default_batch_size() -> i64 {
    500
}

/// `[controlplane.siem]` — the SIEM export forwarder (§9). Default OFF. The forwarder polls new stored
/// events and PUSHes batches (NDJSON) to each destination; the WAF is unaware (zero-datapath).
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct SiemConfig {
    pub enabled: bool,
    /// Seconds between flush cycles (temporal batching — not event-per-event).
    pub flush_interval_seconds: u64,
    /// Max events per (destination, stream) batch.
    pub batch_size: i64,
    pub destinations: Vec<SiemDestination>,
}

impl Default for SiemConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            flush_interval_seconds: default_flush_interval(),
            batch_size: default_batch_size(),
            destinations: Vec::new(),
        }
    }
}

/// Normalize a destination name into an env-var-safe suffix: upper-case, non-alphanumerics → `_`.
fn env_key(name: &str) -> String {
    name.chars()
        .map(|c| if c.is_ascii_alphanumeric() { c.to_ascii_uppercase() } else { '_' })
        .collect()
}

/// `[controlplane.governance]` — RBAC + local auth + signed audit (§8). Default OFF (backward-compat:
/// with governance off the control plane keeps the single static bearer token and no sessions).
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct GovernanceConfig {
    /// Enable governance (user accounts, sessions, RBAC, signed audit log).
    pub enabled: bool,
    /// Session lifetime (hours).
    pub session_ttl_hours: u64,
    /// Set the `Secure` attribute on the session cookie (leave true in prod; false for local http dev).
    pub cookie_secure: bool,
    /// If set and there are zero users at boot, create this admin (password from
    /// `WAF_CP_BOOTSTRAP_ADMIN_PASSWORD`) so the deployment is not locked out.
    pub bootstrap_admin: Option<String>,
    /// Login brute-force throttle: this many failed logins for a username within
    /// `login_window_seconds` locks it out for `login_lockout_seconds`.
    pub login_max_failures: u32,
    pub login_window_seconds: u64,
    pub login_lockout_seconds: u64,
    /// SSO via OpenID Connect (§8 v2). Absent = OIDC disabled (local auth only).
    #[serde(default)]
    pub oidc: Option<OidcConfig>,
}

impl Default for GovernanceConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            session_ttl_hours: 12,
            cookie_secure: true,
            bootstrap_admin: None,
            login_max_failures: 5,
            login_window_seconds: 60,
            login_lockout_seconds: 300,
            oidc: None,
        }
    }
}

/// `controlplane.toml` → `[controlplane]`.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ControlPlaneConfig {
    /// HTTP listen address for the read/ingest API (served in Phase 3).
    pub listen: String,
    /// Postgres connection string. Prefer the `WAF_CP_DATABASE_URL` env var.
    pub database_url: Option<String>,
    /// Bearer token required on the ingest + read API. Prefer the `WAF_CP_API_TOKEN` env var.
    /// v1 auth is a single static token; RBAC/SSO is §8 (`waf-governance`).
    pub api_token: Option<String>,
    /// WAF nodes to scrape for `/metrics` (Phase 2).
    pub nodes: Vec<NodeConfig>,
    /// Delete telemetry older than this many days (`0` = keep forever).
    pub retention_days: u32,
    /// Seconds between `/metrics` scrapes (Phase 2).
    pub scrape_interval_seconds: u64,
    /// Alerting evaluator + delivery (v2). Default OFF.
    pub alerting: AlertingConfig,
    /// Alert rules (v2). Evaluated only when `alerting.enabled`.
    pub alerts: Vec<AlertRule>,
    /// Serve the built web UI (SPA) from this directory — a **development override**. Production
    /// uses the embedded single-binary UI (UI-3, `embed-ui` feature); leave unset there.
    pub ui_dir: Option<String>,
    /// Governance: RBAC + local auth + signed audit (§8). Default OFF.
    pub governance: GovernanceConfig,
    /// SIEM export forwarder (§9). Default OFF.
    pub siem: SiemConfig,
    /// API attack-surface inventory (§4-B pt3 discovery). Optional spec to classify against.
    pub api_inventory: ApiInventoryConfig,
    /// Request-capture storage (retention of the full denied requests shipped by nodes).
    pub captures: CaptureStoreConfig,
}

/// `[controlplane.captures]` — retention of the full denied requests (`request_captures`) shipped by
/// nodes running the request-capture feature. Independent of and typically SHORTER than
/// `retention_days`: captures carry raw request material (bodies/headers), so they age out fast.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct CaptureStoreConfig {
    /// Hard-delete captures older than this many hours (`0` = keep forever). Default 168 (7 days).
    pub retention_hours: u32,
}

impl Default for CaptureStoreConfig {
    fn default() -> Self {
        Self { retention_hours: default_capture_retention_hours() }
    }
}

/// `[controlplane.api_inventory]` — builds an API attack-surface inventory from the persisted
/// enforcement decisions (`decision_events` are denied requests only). When `spec_path` points at
/// the app's OpenAPI **JSON** spec, observed endpoints are classified `documented` (a declared
/// operation under attack / with contract violations) vs `shadow` (an undeclared endpoint being hit).
/// Unset ⇒ the inventory still lists observed endpoints, but unclassified.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct ApiInventoryConfig {
    /// The app's OpenAPI spec (JSON) to classify observed endpoints against (optional).
    pub spec_path: Option<String>,
}

impl Default for ControlPlaneConfig {
    fn default() -> Self {
        Self {
            listen: default_listen(),
            database_url: None,
            api_token: None,
            nodes: Vec::new(),
            retention_days: default_retention_days(),
            scrape_interval_seconds: default_scrape_interval(),
            alerting: AlertingConfig::default(),
            alerts: Vec::new(),
            ui_dir: None,
            governance: GovernanceConfig::default(),
            siem: SiemConfig::default(),
            api_inventory: ApiInventoryConfig::default(),
            captures: CaptureStoreConfig::default(),
        }
    }
}

/// The `[controlplane]` table wrapper, so the file has a named section like the WAF config.
#[derive(Debug, Clone, Deserialize)]
struct File {
    controlplane: ControlPlaneConfig,
}

impl ControlPlaneConfig {
    /// Parse from a TOML string — PURE (no environment reads), so it is deterministic in tests.
    /// Environment overrides for secrets are applied by [`Self::load`], the production path.
    pub fn from_toml_str(text: &str) -> Result<Self> {
        let file: File = toml::from_str(text).map_err(|e| Error::Config(e.to_string()))?;
        Ok(file.controlplane)
    }

    /// Read `path`, parse, then apply environment overrides for the secrets (env wins over file).
    pub fn load(path: &str) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| Error::Config(format!("cannot read {path}: {e}")))?;
        Ok(Self::from_toml_str(&text)?.with_env_overrides())
    }

    /// Env wins over the file for the two secrets (never logged).
    fn with_env_overrides(mut self) -> Self {
        if let Ok(v) = std::env::var(ENV_DATABASE_URL) {
            if !v.is_empty() {
                self.database_url = Some(v);
            }
        }
        if let Ok(v) = std::env::var(ENV_API_TOKEN) {
            if !v.is_empty() {
                self.api_token = Some(v);
            }
        }
        if let Ok(v) = std::env::var(ENV_ALERT_WEBHOOK) {
            if !v.is_empty() {
                self.alerting.webhook_url = Some(v);
            }
        }
        if let Ok(v) = std::env::var(ENV_OIDC_CLIENT_SECRET) {
            if !v.is_empty() {
                if let Some(oidc) = self.governance.oidc.as_mut() {
                    oidc.client_secret = Some(v);
                }
            }
        }
        // Per-destination SIEM auth header: WAF_CP_SIEM_AUTH_<NAME> (name upper-cased, non-alnum → _).
        for dest in &mut self.siem.destinations {
            let key = format!("{ENV_SIEM_AUTH_PREFIX}{}", env_key(&dest.name));
            if let Ok(v) = std::env::var(&key) {
                if !v.is_empty() {
                    dest.auth_header = Some(v);
                }
            }
        }
        self
    }

    /// The resolved database URL, or a config error naming both sources.
    pub fn require_database_url(&self) -> Result<&str> {
        self.database_url.as_deref().filter(|s| !s.is_empty()).ok_or_else(|| {
            Error::Config(format!(
                "database_url is required (set [controlplane].database_url or the {ENV_DATABASE_URL} env var)"
            ))
        })
    }

    /// Validate the invariants that make a running control plane sane.
    pub fn validate(&self) -> Result<()> {
        self.listen
            .parse::<std::net::SocketAddr>()
            .map_err(|e| Error::Config(format!("invalid listen address {:?}: {e}", self.listen)))?;
        for n in &self.nodes {
            if n.name.trim().is_empty() {
                return Err(Error::Config("a [[controlplane.nodes]] entry has an empty name".into()));
            }
            if !n.metrics_url.starts_with("http://") && !n.metrics_url.starts_with("https://") {
                return Err(Error::Config(format!(
                    "node {:?} metrics_url must be http(s)://…, got {:?}",
                    n.name, n.metrics_url
                )));
            }
        }
        let mut seen = std::collections::HashSet::new();
        for a in &self.alerts {
            if a.name.trim().is_empty() {
                return Err(Error::Config("an [[controlplane.alerts]] rule has an empty name".into()));
            }
            if !seen.insert(&a.name) {
                return Err(Error::Config(format!("duplicate alert rule name {:?}", a.name)));
            }
            if a.window_seconds == 0 {
                return Err(Error::Config(format!("alert rule {:?}: window_seconds must be > 0", a.name)));
            }
            if a.threshold <= 0 {
                return Err(Error::Config(format!("alert rule {:?}: threshold must be > 0", a.name)));
            }
        }
        if self.siem.enabled {
            if self.siem.batch_size <= 0 {
                return Err(Error::Config("siem.batch_size must be > 0".into()));
            }
            if self.siem.flush_interval_seconds == 0 {
                return Err(Error::Config("siem.flush_interval_seconds must be > 0".into()));
            }
            if self.siem.destinations.is_empty() {
                return Err(Error::Config("siem enabled but no [[controlplane.siem.destinations]]".into()));
            }
            let mut seen_dest = std::collections::HashSet::new();
            for d in &self.siem.destinations {
                if d.name.trim().is_empty() {
                    return Err(Error::Config("a [[controlplane.siem.destinations]] has an empty name".into()));
                }
                if !seen_dest.insert(&d.name) {
                    return Err(Error::Config(format!("duplicate siem destination name {:?}", d.name)));
                }
                if !d.endpoint.starts_with("http://") && !d.endpoint.starts_with("https://") {
                    return Err(Error::Config(format!(
                        "siem destination {:?} endpoint must be http(s)://…, got {:?}",
                        d.name, d.endpoint
                    )));
                }
                if d.streams.is_empty() {
                    return Err(Error::Config(format!("siem destination {:?} has no streams", d.name)));
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_and_applies_defaults() {
        let cfg = ControlPlaneConfig::from_toml_str("[controlplane]\n").unwrap();
        assert_eq!(cfg.listen, "127.0.0.1:9600");
        assert_eq!(cfg.retention_days, 30);
        assert_eq!(cfg.scrape_interval_seconds, 15);
        assert!(cfg.nodes.is_empty());
        assert!(cfg.database_url.is_none());
    }

    #[test]
    fn parses_full_config() {
        let toml = r#"
[controlplane]
listen = "0.0.0.0:9600"
database_url = "postgres://u:p@db/waf_cp"
api_token = "s3cret"
retention_days = 90
scrape_interval_seconds = 30

[[controlplane.nodes]]
name = "edge-1"
metrics_url = "http://10.0.0.1:9090/metrics"

[[controlplane.nodes]]
name = "edge-2"
metrics_url = "http://10.0.0.2:9090/metrics"
"#;
        let cfg = ControlPlaneConfig::from_toml_str(toml).unwrap();
        assert_eq!(cfg.listen, "0.0.0.0:9600");
        assert_eq!(cfg.require_database_url().unwrap(), "postgres://u:p@db/waf_cp");
        assert_eq!(cfg.retention_days, 90);
        assert_eq!(cfg.nodes.len(), 2);
        assert_eq!(cfg.nodes[0].name, "edge-1");
        cfg.validate().unwrap();
    }

    #[test]
    fn missing_database_url_is_an_error() {
        let cfg = ControlPlaneConfig::from_toml_str("[controlplane]\n").unwrap();
        assert!(cfg.require_database_url().is_err());
    }

    #[test]
    fn invalid_listen_fails_validation() {
        let cfg = ControlPlaneConfig::from_toml_str("[controlplane]\nlisten = \"not-an-addr\"\n").unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn node_without_scheme_fails_validation() {
        let toml = "[controlplane]\n[[controlplane.nodes]]\nname = \"n\"\nmetrics_url = \"10.0.0.1:9090\"\n";
        let cfg = ControlPlaneConfig::from_toml_str(toml).unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn parses_alert_rules_and_alerting() {
        let toml = r#"
[controlplane]
[controlplane.alerting]
enabled = true
eval_interval_seconds = 10

[[controlplane.alerts]]
name = "sqli-burst-per-ip"
decision = "blocked"
rule_id = "sqli-union-select"
group_by = "client_ip"
window_seconds = 60
threshold = 20
severity = "critical"
cooldown_seconds = 120

[[controlplane.alerts]]
name = "any-block-spike"
window_seconds = 300
threshold = 500
"#;
        let cfg = ControlPlaneConfig::from_toml_str(toml).unwrap();
        assert!(cfg.alerting.enabled);
        assert_eq!(cfg.alerting.eval_interval_seconds, 10);
        assert_eq!(cfg.alerts.len(), 2);
        let a = &cfg.alerts[0];
        assert_eq!(a.name, "sqli-burst-per-ip");
        assert_eq!(a.group_by, GroupBy::ClientIp);
        assert_eq!(a.group_by.column(), Some("client_ip"));
        assert_eq!(a.threshold, 20);
        assert_eq!(a.severity, "critical");
        // Defaults on the second rule.
        let b = &cfg.alerts[1];
        assert_eq!(b.group_by, GroupBy::None);
        assert_eq!(b.group_by.column(), None);
        assert_eq!(b.severity, "warning");
        assert_eq!(b.cooldown_seconds, 300);
        cfg.validate().unwrap();
    }

    #[test]
    fn governance_defaults_off_and_parses() {
        // Absent → off with sane defaults (backward-compat).
        let cfg = ControlPlaneConfig::from_toml_str("[controlplane]\n").unwrap();
        assert!(!cfg.governance.enabled);
        assert_eq!(cfg.governance.session_ttl_hours, 12);
        assert!(cfg.governance.cookie_secure);
        assert!(cfg.governance.bootstrap_admin.is_none());
        assert_eq!(cfg.governance.login_max_failures, 5);
        assert_eq!(cfg.governance.login_window_seconds, 60);
        assert_eq!(cfg.governance.login_lockout_seconds, 300);

        let toml = r#"
[controlplane]
[controlplane.governance]
enabled = true
session_ttl_hours = 8
cookie_secure = false
bootstrap_admin = "root"
"#;
        let cfg = ControlPlaneConfig::from_toml_str(toml).unwrap();
        assert!(cfg.governance.enabled);
        assert_eq!(cfg.governance.session_ttl_hours, 8);
        assert!(!cfg.governance.cookie_secure);
        assert_eq!(cfg.governance.bootstrap_admin.as_deref(), Some("root"));
    }

    #[test]
    fn alerting_defaults_off_when_absent() {
        let cfg = ControlPlaneConfig::from_toml_str("[controlplane]\n").unwrap();
        assert!(!cfg.alerting.enabled);
        assert_eq!(cfg.alerting.eval_interval_seconds, 30);
        assert!(cfg.alerts.is_empty());
    }

    #[test]
    fn duplicate_alert_name_fails_validation() {
        let toml = r#"
[controlplane]
[[controlplane.alerts]]
name = "dup"
window_seconds = 60
threshold = 5
[[controlplane.alerts]]
name = "dup"
window_seconds = 60
threshold = 5
"#;
        let cfg = ControlPlaneConfig::from_toml_str(toml).unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn siem_defaults_off_and_parses() {
        // Absent → off.
        let cfg = ControlPlaneConfig::from_toml_str("[controlplane]\n").unwrap();
        assert!(!cfg.siem.enabled);
        assert_eq!(cfg.siem.flush_interval_seconds, 10);
        assert_eq!(cfg.siem.batch_size, 500);
        assert!(cfg.siem.destinations.is_empty());

        let toml = r#"
[controlplane]
[controlplane.siem]
enabled = true
flush_interval_seconds = 5
batch_size = 200

[[controlplane.siem.destinations]]
name = "splunk"
endpoint = "https://splunk:8088/services/collector/event"
auth_header = "Splunk abc"
streams = ["decisions", "audit"]

[[controlplane.siem.destinations]]
name = "elastic"
endpoint = "http://elastic:9200/waf/_doc"
"#;
        let cfg = ControlPlaneConfig::from_toml_str(toml).unwrap();
        assert!(cfg.siem.enabled);
        assert_eq!(cfg.siem.batch_size, 200);
        assert_eq!(cfg.siem.destinations.len(), 2);
        assert_eq!(cfg.siem.destinations[0].name, "splunk");
        assert_eq!(cfg.siem.destinations[0].format, SiemFormat::Ecs);
        assert_eq!(cfg.siem.destinations[0].streams, vec![SiemStream::Decisions, SiemStream::Audit]);
        // Second destination defaults to all three streams.
        assert_eq!(cfg.siem.destinations[1].streams, default_siem_streams());
        cfg.validate().unwrap();
    }

    #[test]
    fn siem_validation_rejects_bad_config() {
        // Enabled but no destinations.
        let bad = "[controlplane]\n[controlplane.siem]\nenabled = true\n";
        assert!(ControlPlaneConfig::from_toml_str(bad).unwrap().validate().is_err());
        // Non-http endpoint.
        let bad_ep = "[controlplane]\n[controlplane.siem]\nenabled=true\n[[controlplane.siem.destinations]]\nname=\"s\"\nendpoint=\"splunk:8088\"\n";
        assert!(ControlPlaneConfig::from_toml_str(bad_ep).unwrap().validate().is_err());
        // Duplicate destination name.
        let dup = "[controlplane]\n[controlplane.siem]\nenabled=true\n[[controlplane.siem.destinations]]\nname=\"s\"\nendpoint=\"http://a\"\n[[controlplane.siem.destinations]]\nname=\"s\"\nendpoint=\"http://b\"\n";
        assert!(ControlPlaneConfig::from_toml_str(dup).unwrap().validate().is_err());
        // Unknown stream → deserialize error.
        let bad_stream = "[controlplane]\n[[controlplane.siem.destinations]]\nname=\"s\"\nendpoint=\"http://a\"\nstreams=[\"bogus\"]\n";
        assert!(ControlPlaneConfig::from_toml_str(bad_stream).is_err());
    }

    #[test]
    fn env_key_normalizes() {
        assert_eq!(env_key("splunk-prod"), "SPLUNK_PROD");
        assert_eq!(env_key("Elastic.1"), "ELASTIC_1");
    }

    #[test]
    fn zero_threshold_or_window_fails_validation() {
        let bad_w = "[controlplane]\n[[controlplane.alerts]]\nname=\"a\"\nwindow_seconds=0\nthreshold=5\n";
        assert!(ControlPlaneConfig::from_toml_str(bad_w).unwrap().validate().is_err());
        let bad_t = "[controlplane]\n[[controlplane.alerts]]\nname=\"a\"\nwindow_seconds=60\nthreshold=0\n";
        assert!(ControlPlaneConfig::from_toml_str(bad_t).unwrap().validate().is_err());
    }
}
