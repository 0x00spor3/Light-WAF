// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: BUSL-1.1

//! Node-agent configuration (`node-agent.toml`). The service token is a secret and is read from the
//! environment in preference to the file, so the file can be committed safely.

use serde::Deserialize;

/// Env var overriding `[agent].token` (the control-plane service token — a secret).
pub const ENV_TOKEN: &str = "WAF_AGENT_TOKEN";

fn default_poll_interval() -> u64 {
    15
}

/// `node-agent.toml` → `[agent]`.
#[derive(Debug, Clone, Deserialize)]
pub struct AgentConfig {
    /// Base URL of the control plane, e.g. `http://127.0.0.1:9600`.
    pub control_plane_url: String,
    /// Service token (bearer) for the control-plane API. Prefer the `WAF_AGENT_TOKEN` env var.
    #[serde(default)]
    pub token: Option<String>,
    /// This node's identity (labels its status in the convergence view).
    pub node_name: String,
    /// The managed SecRule `.conf` this agent owns — the same path the WAF loads via
    /// `[modules.crs].files`. The agent overwrites it atomically on each new version.
    pub managed_file: String,
    /// Command to run after writing the file to make the WAF reload (SIGHUP): e.g.
    /// `kill -HUP $(cat /run/waf.pid)` or `systemctl reload waf`. Run via the shell.
    pub reload_command: String,
    /// Seconds between polls of the control plane.
    #[serde(default = "default_poll_interval")]
    pub poll_interval_seconds: u64,
}

/// The `[agent]` table wrapper.
#[derive(Debug, Clone, Deserialize)]
struct File {
    agent: AgentConfig,
}

impl AgentConfig {
    /// Parse from a TOML string — PURE (no environment reads), deterministic in tests.
    pub fn from_toml_str(text: &str) -> Result<Self, String> {
        let file: File = toml::from_str(text).map_err(|e| e.to_string())?;
        Ok(file.agent)
    }

    /// Read `path`, parse, then let `WAF_AGENT_TOKEN` override the token (env wins over file).
    pub fn load(path: &str) -> Result<Self, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("cannot read {path}: {e}"))?;
        let mut cfg = Self::from_toml_str(&text)?;
        if let Ok(v) = std::env::var(ENV_TOKEN) {
            if !v.is_empty() {
                cfg.token = Some(v);
            }
        }
        Ok(cfg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_applies_defaults() {
        let toml = r#"
[agent]
control_plane_url = "http://127.0.0.1:9600"
node_name = "edge-1"
managed_file = "/etc/waf/managed.conf"
reload_command = "kill -HUP 123"
"#;
        let cfg = AgentConfig::from_toml_str(toml).unwrap();
        assert_eq!(cfg.control_plane_url, "http://127.0.0.1:9600");
        assert_eq!(cfg.node_name, "edge-1");
        assert_eq!(cfg.poll_interval_seconds, 15);
        assert!(cfg.token.is_none());
    }

    #[test]
    fn missing_required_field_errors() {
        // No node_name → parse error.
        let toml = "[agent]\ncontrol_plane_url=\"x\"\nmanaged_file=\"y\"\nreload_command=\"z\"\n";
        assert!(AgentConfig::from_toml_str(toml).is_err());
    }
}
