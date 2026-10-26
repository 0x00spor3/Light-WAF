// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

//! Light WAF — **per-node rule-management agent** (§7 write-path v3, enterprise BSL 1.1).
//!
//! The agent is the pull-side of the write path. It polls the control plane for the current managed
//! ruleset version; when a new version appears it **pre-validates** the content with the OPEN seclang
//! parser, writes it **atomically** to the managed `.conf` the WAF loads (`[modules.crs].files`), and
//! runs a configurable `reload_command` (a SIGHUP) so the WAF reloads it. Then it reports the outcome
//! back so the control plane's convergence view is truthful.
//!
//! **Two fail-safe levels**: (1) the agent's pre-validation refuses to touch the WAF if the ruleset
//! does not parse into the supported subset; (2) even so, the WAF's own reload does validate-then-swap
//! (a bad file keeps the last-good rules). **Zero-core**: the agent writes a file the core already
//! reads and triggers the core's existing SIGHUP reload — nothing in the core changes.

use std::io;
use std::path::Path;

use serde::Deserialize;

pub mod config;

pub use config::AgentConfig;

/// The current-version payload from `GET /api/rules/current`. `version`/`content` are both `None`
/// when nothing has been published yet (the agent then leaves the WAF untouched).
#[derive(Debug, Clone, Deserialize)]
pub struct CurrentRule {
    pub version: Option<i64>,
    pub content: Option<String>,
}

/// The result of one poll cycle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PollOutcome {
    /// Nothing to do: no version published, or the current version is already applied.
    Unchanged,
    /// A new version was validated, written and reloaded successfully.
    Applied(i64),
    /// A new version failed pre-validation; the WAF was NOT touched (level-1 fail-safe).
    Rejected { version: i64, reason: String },
    /// A write or reload failed after validation; reported as an error (the WAF's own
    /// validate-then-swap protects it — level-2 fail-safe).
    Error(String),
}

/// Pre-validate a candidate ruleset with the OPEN seclang parser. `Ok(n)` = it parses cleanly into
/// `n` loadable rules (n may be 0 for a legitimately empty/comment-only ruleset that clears rules).
/// `Err` = one or more rules fall OUTSIDE the supported subset (bad regex, missing id, unsupported
/// operator, …) — the agent then refuses to write, so the WAF never sees a partially-loading ruleset.
pub fn validate_ruleset(content: &str) -> Result<usize, String> {
    let module = waf_detection::crs::CrsModule::from_source(content);
    let skipped = module.skipped();
    if !skipped.is_empty() {
        let reasons: Vec<String> = skipped
            .iter()
            .take(5)
            .map(|s| format!("line {}: {}", s.line_no, s.reason))
            .collect();
        return Err(format!(
            "{} rule(s) fall outside the supported subset: {}",
            skipped.len(),
            reasons.join("; ")
        ));
    }
    Ok(module.loaded_count())
}

/// Overwrite `path` atomically: write a sibling temp file, then rename it over the target (an atomic
/// replace on the same filesystem, cross-platform) so the WAF never reloads a half-written file.
pub fn write_atomic(path: &Path, content: &str) -> io::Result<()> {
    let dir = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or_else(|| Path::new("."));
    let stem = path.file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_else(|| "managed".into());
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let tmp = dir.join(format!(".{stem}.tmp.{}.{nanos}", std::process::id()));
    if let Err(e) = std::fs::write(&tmp, content) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    match std::fs::rename(&tmp, path) {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(e)
        }
    }
}

/// Run the configured reload command through the shell (so operators can use pidfile substitution,
/// `systemctl reload`, etc.). A non-zero exit is an error.
pub async fn run_reload_command(cmd: &str) -> Result<(), String> {
    #[cfg(unix)]
    let mut command = {
        let mut c = tokio::process::Command::new("sh");
        c.arg("-c").arg(cmd);
        c
    };
    #[cfg(windows)]
    let mut command = {
        let mut c = tokio::process::Command::new("cmd");
        c.arg("/C").arg(cmd);
        c
    };
    let status = command.status().await.map_err(|e| format!("spawn reload_command: {e}"))?;
    if !status.success() {
        return Err(format!("reload_command exited with {status}"));
    }
    Ok(())
}

/// A thin HTTP client for the control plane's rule endpoints, carrying the service token as a bearer.
pub struct AgentClient {
    http: reqwest::Client,
    base: String,
    token: Option<String>,
}

impl AgentClient {
    /// Build a client for the control plane at `base` (e.g. `http://127.0.0.1:9600`).
    pub fn new(base: impl Into<String>, token: Option<String>) -> Self {
        Self { http: reqwest::Client::new(), base: base.into(), token }
    }

    fn auth(&self, rb: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.token {
            Some(t) => rb.bearer_auth(t),
            None => rb,
        }
    }

    /// `GET /api/rules/current`.
    pub async fn fetch_current(&self) -> Result<CurrentRule, String> {
        let resp = self
            .auth(self.http.get(format!("{}/api/rules/current", self.base)))
            .send()
            .await
            .map_err(|e| e.to_string())?;
        if !resp.status().is_success() {
            return Err(format!("HTTP {}", resp.status()));
        }
        resp.json::<CurrentRule>().await.map_err(|e| e.to_string())
    }

    /// `POST /api/rules/status` — report the applied version + outcome for this node.
    pub async fn report_status(
        &self,
        node: &str,
        version: Option<i64>,
        status: &str,
        detail: &str,
    ) -> Result<(), String> {
        let body = serde_json::json!({ "node": node, "version": version, "status": status, "detail": detail });
        let resp = self
            .auth(self.http.post(format!("{}/api/rules/status", self.base)).json(&body))
            .send()
            .await
            .map_err(|e| e.to_string())?;
        if !resp.status().is_success() {
            return Err(format!("HTTP {}", resp.status()));
        }
        Ok(())
    }
}

/// One poll cycle: fetch the current version; if it differs from `last_applied`, pre-validate it and
/// — only if valid — write it and run `reload` (a SIGHUP/`reload_command` in production, or an
/// in-process `reload_from` in tests), then report the outcome. `reload` is injected so the same
/// orchestration serves both. Never panics; every failure path reports a status and returns.
pub async fn poll_once<F, Fut>(
    client: &AgentClient,
    node: &str,
    managed_file: &Path,
    last_applied: Option<i64>,
    reload: F,
) -> PollOutcome
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<(), String>>,
{
    let current = match client.fetch_current().await {
        Ok(c) => c,
        Err(e) => return PollOutcome::Error(format!("fetch current: {e}")),
    };
    let Some(version) = current.version else {
        return PollOutcome::Unchanged; // nothing published yet
    };
    if Some(version) == last_applied {
        return PollOutcome::Unchanged;
    }
    let content = current.content.unwrap_or_default();

    // Level-1 fail-safe: reject outside-subset content BEFORE touching the WAF.
    if let Err(reason) = validate_ruleset(&content) {
        let _ = client
            .report_status(node, last_applied, "rejected", &format!("v{version}: {reason}"))
            .await;
        return PollOutcome::Rejected { version, reason };
    }

    if let Err(e) = write_atomic(managed_file, &content) {
        let msg = format!("write {}: {e}", managed_file.display());
        let _ = client.report_status(node, last_applied, "error", &msg).await;
        return PollOutcome::Error(msg);
    }
    // The WAF reloads (validate-then-swap = level-2 fail-safe).
    if let Err(e) = reload().await {
        let msg = format!("reload: {e}");
        let _ = client.report_status(node, last_applied, "error", &msg).await;
        return PollOutcome::Error(msg);
    }
    let _ = client.report_status(node, Some(version), "applied", "").await;
    PollOutcome::Applied(version)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_accepts_supported_rule() {
        let ok = "SecRule ARGS \"@rx (?i)bespoketoken\" \"id:9001,phase:2,severity:CRITICAL,block\"";
        assert_eq!(validate_ruleset(ok).unwrap(), 1);
    }

    #[test]
    fn validate_accepts_empty_ruleset() {
        // A comment-only / empty ruleset is valid (0 loaded, nothing skipped) — clears rules.
        assert_eq!(validate_ruleset("# nothing here\n").unwrap(), 0);
        assert_eq!(validate_ruleset("").unwrap(), 0);
    }

    #[test]
    fn validate_rejects_outside_subset() {
        // Missing id → the whole rule is skipped by the parser → the agent rejects it.
        let bad = "SecRule ARGS \"@rx x\" \"phase:2,block\"";
        assert!(validate_ruleset(bad).is_err());
        // Invalid @rx regex → skipped → rejected.
        let bad_rx = "SecRule ARGS \"@rx (unclosed\" \"id:9002,phase:2,block\"";
        assert!(validate_ruleset(bad_rx).is_err());
    }

    #[test]
    fn write_atomic_creates_and_overwrites() {
        let dir = std::env::temp_dir().join(format!("waf-agent-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("managed.conf");

        write_atomic(&path, "first").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "first");
        // Overwrite in place (atomic replace) — no leftover temp files.
        write_atomic(&path, "second").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "second");
        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp."))
            .collect();
        assert!(leftovers.is_empty(), "no temp files must remain");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
