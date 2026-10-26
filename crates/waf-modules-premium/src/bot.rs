// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

//! Client-integrity / bot detection (§4-A). Native cross-header heuristics that a single regex
//! cannot express — deliberately NOT the OPEN `scanner` module (which matches offensive-tool names
//! in the User-Agent) nor curated content (CRS-curated §6).
//!
//! **v1 signal — browser impersonation (S1).** A request whose User-Agent advertises a *modern*
//! browser (Chromium/Firefox with a 3-digit major version → 2022+) but which carries **none** of the
//! `sec-fetch-*` Fetch-Metadata headers that browser always sends. A crude bot spoofing a Chrome UA
//! via `curl`/`requests` omits them; a legitimate non-browser client (curl/SDK) does not advertise a
//! browser at all, so it is not flagged. Additive `Decision::Scores` (Critical, tunable) — never a
//! hard reject: the FP source is old/edge browsers or header-stripping proxies, governed by severity.
//!
//! **STEP 1–2 (scaffold + config).** The crate carries the `bot-*` registry leaf, the UA classifier,
//! the S1 rule and its config, proven on the real `Pipeline`. Safari is excluded in v1 (historically
//! inconsistent Sec-Fetch). Unlike the schema modules there is no file to load, so construction is
//! infallible (no boot-fatal). The `[enterprise.bot_detection]` wiring lands in Step 5.

use waf_core::{Config, Decision, Phase, RequestContext, ScoreItem, Severity, WafModule};

use crate::rules;

/// Configuration for the bot-detection module. Built by the enterprise wiring from
/// `[enterprise.bot_detection]` (Step 5). No file/schema, no Redis — the heuristics are native.
#[derive(Debug, Clone)]
pub struct BotDetectionConfig {
    /// Off by default → the module is inert.
    pub enabled: bool,
    /// Severity contributed by the browser-impersonation signal (S1). Default Critical.
    pub browser_impersonation_severity: Severity,
}

impl Default for BotDetectionConfig {
    fn default() -> Self {
        Self { enabled: false, browser_impersonation_severity: Severity::Critical }
    }
}

/// True if `ua` advertises a **modern** Chromium or Firefox browser — a 3-digit major version
/// (`>= 100`, i.e. 2022+), which always emits Fetch-Metadata (`Sec-Fetch-*`). Safari is intentionally
/// NOT matched (its Sec-Fetch support was historically inconsistent → would be a false-positive
/// source). Chromium-based Edge/Opera/etc. carry the `Chrome/1xx` token and are covered.
pub fn is_modern_browser_ua(ua: &str) -> bool {
    ua_token_major_ge_100(ua, "Chrome/") || ua_token_major_ge_100(ua, "Firefox/")
}

/// Whether `ua` contains `<token><major>` with a 3+ digit major version.
fn ua_token_major_ge_100(ua: &str, token: &str) -> bool {
    ua.match_indices(token).any(|(i, _)| {
        let rest = &ua[i + token.len()..];
        rest.chars().take_while(|c| c.is_ascii_digit()).count() >= 3
    })
}

/// The User-Agent header value (empty if absent). Read from the normalized headers (names
/// lowercased, values preserved).
fn user_agent(ctx: &RequestContext) -> &str {
    ctx.normalized
        .headers
        .iter()
        .find(|(k, _)| k == "user-agent")
        .map(|(_, v)| v.as_str())
        .unwrap_or("")
}

/// Whether the request carries any `sec-fetch-*` header (Fetch Metadata).
fn has_sec_fetch(ctx: &RequestContext) -> bool {
    ctx.normalized.headers.iter().any(|(k, _)| k.starts_with("sec-fetch-"))
}

/// Bot-detection module. Scores a request that impersonates a browser (S1).
pub struct BotDetectionModule {
    enabled: bool,
    impersonation_severity: Severity,
}

impl BotDetectionModule {
    /// Production constructor. Infallible — there is no schema/file to load (native heuristics).
    pub fn from_config(cfg: &BotDetectionConfig) -> Self {
        Self { enabled: cfg.enabled, impersonation_severity: cfg.browser_impersonation_severity }
    }

    /// Test/embedding constructor (default Critical severity).
    pub fn new(enabled: bool) -> Self {
        Self::from_config(&BotDetectionConfig { enabled, ..Default::default() })
    }
}

impl WafModule for BotDetectionModule {
    fn id(&self) -> &str {
        "bot-detection"
    }

    fn phase(&self) -> Phase {
        Phase::Headers
    }

    /// Structural: the verdict is a cross-header heuristic, not a content-rule match, so the content
    /// fast-path must not skip it.
    fn structural(&self) -> bool {
        true
    }

    fn init(&mut self, _cfg: &Config) {}

    fn inspect(&self, ctx: &RequestContext) -> Decision {
        if !self.enabled {
            return Decision::Allow;
        }
        // S1: UA claims a modern browser but the request carries no Fetch-Metadata → impersonation.
        if is_modern_browser_ua(user_agent(ctx)) && !has_sec_fetch(ctx) {
            return Decision::Scores(vec![ScoreItem {
                rule_id: rules::BOT_BROWSER_IMPERSONATION.id(),
                severity: self.impersonation_severity,
            }]);
        }
        Decision::Allow
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHROME: &str =
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) \
         Chrome/120.0.0.0 Safari/537.36";
    const FIREFOX: &str = "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0";
    const EDGE: &str = "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) \
                        Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0";
    const SAFARI: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 \
                          (KHTML, like Gecko) Version/17.0 Safari/605.1.15";

    #[test]
    fn classifies_modern_browsers() {
        assert!(is_modern_browser_ua(CHROME));
        assert!(is_modern_browser_ua(FIREFOX));
        assert!(is_modern_browser_ua(EDGE)); // Chromium token
    }

    #[test]
    fn excludes_non_browsers_old_browsers_and_safari() {
        assert!(!is_modern_browser_ua("curl/8.4.0"));
        assert!(!is_modern_browser_ua("python-requests/2.31.0"));
        assert!(!is_modern_browser_ua("")); // no UA
        assert!(!is_modern_browser_ua("Mozilla/5.0 ... Chrome/79.0.3945.88 Safari/537.36")); // 2-digit
        assert!(!is_modern_browser_ua(SAFARI)); // Safari excluded (no Chrome/Firefox token)
    }

    #[test]
    fn default_config_is_off_with_critical_severity() {
        let c = BotDetectionConfig::default();
        assert!(!c.enabled);
        assert_eq!(c.browser_impersonation_severity, Severity::Critical);
    }

    #[test]
    fn from_config_carries_enabled_and_severity() {
        let cfg = BotDetectionConfig {
            enabled: true,
            browser_impersonation_severity: Severity::Warning,
        };
        let m = BotDetectionModule::from_config(&cfg);
        assert!(m.enabled);
        assert_eq!(m.impersonation_severity, Severity::Warning);
    }
}
