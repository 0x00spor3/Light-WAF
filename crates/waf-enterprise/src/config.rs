// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: BUSL-1.1

//! Enterprise-only configuration, read from the SAME TOML file as the OPEN
//! `waf_core::Config`.
//!
//! The core's `Config` is a frozen, `#[non_exhaustive]` ABI with no enterprise
//! fields and no `deny_unknown_fields`, so it simply **ignores** an `[enterprise]`
//! section. We deserialize the same file a second time into [`EnterpriseFile`],
//! which keeps `[enterprise]` and ignores everything else (`[proxy]`, `[waf]`, …).
//! That keeps the enterprise knobs out of the OPEN schema while still living in one
//! file (BOUNDARY §4: extend without forking).

use serde::Deserialize;
use waf_tls_managed::ChallengeStrategy;

/// A view over the config file that extracts ONLY the enterprise-relevant tables
/// (`[enterprise]`, `[tls.acme]`, `[tls.mtls]`). Everything else is ignored.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct EnterpriseFile {
    #[serde(default)]
    pub enterprise: EnterpriseConfig,
    /// The `[tls]` table — we only read its enterprise sub-tables (`acme`/`mtls`); the
    /// OPEN keys (`enabled`/`cert_path`/`key_path`/`alpn`) are owned by `waf_core::Config`.
    #[serde(default)]
    pub tls: TlsSection,
}

/// `[tls]` — enterprise sub-tables only.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct TlsSection {
    pub acme: AcmeSection,
    pub mtls: MtlsSection,
}

/// `[tls.acme]` — managed ACME certificates (enterprise).
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct AcmeSection {
    pub enabled: bool,
    pub domains: Vec<String>,
    pub email: Option<String>,
    /// `"tls-alpn-01"` (default) or `"dns-01"`.
    pub strategy: String,
    pub cache_dir: String,
    /// `true` (default) ⇒ staging CA — avoids hitting Let's Encrypt production rate limits
    /// by accident.
    pub staging: bool,
    /// Override the ACME directory URL (a Pebble test server, or a private CA).
    pub directory_url: Option<String>,
    /// DNS provider name (only meaningful for `strategy = "dns-01"`).
    pub provider: Option<String>,
}

impl Default for AcmeSection {
    fn default() -> Self {
        Self {
            enabled: false,
            domains: Vec::new(),
            email: None,
            strategy: "tls-alpn-01".to_string(),
            cache_dir: "acme-cache".to_string(),
            staging: true,
            directory_url: None,
            provider: None,
        }
    }
}

impl AcmeSection {
    /// Map the string strategy to the typed [`ChallengeStrategy`], rejecting unknown values.
    pub fn challenge_strategy(&self) -> Result<ChallengeStrategy, String> {
        match self.strategy.as_str() {
            "tls-alpn-01" => Ok(ChallengeStrategy::TlsAlpn01),
            "dns-01" => Ok(ChallengeStrategy::Dns01 { provider: self.provider.clone() }),
            other => Err(format!(
                "unknown [tls.acme].strategy {other:?} (use \"tls-alpn-01\" or \"dns-01\")"
            )),
        }
    }
}

/// `[tls.mtls]` — managed-PKI client-certificate verification (enterprise).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct MtlsSection {
    pub enabled: bool,
    /// PEM bundle of trusted client CAs.
    pub ca_path: String,
}

/// The `[enterprise]` section. Every field optional with a fail-safe default, so
/// a config without the section behaves exactly like the OPEN single-node proxy.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct EnterpriseConfig {
    /// Redis connection URL for the distributed rate-limit `StateStore`
    /// (e.g. `redis://10.0.0.5:6379`). Absent ⇒ in-memory single-node store.
    /// Overridable by the `WAF_REDIS_URL` env var (env wins).
    pub redis_url: Option<String>,
    /// Connection-pool size for the Redis store. Absent ⇒ the store's default.
    pub pool_size: Option<u32>,
    /// Posture when Redis errors at runtime: `true` (default) ⇒ fail-open (allow),
    /// `false` ⇒ fail-closed (deny). A misconfigured/unreachable Redis at BOOT is
    /// always fatal regardless of this flag.
    pub fail_open: bool,
}

impl Default for EnterpriseConfig {
    fn default() -> Self {
        Self { redis_url: None, pool_size: None, fail_open: true }
    }
}

impl EnterpriseFile {
    /// Parse the `[enterprise]` section out of the raw TOML text. Unknown tables are
    /// ignored, so the same string that `waf_core::Config` parsed loads here too.
    pub fn from_toml_str(text: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FULL: &str = r#"
[proxy]
listen = "127.0.0.1:8080"
backend = "http://127.0.0.1:3000"

[waf]
mode = "blocking"

[rate_limit]
enabled = true
requests = 5
window_seconds = 60

[enterprise]
redis_url = "redis://10.0.0.5:6379"
pool_size = 32
fail_open = false
"#;

    #[test]
    fn reads_enterprise_section_ignoring_the_rest() {
        let f = EnterpriseFile::from_toml_str(FULL).expect("parses");
        assert_eq!(f.enterprise.redis_url.as_deref(), Some("redis://10.0.0.5:6379"));
        assert_eq!(f.enterprise.pool_size, Some(32));
        assert!(!f.enterprise.fail_open);
    }

    #[test]
    fn missing_section_uses_failsafe_defaults() {
        let only_open = r#"
[proxy]
listen = "127.0.0.1:8080"
backend = "http://127.0.0.1:3000"
[waf]
mode = "blocking"
"#;
        let f = EnterpriseFile::from_toml_str(only_open).expect("parses");
        assert!(f.enterprise.redis_url.is_none());
        assert!(f.enterprise.pool_size.is_none());
        assert!(f.enterprise.fail_open, "default posture is fail-open");
    }

    #[test]
    fn reads_tls_acme_and_mtls_sections() {
        let toml = r#"
[proxy]
listen = "127.0.0.1:8080"
backend = "http://127.0.0.1:3000"
[waf]
mode = "blocking"
[tls]
enabled = true
[tls.acme]
enabled = true
domains = ["a.example.com", "b.example.com"]
email = "ops@example.com"
strategy = "tls-alpn-01"
staging = true
[tls.mtls]
enabled = true
ca_path = "/etc/waf/clients-ca.pem"
"#;
        let f = EnterpriseFile::from_toml_str(toml).expect("parses");
        assert!(f.tls.acme.enabled);
        assert_eq!(f.tls.acme.domains, vec!["a.example.com", "b.example.com"]);
        assert_eq!(f.tls.acme.challenge_strategy().unwrap(), ChallengeStrategy::TlsAlpn01);
        assert!(f.tls.mtls.enabled);
        assert_eq!(f.tls.mtls.ca_path, "/etc/waf/clients-ca.pem");
    }

    #[test]
    fn tls_sections_default_off_and_strategy_defaults_to_tls_alpn() {
        let f = EnterpriseFile::from_toml_str(
            "[proxy]\nlisten=\"127.0.0.1:8080\"\nbackend=\"http://x:3000\"\n[waf]\nmode=\"blocking\"\n",
        )
        .expect("parses");
        assert!(!f.tls.acme.enabled);
        assert!(!f.tls.mtls.enabled);
        assert_eq!(f.tls.acme.challenge_strategy().unwrap(), ChallengeStrategy::TlsAlpn01);
        assert!(f.tls.acme.staging, "staging must default true (avoid LE prod rate limits)");
    }

    #[test]
    fn dns01_strategy_maps_with_provider() {
        let toml = r#"
[proxy]
listen = "127.0.0.1:8080"
backend = "http://127.0.0.1:3000"
[waf]
mode = "blocking"
[tls.acme]
strategy = "dns-01"
provider = "cloudflare"
"#;
        let f = EnterpriseFile::from_toml_str(toml).expect("parses");
        assert_eq!(
            f.tls.acme.challenge_strategy().unwrap(),
            ChallengeStrategy::Dns01 { provider: Some("cloudflare".to_string()) }
        );
    }

    #[test]
    fn unknown_strategy_is_rejected() {
        let toml = r#"
[proxy]
listen = "127.0.0.1:8080"
backend = "http://127.0.0.1:3000"
[waf]
mode = "blocking"
[tls.acme]
strategy = "http-01"
"#;
        let f = EnterpriseFile::from_toml_str(toml).expect("parses");
        assert!(f.tls.acme.challenge_strategy().is_err());
    }

    #[test]
    fn partial_section_defaults_the_omitted_fields() {
        let partial = r#"
[proxy]
listen = "127.0.0.1:8080"
backend = "http://127.0.0.1:3000"
[waf]
mode = "blocking"
[enterprise]
redis_url = "redis://localhost:6379"
"#;
        let f = EnterpriseFile::from_toml_str(partial).expect("parses");
        assert_eq!(f.enterprise.redis_url.as_deref(), Some("redis://localhost:6379"));
        assert!(f.enterprise.pool_size.is_none());
        assert!(f.enterprise.fail_open);
    }
}
