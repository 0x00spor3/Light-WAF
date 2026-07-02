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

use std::time::Duration;

use serde::Deserialize;
use waf_core::Severity;
use waf_state_redis::Reputation;
use waf_threatintel::FeedConfig;
use waf_tls_managed::acme_dns01::Dns01Config;
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
    /// DNS provider name (only meaningful for `strategy = "dns-01"`). E.g. `"cloudflare"`.
    pub provider: Option<String>,
    /// Cluster cert-sharing (multi-node): when `true`, nodes coordinate via the Redis
    /// `SharedCertStore` so ONE node issues for the cluster and the rest converge on that cert.
    /// Requires `[enterprise].redis_url` (or `WAF_REDIS_URL`) AND `WAF_CERT_STORE_KEY`, and is
    /// only meaningful for `strategy = "dns-01"`. Default `false` (per-node issuance).
    pub cluster: bool,
    /// `[tls.acme.dns]` — DNS-01 tunables (zone + propagation/renewal timing).
    pub dns: DnsSection,
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
            cluster: false,
            dns: DnsSection::default(),
        }
    }
}

/// `[tls.acme.dns]` — DNS-01 settings. Secrets (e.g. the Cloudflare token) come from the
/// environment (`CF_API_TOKEN`), never this file.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct DnsSection {
    /// Provider zone identifier (e.g. the Cloudflare zone id the records live in).
    pub zone_id: String,
    /// Max wait for the TXT to appear on the zone's authoritative nameservers.
    pub propagation_timeout_secs: u64,
    /// Interval between propagation polls.
    pub poll_interval_secs: u64,
    /// Courtesy delay after the TXT is first seen (CAs validate from several vantage points).
    pub grace_secs: u64,
    /// Days between successful issuance and the next renewal attempt.
    pub renewal_days: u64,
}

impl Default for DnsSection {
    fn default() -> Self {
        Self {
            zone_id: String::new(),
            propagation_timeout_secs: 120,
            poll_interval_secs: 5,
            grace_secs: 10,
            renewal_days: 60,
        }
    }
}

impl DnsSection {
    /// Build the driver's [`Dns01Config`] from these tunables.
    pub fn to_config(&self) -> Dns01Config {
        Dns01Config {
            propagation_timeout: Duration::from_secs(self.propagation_timeout_secs),
            poll_interval: Duration::from_secs(self.poll_interval_secs),
            grace: Duration::from_secs(self.grace_secs),
            renewal_interval: Duration::from_secs(self.renewal_days * 24 * 60 * 60),
            // retry_backoff / lock_ttl / convergence_poll: driver defaults (not TOML-exposed yet).
            ..Dns01Config::default()
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
    /// `[enterprise.reputation]` — cluster-wide IP-reputation module (reads the same Redis).
    pub reputation: ReputationSection,
    /// `[enterprise.crs_curated]` — the curated premium CRS ruleset module (§6).
    pub crs_curated: CrsCuratedSection,
}

impl Default for EnterpriseConfig {
    fn default() -> Self {
        Self {
            redis_url: None,
            pool_size: None,
            fail_open: true,
            reputation: ReputationSection::default(),
            crs_curated: CrsCuratedSection::default(),
        }
    }
}

/// `[enterprise.crs_curated]` — loads the curated premium CRS/ModSecurity ruleset (the
/// `waf-crs-curated` content) as a `WafModule` via the OPEN CRS engine. Default OFF. No Redis
/// needed (pure detection content); contributes to the same cumulative anomaly score.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct CrsCuratedSection {
    pub enabled: bool,
}

/// `[enterprise.reputation]` — the cluster-wide IP-reputation `WafModule`. It reads the Redis
/// store (so it needs `redis_url`) and contributes to the cumulative anomaly score. The score
/// weight is a **severity** (no hardcoded points — the pipeline maps severity→points).
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ReputationSection {
    pub enabled: bool,
    /// Severity contributed for a Malicious IP: `critical` | `error` | `warning` | `notice`.
    pub malicious_severity: String,
    /// Severity contributed for a Suspicious IP.
    pub suspicious_severity: String,
    /// `[enterprise.reputation.feed]` — the threat-intel feed that POPULATES `rep:<ip>` (§6).
    pub feed: FeedSection,
}

impl Default for ReputationSection {
    fn default() -> Self {
        Self {
            enabled: false,
            malicious_severity: "critical".to_string(),
            suspicious_severity: "warning".to_string(),
            feed: FeedSection::default(),
        }
    }
}

impl ReputationSection {
    /// Parse the `(malicious, suspicious)` severities, rejecting unknown names.
    pub fn severities(&self) -> Result<(Severity, Severity), String> {
        Ok((parse_severity(&self.malicious_severity)?, parse_severity(&self.suspicious_severity)?))
    }
}

/// `[enterprise.reputation.feed]` — the background feed that populates the `rep:<ip>` keyspace the
/// reputation module reads (ARCHITECTURE_ENTERPRISE §6). Needs Redis (the shared store). One node
/// (the single-writer lock winner) refreshes per cycle. Default OFF.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct FeedSection {
    pub enabled: bool,
    /// Seconds between refresh cycles.
    pub refresh_interval_secs: u64,
    /// TTL (seconds) of each written `rep:<ip>` entry. Absent ⇒ 3× the refresh interval, so a
    /// missed/failed cycle never drops still-listed IPs (a down feed ages everything to Unknown).
    pub entry_ttl_secs: Option<u64>,
    /// TTL (seconds) of the per-cycle single-writer lock — roughly the worst-case fetch+write time.
    pub lock_ttl_secs: u64,
    /// The list sources. Each has a fixed verdict (the content says WHICH ips, never HOW severe).
    pub sources: Vec<FeedSourceSection>,
}

impl Default for FeedSection {
    fn default() -> Self {
        Self {
            enabled: false,
            refresh_interval_secs: 300,
            entry_ttl_secs: None,
            lock_ttl_secs: 90,
            sources: Vec::new(),
        }
    }
}

impl FeedSection {
    /// Build the driver's [`FeedConfig`]. `entry_ttl` defaults to 3× the refresh interval (F2).
    pub fn to_config(&self) -> FeedConfig {
        let refresh = Duration::from_secs(self.refresh_interval_secs.max(1));
        let entry_ttl = match self.entry_ttl_secs {
            Some(s) => Duration::from_secs(s.max(1)),
            None => refresh * 3,
        };
        FeedConfig {
            refresh_interval: refresh,
            entry_ttl,
            lock_ttl: Duration::from_secs(self.lock_ttl_secs.max(1)),
        }
    }
}

/// One `[[enterprise.reputation.feed.sources]]` entry.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct FeedSourceSection {
    /// `"file"` (local path) or `"http"` (HTTPS URL).
    pub kind: String,
    /// The file path or URL of the IP list.
    pub location: String,
    /// The verdict assigned to every IP in this source: `malicious` | `suspicious`.
    pub verdict: String,
}

impl Default for FeedSourceSection {
    fn default() -> Self {
        Self { kind: String::new(), location: String::new(), verdict: "malicious".to_string() }
    }
}

impl FeedSourceSection {
    /// Parse the fixed verdict for this source, rejecting anything but malicious/suspicious
    /// (`Unknown` as a source verdict is meaningless — it would write nothing).
    pub fn verdict(&self) -> Result<Reputation, String> {
        match self.verdict.trim().to_ascii_lowercase().as_str() {
            "malicious" => Ok(Reputation::Malicious),
            "suspicious" => Ok(Reputation::Suspicious),
            other => Err(format!(
                "unknown [enterprise.reputation.feed] verdict {other:?} (use malicious|suspicious)"
            )),
        }
    }
}

fn parse_severity(s: &str) -> Result<Severity, String> {
    match s.trim().to_ascii_lowercase().as_str() {
        "critical" => Ok(Severity::Critical),
        "error" => Ok(Severity::Error),
        "warning" => Ok(Severity::Warning),
        "notice" => Ok(Severity::Notice),
        other => Err(format!(
            "unknown [enterprise.reputation] severity {other:?} (use critical|error|warning|notice)"
        )),
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
    fn reads_reputation_section_and_parses_severities() {
        let toml = r#"
[proxy]
listen = "127.0.0.1:8080"
backend = "http://127.0.0.1:3000"
[waf]
mode = "blocking"
[enterprise]
redis_url = "redis://localhost:6379"
[enterprise.reputation]
enabled = true
malicious_severity = "error"
suspicious_severity = "notice"
"#;
        let f = EnterpriseFile::from_toml_str(toml).expect("parses");
        let rep = &f.enterprise.reputation;
        assert!(rep.enabled);
        assert_eq!(rep.severities().unwrap(), (Severity::Error, Severity::Notice));
    }

    #[test]
    fn reads_crs_curated_flag_and_defaults_off() {
        let f = EnterpriseFile::from_toml_str(
            "[proxy]\nlisten=\"127.0.0.1:8080\"\nbackend=\"http://x:3000\"\n[waf]\nmode=\"blocking\"\n",
        )
        .expect("parses");
        assert!(!f.enterprise.crs_curated.enabled, "curated CRS default OFF");

        let toml = r#"
[proxy]
listen = "127.0.0.1:8080"
backend = "http://127.0.0.1:3000"
[waf]
mode = "blocking"
[enterprise.crs_curated]
enabled = true
"#;
        let f = EnterpriseFile::from_toml_str(toml).expect("parses");
        assert!(f.enterprise.crs_curated.enabled);
    }

    #[test]
    fn reputation_defaults_off_with_critical_warning() {
        let f = EnterpriseFile::from_toml_str(
            "[proxy]\nlisten=\"127.0.0.1:8080\"\nbackend=\"http://x:3000\"\n[waf]\nmode=\"blocking\"\n",
        )
        .expect("parses");
        assert!(!f.enterprise.reputation.enabled, "reputation default OFF");
        assert_eq!(
            f.enterprise.reputation.severities().unwrap(),
            (Severity::Critical, Severity::Warning)
        );
    }

    #[test]
    fn reads_feed_section_with_sources_and_builds_config() {
        let toml = r#"
[proxy]
listen = "127.0.0.1:8080"
backend = "http://127.0.0.1:3000"
[waf]
mode = "blocking"
[enterprise]
redis_url = "redis://localhost:6379"
[enterprise.reputation]
enabled = true
[enterprise.reputation.feed]
enabled = true
refresh_interval_secs = 120
lock_ttl_secs = 60
[[enterprise.reputation.feed.sources]]
kind = "file"
location = "/etc/waf/blocklist.txt"
verdict = "malicious"
[[enterprise.reputation.feed.sources]]
kind = "http"
location = "https://example.com/greylist.txt"
verdict = "suspicious"
"#;
        let f = EnterpriseFile::from_toml_str(toml).expect("parses");
        let feed = &f.enterprise.reputation.feed;
        assert!(feed.enabled);
        assert_eq!(feed.sources.len(), 2);
        assert_eq!(feed.sources[0].kind, "file");
        assert_eq!(feed.sources[0].verdict().unwrap(), Reputation::Malicious);
        assert_eq!(feed.sources[1].kind, "http");
        assert_eq!(feed.sources[1].verdict().unwrap(), Reputation::Suspicious);

        let cfg = feed.to_config();
        assert_eq!(cfg.refresh_interval, Duration::from_secs(120));
        assert_eq!(cfg.entry_ttl, Duration::from_secs(360), "entry_ttl defaults to 3× refresh");
        assert_eq!(cfg.lock_ttl, Duration::from_secs(60));
    }

    #[test]
    fn feed_defaults_off_and_entry_ttl_follows_refresh() {
        let f = EnterpriseFile::from_toml_str(
            "[proxy]\nlisten=\"127.0.0.1:8080\"\nbackend=\"http://x:3000\"\n[waf]\nmode=\"blocking\"\n",
        )
        .expect("parses");
        let feed = &f.enterprise.reputation.feed;
        assert!(!feed.enabled, "feed default OFF");
        assert!(feed.sources.is_empty());
        let cfg = feed.to_config();
        assert_eq!(cfg.refresh_interval, Duration::from_secs(300));
        assert_eq!(cfg.entry_ttl, Duration::from_secs(900), "default entry_ttl = 3× default refresh");
    }

    #[test]
    fn feed_explicit_entry_ttl_overrides_the_default() {
        let toml = r#"
[proxy]
listen = "127.0.0.1:8080"
backend = "http://127.0.0.1:3000"
[waf]
mode = "blocking"
[enterprise.reputation.feed]
enabled = true
refresh_interval_secs = 100
entry_ttl_secs = 111
"#;
        let f = EnterpriseFile::from_toml_str(toml).expect("parses");
        assert_eq!(f.enterprise.reputation.feed.to_config().entry_ttl, Duration::from_secs(111));
    }

    #[test]
    fn feed_unknown_verdict_is_rejected() {
        let toml = r#"
[proxy]
listen = "127.0.0.1:8080"
backend = "http://127.0.0.1:3000"
[waf]
mode = "blocking"
[[enterprise.reputation.feed.sources]]
kind = "file"
location = "/x"
verdict = "nope"
"#;
        let f = EnterpriseFile::from_toml_str(toml).expect("parses");
        assert!(f.enterprise.reputation.feed.sources[0].verdict().is_err());
    }

    #[test]
    fn reputation_unknown_severity_is_rejected() {
        let toml = r#"
[proxy]
listen = "127.0.0.1:8080"
backend = "http://127.0.0.1:3000"
[waf]
mode = "blocking"
[enterprise.reputation]
malicious_severity = "nope"
"#;
        let f = EnterpriseFile::from_toml_str(toml).expect("parses");
        assert!(f.enterprise.reputation.severities().is_err());
    }

    #[test]
    fn reads_dns01_section_and_builds_driver_config() {
        let toml = r#"
[proxy]
listen = "127.0.0.1:8080"
backend = "http://127.0.0.1:3000"
[waf]
mode = "blocking"
[tls.acme]
enabled = true
strategy = "dns-01"
provider = "cloudflare"
domains = ["example.com", "*.example.com"]
[tls.acme.dns]
zone_id = "zone-abc"
propagation_timeout_secs = 90
poll_interval_secs = 3
grace_secs = 7
renewal_days = 45
"#;
        let f = EnterpriseFile::from_toml_str(toml).expect("parses");
        let acme = &f.tls.acme;
        assert_eq!(
            acme.challenge_strategy().unwrap(),
            ChallengeStrategy::Dns01 { provider: Some("cloudflare".to_string()) }
        );
        assert_eq!(acme.dns.zone_id, "zone-abc");
        let cfg = acme.dns.to_config();
        assert_eq!(cfg.propagation_timeout, Duration::from_secs(90));
        assert_eq!(cfg.poll_interval, Duration::from_secs(3));
        assert_eq!(cfg.grace, Duration::from_secs(7));
        assert_eq!(cfg.renewal_interval, Duration::from_secs(45 * 24 * 60 * 60));
    }

    #[test]
    fn cluster_flag_defaults_off_and_parses() {
        let f = EnterpriseFile::from_toml_str(
            "[proxy]\nlisten=\"127.0.0.1:8080\"\nbackend=\"http://x:3000\"\n[waf]\nmode=\"blocking\"\n",
        )
        .expect("parses");
        assert!(!f.tls.acme.cluster, "cert-sharing must default OFF (per-node issuance)");

        let toml = r#"
[proxy]
listen = "127.0.0.1:8080"
backend = "http://127.0.0.1:3000"
[waf]
mode = "blocking"
[tls.acme]
enabled = true
strategy = "dns-01"
cluster = true
"#;
        let f = EnterpriseFile::from_toml_str(toml).expect("parses");
        assert!(f.tls.acme.cluster);
    }

    #[test]
    fn dns_section_defaults_when_omitted() {
        let f = EnterpriseFile::from_toml_str(
            "[proxy]\nlisten=\"127.0.0.1:8080\"\nbackend=\"http://x:3000\"\n[waf]\nmode=\"blocking\"\n",
        )
        .expect("parses");
        assert_eq!(f.tls.acme.dns.zone_id, "");
        assert_eq!(f.tls.acme.dns.to_config().propagation_timeout, Duration::from_secs(120));
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
