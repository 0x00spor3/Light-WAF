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

use std::path::PathBuf;
use std::time::Duration;

use serde::Deserialize;
use waf_capture::{CaptureConfig, RedactionConfig};
use waf_core::Severity;
use waf_marketplace::WasmOptions;
use waf_modules_premium::{
    ApiSchemaEnforcementConfig, BotDetectionConfig, GrpcSchemaEnforcementConfig,
    SchemaEnforcementConfig,
};
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
    /// `[enterprise.schema_enforcement]` — GraphQL schema-enforcement module (§4-B).
    pub schema_enforcement: SchemaEnforcementSection,
    /// `[enterprise.grpc_schema_enforcement]` — gRPC schema-enforcement module (§4-B part 2).
    pub grpc_schema_enforcement: GrpcSchemaEnforcementSection,
    /// `[enterprise.api_schema]` — OpenAPI positive-security module (§4-B part 3).
    pub api_schema: ApiSchemaEnforcementSection,
    /// `[enterprise.bot_detection]` — client-integrity / bot detection module (§4-A).
    pub bot_detection: BotDetectionSection,
    /// `[enterprise.wasm]` — signed WASM plugin loader (§4-C).
    pub wasm: WasmSection,
    /// `[enterprise.capture]` — request-capture feature (full denied requests → control-plane).
    pub capture: CaptureSection,
}

impl Default for EnterpriseConfig {
    fn default() -> Self {
        Self {
            redis_url: None,
            pool_size: None,
            fail_open: true,
            reputation: ReputationSection::default(),
            crs_curated: CrsCuratedSection::default(),
            schema_enforcement: SchemaEnforcementSection::default(),
            grpc_schema_enforcement: GrpcSchemaEnforcementSection::default(),
            api_schema: ApiSchemaEnforcementSection::default(),
            bot_detection: BotDetectionSection::default(),
            wasm: WasmSection::default(),
            capture: CaptureSection::default(),
        }
    }
}

/// `[enterprise.capture]` — Request Capture (optional, default OFF). Buffers the FULL denied request
/// (headers/body) off the datapath and ships it to the control-plane for the event drill-down. Zero
/// core changes (a `WafModule` fills a bounded ring, a `tracing::Layer` joins the verdict, a shipper
/// POSTs to `/ingest/captures` — landing in C1–C2). Capture is **raw by default**; the redaction
/// sub-table strips named headers/body-fields node-side. Retention (hard-delete) is a control-plane
/// concern and is configured there, not here. The bearer token comes from the environment
/// (`token_env`), never this file.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct CaptureSection {
    pub enabled: bool,
    /// Control-plane base URL (e.g. `http://controlplane:8080`); the shipper appends `/ingest/captures`.
    pub controlplane_url: String,
    /// Env var holding the ingest bearer token (never the token itself).
    pub token_env: String,
    /// Cap on captured body bytes (larger → truncated + flagged).
    pub max_body_bytes: usize,
    /// Ring bound by entry count.
    pub ring_capacity: usize,
    /// Ring bound by total bytes.
    pub ring_bytes: usize,
    /// Ring entry time-to-live (ms) before an unshipped capture is evicted.
    pub ring_ttl_ms: u64,
    /// Bound on the shipper's outbound queue (full ⇒ drop, never block the datapath).
    pub queue_capacity: usize,
    /// `[enterprise.capture.redaction]` — header/body-field names to strip node-side.
    pub redaction: RedactionSection,
}

impl Default for CaptureSection {
    fn default() -> Self {
        // Mirror `CaptureConfig::default()` so the TOML defaults and the typed defaults never drift.
        let d = CaptureConfig::default();
        Self {
            enabled: d.enabled,
            controlplane_url: d.controlplane_url,
            token_env: d.token_env,
            max_body_bytes: d.max_body_bytes,
            ring_capacity: d.ring_capacity,
            ring_bytes: d.ring_bytes,
            ring_ttl_ms: d.ring_ttl.as_millis() as u64,
            queue_capacity: d.queue_capacity,
            redaction: RedactionSection::default(),
        }
    }
}

impl CaptureSection {
    /// Build the typed [`CaptureConfig`]. Boot-fatal (returns `Err`) when enabled without a
    /// control-plane URL — a capture module that can never ship is a silent misconfiguration.
    pub fn to_config(&self) -> Result<CaptureConfig, String> {
        if self.enabled && self.controlplane_url.trim().is_empty() {
            return Err(
                "[enterprise.capture] enabled = true requires a non-empty controlplane_url".into(),
            );
        }
        Ok(CaptureConfig {
            enabled: self.enabled,
            controlplane_url: self.controlplane_url.clone(),
            token_env: self.token_env.clone(),
            max_body_bytes: self.max_body_bytes,
            ring_capacity: self.ring_capacity,
            ring_bytes: self.ring_bytes,
            ring_ttl: Duration::from_millis(self.ring_ttl_ms),
            queue_capacity: self.queue_capacity,
            redaction: RedactionConfig {
                headers: self.redaction.headers.clone(),
                body_fields: self.redaction.body_fields.clone(),
            },
        })
    }
}

/// `[enterprise.capture.redaction]` — names stripped node-side before a capture is stored/shipped.
/// Empty (the default) = raw capture. Both lists match case-insensitively.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct RedactionSection {
    /// Header names to replace with `***REDACTED***` (e.g. `authorization`, `cookie`, `set-cookie`).
    pub headers: Vec<String>,
    /// Body field / form parameter names to replace with `***REDACTED***` (e.g. `password`, `token`).
    pub body_fields: Vec<String>,
}

/// `[enterprise.wasm]` — load Proxy-Wasm plugins ONLY after verifying a minisign signature against
/// `trusted_keys` (§4-C). Default OFF. A signed plugin whose signature does not verify is boot-fatal
/// (fail-closed, K5 — unlike the OPEN `[modules.wasm]`, which skips a broken UNSIGNED plugin).
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct WasmSection {
    pub enabled: bool,
    /// K6 enforcement: when `true`, refuse to boot if the OPEN `[modules.wasm]` also loads plugins
    /// (which would be UNSIGNED, bypassing the gate). Off by default — coexistence is a convention.
    pub exclusive: bool,
    /// Base64 minisign public keys (the key line of a `.pub`) plugins are trusted against.
    pub trusted_keys: Vec<String>,
    /// Section-global runtime limits (mirror `[modules.wasm]`).
    pub pool_size: usize,
    pub fuel_per_request: u64,
    pub max_memory_bytes: usize,
    pub checkout_timeout_ms: u64,
    pub plugins: Vec<WasmPluginSection>,
}

impl Default for WasmSection {
    fn default() -> Self {
        Self {
            enabled: false,
            exclusive: false,
            trusted_keys: Vec::new(),
            pool_size: 4,
            fuel_per_request: 10_000_000,
            max_memory_bytes: 16 * 1024 * 1024,
            checkout_timeout_ms: 100,
            plugins: Vec::new(),
        }
    }
}

impl WasmSection {
    /// K6 enforcement predicate: `true` when `exclusive` is set AND the OPEN `[modules.wasm]` would
    /// load UNSIGNED plugins (which bypass the signature gate) → the boot must be refused.
    pub fn exclusive_conflict(&self, open: &waf_core::WasmConfig) -> bool {
        self.exclusive && open.enabled && !open.plugins.is_empty()
    }

    /// The runtime options shared by every plugin in this section.
    pub fn to_options(&self) -> WasmOptions {
        WasmOptions {
            pool_size: self.pool_size,
            fuel_per_request: self.fuel_per_request,
            max_memory_bytes: self.max_memory_bytes,
            checkout_timeout: Duration::from_millis(self.checkout_timeout_ms),
        }
    }
}

/// One `[[enterprise.wasm.plugins]]` entry: the `.wasm`, its detached `.minisig`, and an optional
/// plugin config string passed to the runtime.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct WasmPluginSection {
    pub wasm_path: String,
    pub sig_path: String,
    pub config: Option<String>,
}

/// `[enterprise.bot_detection]` — client-integrity / bot detection (§4-A). Default OFF. No file, no
/// Redis (native heuristics). v1 = browser-impersonation (S1): a UA advertising a modern browser
/// with no `sec-fetch-*` headers scores `browser_impersonation_severity`. Contributes to the same
/// cumulative anomaly score.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct BotDetectionSection {
    pub enabled: bool,
    pub browser_impersonation_severity: String,
}

impl Default for BotDetectionSection {
    fn default() -> Self {
        Self { enabled: false, browser_impersonation_severity: "critical".to_string() }
    }
}

impl BotDetectionSection {
    /// Build the module's [`BotDetectionConfig`], parsing the severity (rejecting unknown names).
    pub fn to_config(&self) -> Result<BotDetectionConfig, String> {
        Ok(BotDetectionConfig {
            enabled: self.enabled,
            browser_impersonation_severity: parse_severity(&self.browser_impersonation_severity)?,
        })
    }
}

/// `[enterprise.grpc_schema_enforcement]` — validates each unary gRPC message against the app's REAL
/// compiled schema (a `FileDescriptorSet` `.bin` from `protoc`/`buf`, §4-B part 2). Default OFF. No
/// Redis. Contributes to the same cumulative anomaly score. An unknown RPC method scores
/// `unknown_method_severity`; a message that won't decode scores `decode_error_severity`; a message
/// carrying fields not in the descriptor scores `unknown_field_severity` ONLY when
/// `flag_unknown_fields` (opt-in — protobuf tolerates unknown fields by design). `descriptor_path` is
/// required when enabled (boot-fatal if missing/invalid).
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct GrpcSchemaEnforcementSection {
    pub enabled: bool,
    /// Path to the app's compiled `FileDescriptorSet` (`.bin`).
    pub descriptor_path: String,
    /// Opt-in: flag messages carrying fields not in the descriptor (default off — forward-compat).
    pub flag_unknown_fields: bool,
    pub unknown_method_severity: String,
    pub decode_error_severity: String,
    pub unknown_field_severity: String,
}

impl Default for GrpcSchemaEnforcementSection {
    fn default() -> Self {
        Self {
            enabled: false,
            descriptor_path: String::new(),
            flag_unknown_fields: false,
            unknown_method_severity: "critical".to_string(),
            decode_error_severity: "warning".to_string(),
            unknown_field_severity: "notice".to_string(),
        }
    }
}

impl GrpcSchemaEnforcementSection {
    /// Build the module's [`GrpcSchemaEnforcementConfig`], parsing the severities (rejecting unknown
    /// names). The descriptor file is read later by `GrpcSchemaModule::from_config` (boot-fatal).
    pub fn to_config(&self) -> Result<GrpcSchemaEnforcementConfig, String> {
        Ok(GrpcSchemaEnforcementConfig {
            enabled: self.enabled,
            descriptor_path: PathBuf::from(&self.descriptor_path),
            flag_unknown_fields: self.flag_unknown_fields,
            unknown_method_severity: parse_severity(&self.unknown_method_severity)?,
            decode_error_severity: parse_severity(&self.decode_error_severity)?,
            unknown_field_severity: parse_severity(&self.unknown_field_severity)?,
        })
    }
}

/// `[enterprise.schema_enforcement]` — validates each GraphQL operation against the app's REAL SDL
/// schema (§4-B). Default OFF. No Redis (pure detection). Contributes to the same cumulative anomaly
/// score. A schema-invalid query scores `unknown_field_severity`; a non-GraphQL body scores the
/// lower `parse_error_severity`. `schema_path` is required when enabled (boot-fatal if missing).
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct SchemaEnforcementSection {
    pub enabled: bool,
    /// Path to the app's `.graphql` SDL schema file (loaded once at boot; no hot-reload in v1).
    pub schema_path: String,
    /// GraphQL endpoint path(s): the JSON/GET transports are inspected ONLY here (a non-GraphQL JSON
    /// API with a `query` field is left alone). The `application/graphql` body is caught on any path.
    pub paths: Vec<String>,
    /// Severity for a body that is not parseable as GraphQL (lower — broken client / generic probing).
    pub parse_error_severity: String,
    /// Severity for a syntactically valid query that violates the schema (Critical — targeted probing).
    pub unknown_field_severity: String,
}

impl Default for SchemaEnforcementSection {
    fn default() -> Self {
        Self {
            enabled: false,
            schema_path: String::new(),
            paths: vec!["/graphql".to_string()],
            parse_error_severity: "warning".to_string(),
            unknown_field_severity: "critical".to_string(),
        }
    }
}

impl SchemaEnforcementSection {
    /// Build the module's [`SchemaEnforcementConfig`], parsing the severities (rejecting unknown
    /// names). The schema file itself is read later by `GraphqlSchemaModule::from_config` (boot-fatal).
    pub fn to_config(&self) -> Result<SchemaEnforcementConfig, String> {
        Ok(SchemaEnforcementConfig {
            enabled: self.enabled,
            paths: self.paths.clone(),
            schema_path: PathBuf::from(&self.schema_path),
            parse_error_severity: parse_severity(&self.parse_error_severity)?,
            unknown_field_severity: parse_severity(&self.unknown_field_severity)?,
        })
    }
}

/// `[enterprise.api_schema]` — OpenAPI **positive-security** (§4-B part 3). Validates each REST/JSON
/// request under a guarded path prefix against the app's REAL OpenAPI spec (a JSON file — v1 is
/// JSON-only). Default OFF. No Redis (pure detection). Contributes to the same cumulative anomaly
/// score. An unknown route/method scores `unknown_route_severity`; a contract violation (param/body
/// shape) scores the lower `violation_severity`. `spec_path` is required when enabled (boot-fatal if
/// missing/invalid/uncompilable).
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ApiSchemaEnforcementSection {
    pub enabled: bool,
    /// Path to the app's OpenAPI 3.0/3.1 spec (JSON; loaded once at boot, no hot-reload in v1).
    pub spec_path: String,
    /// Path prefixes this module guards. A request outside them is left alone (non-API surfaces).
    pub paths: Vec<String>,
    /// Severity for a request to an endpoint/method the spec does not declare (targeted probing).
    pub unknown_route_severity: String,
    /// Severity for a request to a KNOWN operation that violates its contract (param/body shape).
    pub violation_severity: String,
    /// Flag query parameters not declared for the operation.
    pub strict_params: bool,
    /// Enforce `additionalProperties:false` on the request body even where the spec is silent.
    pub strict_body: bool,
}

impl Default for ApiSchemaEnforcementSection {
    fn default() -> Self {
        Self {
            enabled: false,
            spec_path: String::new(),
            paths: vec!["/api".to_string()],
            unknown_route_severity: "critical".to_string(),
            violation_severity: "warning".to_string(),
            strict_params: true,
            strict_body: true,
        }
    }
}

impl ApiSchemaEnforcementSection {
    /// Build the module's [`ApiSchemaEnforcementConfig`], parsing the severities (rejecting unknown
    /// names). The spec file itself is read + compiled later by `ApiSchemaModule::from_config`
    /// (boot-fatal).
    pub fn to_config(&self) -> Result<ApiSchemaEnforcementConfig, String> {
        Ok(ApiSchemaEnforcementConfig {
            enabled: self.enabled,
            paths: self.paths.clone(),
            spec_path: PathBuf::from(&self.spec_path),
            unknown_route_severity: parse_severity(&self.unknown_route_severity)?,
            violation_severity: parse_severity(&self.violation_severity)?,
            strict_params: self.strict_params,
            strict_body: self.strict_body,
        })
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
    fn reads_schema_enforcement_section_and_builds_config() {
        let toml = r#"
[proxy]
listen = "127.0.0.1:8080"
backend = "http://127.0.0.1:3000"
[waf]
mode = "blocking"
[enterprise.schema_enforcement]
enabled = true
schema_path = "/etc/waf/app.graphql"
paths = ["/graphql", "/api/graphql"]
parse_error_severity = "notice"
unknown_field_severity = "error"
"#;
        let f = EnterpriseFile::from_toml_str(toml).expect("parses");
        let se = &f.enterprise.schema_enforcement;
        assert!(se.enabled);
        let cfg = se.to_config().unwrap();
        assert!(cfg.enabled);
        assert_eq!(cfg.schema_path, PathBuf::from("/etc/waf/app.graphql"));
        assert_eq!(cfg.paths, vec!["/graphql".to_string(), "/api/graphql".to_string()]);
        assert_eq!(cfg.parse_error_severity, Severity::Notice);
        assert_eq!(cfg.unknown_field_severity, Severity::Error);
    }

    #[test]
    fn schema_enforcement_defaults_off_with_graphql_path_and_warning_critical() {
        let f = EnterpriseFile::from_toml_str(
            "[proxy]\nlisten=\"127.0.0.1:8080\"\nbackend=\"http://x:3000\"\n[waf]\nmode=\"blocking\"\n",
        )
        .expect("parses");
        let se = &f.enterprise.schema_enforcement;
        assert!(!se.enabled, "schema-enforcement default OFF");
        let cfg = se.to_config().unwrap();
        assert_eq!(cfg.paths, vec!["/graphql".to_string()]);
        assert_eq!(cfg.parse_error_severity, Severity::Warning);
        assert_eq!(cfg.unknown_field_severity, Severity::Critical);
    }

    #[test]
    fn schema_enforcement_unknown_severity_is_rejected() {
        let toml = r#"
[proxy]
listen = "127.0.0.1:8080"
backend = "http://127.0.0.1:3000"
[waf]
mode = "blocking"
[enterprise.schema_enforcement]
enabled = true
unknown_field_severity = "nope"
"#;
        let f = EnterpriseFile::from_toml_str(toml).expect("parses");
        assert!(f.enterprise.schema_enforcement.to_config().is_err());
    }

    #[test]
    fn reads_api_schema_section_and_builds_config() {
        let toml = r#"
[proxy]
listen = "127.0.0.1:8080"
backend = "http://127.0.0.1:3000"
[waf]
mode = "blocking"
[enterprise.api_schema]
enabled = true
spec_path = "/etc/waf/openapi.json"
paths = ["/api", "/v2"]
unknown_route_severity = "error"
violation_severity = "notice"
strict_params = false
strict_body = false
"#;
        let f = EnterpriseFile::from_toml_str(toml).expect("parses");
        let api = &f.enterprise.api_schema;
        assert!(api.enabled);
        let cfg = api.to_config().unwrap();
        assert_eq!(cfg.spec_path, PathBuf::from("/etc/waf/openapi.json"));
        assert_eq!(cfg.paths, vec!["/api".to_string(), "/v2".to_string()]);
        assert_eq!(cfg.unknown_route_severity, Severity::Error);
        assert_eq!(cfg.violation_severity, Severity::Notice);
        assert!(!cfg.strict_params);
        assert!(!cfg.strict_body);
    }

    #[test]
    fn api_schema_defaults_off_with_api_prefix_and_critical_warning() {
        let f = EnterpriseFile::from_toml_str(
            "[proxy]\nlisten=\"127.0.0.1:8080\"\nbackend=\"http://x:3000\"\n[waf]\nmode=\"blocking\"\n",
        )
        .expect("parses");
        let api = &f.enterprise.api_schema;
        assert!(!api.enabled, "api-schema default OFF");
        let cfg = api.to_config().unwrap();
        assert_eq!(cfg.paths, vec!["/api".to_string()]);
        assert_eq!(cfg.unknown_route_severity, Severity::Critical);
        assert_eq!(cfg.violation_severity, Severity::Warning);
        assert!(cfg.strict_params && cfg.strict_body);
    }

    #[test]
    fn api_schema_unknown_severity_is_rejected() {
        let toml = r#"
[proxy]
listen = "127.0.0.1:8080"
backend = "http://127.0.0.1:3000"
[waf]
mode = "blocking"
[enterprise.api_schema]
enabled = true
violation_severity = "nope"
"#;
        let f = EnterpriseFile::from_toml_str(toml).expect("parses");
        assert!(f.enterprise.api_schema.to_config().is_err());
    }

    #[test]
    fn reads_grpc_schema_enforcement_section_and_builds_config() {
        let toml = r#"
[proxy]
listen = "127.0.0.1:8080"
backend = "http://127.0.0.1:3000"
[waf]
mode = "blocking"
[enterprise.grpc_schema_enforcement]
enabled = true
descriptor_path = "/etc/waf/app.bin"
flag_unknown_fields = true
unknown_method_severity = "critical"
decode_error_severity = "error"
unknown_field_severity = "warning"
"#;
        let f = EnterpriseFile::from_toml_str(toml).expect("parses");
        let se = &f.enterprise.grpc_schema_enforcement;
        assert!(se.enabled);
        let cfg = se.to_config().unwrap();
        assert!(cfg.enabled);
        assert_eq!(cfg.descriptor_path, PathBuf::from("/etc/waf/app.bin"));
        assert!(cfg.flag_unknown_fields);
        assert_eq!(cfg.unknown_method_severity, Severity::Critical);
        assert_eq!(cfg.decode_error_severity, Severity::Error);
        assert_eq!(cfg.unknown_field_severity, Severity::Warning);
    }

    #[test]
    fn grpc_schema_enforcement_defaults_off_flag_off_critical_warning_notice() {
        let f = EnterpriseFile::from_toml_str(
            "[proxy]\nlisten=\"127.0.0.1:8080\"\nbackend=\"http://x:3000\"\n[waf]\nmode=\"blocking\"\n",
        )
        .expect("parses");
        let se = &f.enterprise.grpc_schema_enforcement;
        assert!(!se.enabled, "gRPC schema-enforcement default OFF");
        let cfg = se.to_config().unwrap();
        assert!(!cfg.flag_unknown_fields, "unknown-field flagging is opt-in");
        assert_eq!(cfg.unknown_method_severity, Severity::Critical);
        assert_eq!(cfg.decode_error_severity, Severity::Warning);
        assert_eq!(cfg.unknown_field_severity, Severity::Notice);
    }

    #[test]
    fn grpc_schema_enforcement_unknown_severity_is_rejected() {
        let toml = r#"
[proxy]
listen = "127.0.0.1:8080"
backend = "http://127.0.0.1:3000"
[waf]
mode = "blocking"
[enterprise.grpc_schema_enforcement]
enabled = true
unknown_method_severity = "nope"
"#;
        let f = EnterpriseFile::from_toml_str(toml).expect("parses");
        assert!(f.enterprise.grpc_schema_enforcement.to_config().is_err());
    }

    #[test]
    fn reads_bot_detection_section_and_builds_config() {
        let toml = r#"
[proxy]
listen = "127.0.0.1:8080"
backend = "http://127.0.0.1:3000"
[waf]
mode = "blocking"
[enterprise.bot_detection]
enabled = true
browser_impersonation_severity = "error"
"#;
        let f = EnterpriseFile::from_toml_str(toml).expect("parses");
        let bd = &f.enterprise.bot_detection;
        assert!(bd.enabled);
        let cfg = bd.to_config().unwrap();
        assert!(cfg.enabled);
        assert_eq!(cfg.browser_impersonation_severity, Severity::Error);
    }

    #[test]
    fn bot_detection_defaults_off_with_critical() {
        let f = EnterpriseFile::from_toml_str(
            "[proxy]\nlisten=\"127.0.0.1:8080\"\nbackend=\"http://x:3000\"\n[waf]\nmode=\"blocking\"\n",
        )
        .expect("parses");
        let bd = &f.enterprise.bot_detection;
        assert!(!bd.enabled, "bot-detection default OFF");
        assert_eq!(bd.to_config().unwrap().browser_impersonation_severity, Severity::Critical);
    }

    #[test]
    fn bot_detection_unknown_severity_is_rejected() {
        let toml = r#"
[proxy]
listen = "127.0.0.1:8080"
backend = "http://127.0.0.1:3000"
[waf]
mode = "blocking"
[enterprise.bot_detection]
enabled = true
browser_impersonation_severity = "nope"
"#;
        let f = EnterpriseFile::from_toml_str(toml).expect("parses");
        assert!(f.enterprise.bot_detection.to_config().is_err());
    }

    #[test]
    fn reads_wasm_section_with_plugins_keys_and_exclusive() {
        let toml = r#"
[proxy]
listen = "127.0.0.1:8080"
backend = "http://127.0.0.1:3000"
[waf]
mode = "blocking"
[enterprise.wasm]
enabled = true
exclusive = true
trusted_keys = ["RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3"]
pool_size = 8
fuel_per_request = 5000000
checkout_timeout_ms = 250
[[enterprise.wasm.plugins]]
wasm_path = "/etc/waf/denylist.wasm"
sig_path  = "/etc/waf/denylist.wasm.minisig"
config    = "block=/admin"
"#;
        let f = EnterpriseFile::from_toml_str(toml).expect("parses");
        let w = &f.enterprise.wasm;
        assert!(w.enabled);
        assert!(w.exclusive);
        assert_eq!(w.trusted_keys.len(), 1);
        assert_eq!(w.plugins.len(), 1);
        assert_eq!(w.plugins[0].wasm_path, "/etc/waf/denylist.wasm");
        assert_eq!(w.plugins[0].sig_path, "/etc/waf/denylist.wasm.minisig");
        assert_eq!(w.plugins[0].config.as_deref(), Some("block=/admin"));
        let opts = w.to_options();
        assert_eq!(opts.pool_size, 8);
        assert_eq!(opts.fuel_per_request, 5_000_000);
        assert_eq!(opts.checkout_timeout, Duration::from_millis(250));
    }

    #[test]
    fn exclusive_conflict_detects_unsigned_open_plugins() {
        use waf_core::{Config, WasmPluginConfig};
        let ent = WasmSection { exclusive: true, ..Default::default() };
        let mut open = Config::default();
        // No OPEN plugins → no conflict.
        assert!(!ent.exclusive_conflict(&open.modules.wasm));
        // OPEN [modules.wasm] loads a plugin → conflict (it would be unsigned).
        open.modules.wasm.enabled = true;
        open.modules.wasm.plugins = vec![WasmPluginConfig { path: "x.wasm".into(), config: None }];
        assert!(ent.exclusive_conflict(&open.modules.wasm));
        // Non-exclusive → never a conflict (coexistence allowed).
        let non_excl = WasmSection::default();
        assert!(!non_excl.exclusive_conflict(&open.modules.wasm));
    }

    #[test]
    fn wasm_section_defaults_off_and_non_exclusive() {
        let f = EnterpriseFile::from_toml_str(
            "[proxy]\nlisten=\"127.0.0.1:8080\"\nbackend=\"http://x:3000\"\n[waf]\nmode=\"blocking\"\n",
        )
        .expect("parses");
        let w = &f.enterprise.wasm;
        assert!(!w.enabled, "signed WASM loader default OFF");
        assert!(!w.exclusive, "exclusive default OFF (coexistence allowed)");
        assert!(w.trusted_keys.is_empty());
        assert!(w.plugins.is_empty());
        let opts = w.to_options();
        assert_eq!(opts.pool_size, 4);
        assert_eq!(opts.max_memory_bytes, 16 * 1024 * 1024);
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

    #[test]
    fn capture_defaults_off_and_raw() {
        let f = EnterpriseFile::from_toml_str(
            "[proxy]\nlisten=\"127.0.0.1:8080\"\nbackend=\"http://x:3000\"\n[waf]\nmode=\"blocking\"\n",
        )
        .expect("parses");
        let cap = &f.enterprise.capture;
        assert!(!cap.enabled, "request-capture default OFF");
        let cfg = cap.to_config().expect("disabled config always builds");
        assert!(!cfg.enabled);
        assert!(cfg.redaction.is_empty(), "default is raw capture");
        assert_eq!(cfg.token_env, "WAF_CAPTURE_TOKEN");
        assert_eq!(cfg.ring_ttl, Duration::from_secs(5));
    }

    #[test]
    fn reads_capture_section_with_redaction_and_builds_config() {
        let toml = r#"
[proxy]
listen = "127.0.0.1:8080"
backend = "http://127.0.0.1:3000"
[waf]
mode = "blocking"
[enterprise.capture]
enabled = true
controlplane_url = "http://controlplane:8080"
token_env = "MY_CAPTURE_TOKEN"
max_body_bytes = 131072
ring_capacity = 512
ring_bytes = 16777216
ring_ttl_ms = 3000
queue_capacity = 128
[enterprise.capture.redaction]
headers = ["Authorization", "Cookie"]
body_fields = ["password", "token"]
"#;
        let f = EnterpriseFile::from_toml_str(toml).expect("parses");
        let cfg = f.enterprise.capture.to_config().expect("builds");
        assert!(cfg.enabled);
        assert_eq!(cfg.controlplane_url, "http://controlplane:8080");
        assert_eq!(cfg.token_env, "MY_CAPTURE_TOKEN");
        assert_eq!(cfg.max_body_bytes, 131072);
        assert_eq!(cfg.ring_capacity, 512);
        assert_eq!(cfg.ring_bytes, 16_777_216);
        assert_eq!(cfg.ring_ttl, Duration::from_millis(3000));
        assert_eq!(cfg.queue_capacity, 128);
        assert!(cfg.redaction.header_redacted("authorization"));
        assert!(cfg.redaction.header_redacted("cookie"));
        assert!(cfg.redaction.field_redacted("PASSWORD"));
        assert!(!cfg.redaction.is_empty());
    }

    #[test]
    fn capture_enabled_without_url_is_rejected() {
        let toml = r#"
[proxy]
listen = "127.0.0.1:8080"
backend = "http://127.0.0.1:3000"
[waf]
mode = "blocking"
[enterprise.capture]
enabled = true
"#;
        let f = EnterpriseFile::from_toml_str(toml).expect("parses");
        assert!(
            f.enterprise.capture.to_config().is_err(),
            "enabled capture without controlplane_url must be boot-fatal"
        );
    }
}
