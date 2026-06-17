use std::net::IpAddr;
use std::time::SystemTime;

use serde::Deserialize;

pub use bytes::Bytes;

pub mod network;
pub use network::{ClientIpResolver, IpSource, ResolvedClientIp};

// ── Decision / Phase / Module contract ───────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Block { rule_id: String, reason: String },
    Monitor { rule_id: String },
    /// A single contribution with explicit points — used for high-confidence
    /// rules or direct scoring where the module already knows the weight.
    Score { rule_id: String, points: u32 },
    /// Multiple contributions, one per matched rule, each carrying a severity.
    /// The pipeline resolves `severity -> points` via `[waf.severity_scores]`,
    /// so the cumulative anomaly score (CRS-style) sums every matched rule —
    /// three Notice matches weigh more than one.
    Scores(Vec<ScoreItem>),
    /// Direct rejection with an explicit HTTP status — distinct from `Block`
    /// (which is the 403 anomaly/high-confidence path). Used by rate limiting to
    /// return 429 with an optional `Retry-After` (seconds). In detection-only the
    /// pipeline logs it but does not reject.
    Reject {
        rule_id: String,
        reason: String,
        status: u16,
        retry_after: Option<u64>,
    },
}

/// One severity-tagged contribution emitted inside `Decision::Scores`.
/// The module reports *what* it found (`rule_id` + `severity`); the pipeline
/// owns the `severity -> points` policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScoreItem {
    pub rule_id: String,
    pub severity: Severity,
}

/// Rule severity classes (CRS-inspired). The numeric weight of each class is
/// configurable via `[waf.severity_scores]`, never hardcoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Severity {
    Critical,
    Error,
    Warning,
    Notice,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Phase {
    Connection,
    RequestLine,
    Headers,
    Body,
    Response,
}

pub trait WafModule: Send + Sync {
    fn id(&self) -> &str;
    fn phase(&self) -> Phase;
    /// Called once at startup; compile/init rules here, never in `inspect`.
    fn init(&mut self, cfg: &Config);
    /// Read-only access to context; pipeline owns mutation of `score`.
    fn inspect(&self, ctx: &RequestContext) -> Decision;
}

// ── Config ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub proxy: ProxyConfig,
    pub waf: WafConfig,
    #[serde(default)]
    pub limits: LimitsConfig,
    #[serde(default)]
    pub modules: ModulesConfig,
    #[serde(default)]
    pub rate_limit: RateLimitConfig,
    /// Shared network settings (trusted-proxy client-IP resolution). Reused by
    /// rate limiting, structured logging and future Geo/IP-reputation.
    #[serde(default)]
    pub network: NetworkConfig,
    /// Per-scenario behaviour when the WAF itself is in trouble.
    #[serde(default)]
    pub resilience: ResilienceConfig,
}

// ── Resilience (fail-open / fail-closed, per scenario) ─────────────────────────

/// What to do when a given failure scenario occurs. Uniform across scenarios for
/// schema consistency, but the *meaning* of `FailOpen` is scenario-specific — see
/// `ResilienceConfig` and ARCHITECTURE §9.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailMode {
    /// Favour availability.
    FailOpen,
    /// Favour security / surface the error.
    FailClosed,
}

/// Explicit, per-scenario failure policy. No single global boolean: each kind of
/// trouble has its own correct posture (see the defaults' rationale in §9).
#[derive(Debug, Clone, Copy, Deserialize)]
pub struct ResilienceConfig {
    /// Origin unreachable / timeout. `fail_closed` → 502, `fail_open` → 503
    /// (retryable). NB: `fail_open` here does NOT mean "let traffic through"
    /// (there is no origin to reach) — only which 5xx is returned.
    #[serde(default = "default_on_upstream_error")]
    pub on_upstream_error: FailMode,
    /// Module panic / regex blow-up. `fail_open` → skip the module and continue
    /// (a WAF bug must not take down the site); `fail_closed` → synthetic block.
    #[serde(default = "default_on_internal_error")]
    pub on_internal_error: FailMode,
    /// Invalid config detected at runtime (hot reload, Pillar 3). `fail_open` →
    /// keep last-good config; `fail_closed` → refuse serving until valid.
    #[serde(default = "default_on_config_error")]
    pub on_config_error: FailMode,
    /// Normalization failed (limits exceeded / malformed input). `fail_closed` →
    /// 400; `fail_open` → forward UNINSPECTED (logged loudly).
    #[serde(default = "default_on_parser_limit")]
    pub on_parser_limit: FailMode,
    /// Hard cap on the upstream round-trip so a stalled origin cannot pin the
    /// worker. Must be >= 1 (validated).
    #[serde(default = "default_upstream_timeout_ms")]
    pub upstream_timeout_ms: u64,
}

fn default_on_upstream_error() -> FailMode { FailMode::FailClosed }
fn default_on_internal_error() -> FailMode { FailMode::FailOpen }
fn default_on_config_error() -> FailMode { FailMode::FailOpen }
fn default_on_parser_limit() -> FailMode { FailMode::FailClosed }
fn default_upstream_timeout_ms() -> u64 { 30_000 }

impl Default for ResilienceConfig {
    fn default() -> Self {
        Self {
            on_upstream_error: default_on_upstream_error(),
            on_internal_error: default_on_internal_error(),
            on_config_error: default_on_config_error(),
            on_parser_limit: default_on_parser_limit(),
            upstream_timeout_ms: default_upstream_timeout_ms(),
        }
    }
}

impl ResilienceConfig {
    /// Upstream round-trip cap as a `Duration`.
    pub fn upstream_timeout(&self) -> std::time::Duration {
        std::time::Duration::from_millis(self.upstream_timeout_ms)
    }
}

// ── Network (shared client-IP resolution) ─────────────────────────────────────

/// Trusted-proxy configuration for resolving the real client IP behind an
/// LB/CDN/TLS-terminator. See `network::ClientIpResolver` for the logic.
#[derive(Debug, Clone, Deserialize)]
pub struct NetworkConfig {
    /// CIDR blocks of YOUR proxies (IPv4 or IPv6). Empty (default) = fail-safe:
    /// the forwarded header is ALWAYS ignored and the peer address is used.
    #[serde(default)]
    pub trusted_proxies: Vec<String>,
    /// Header carrying the forwarded chain (default `x-forwarded-for`).
    #[serde(default = "default_client_ip_header")]
    pub client_ip_header: String,
    /// How many hops, counted from the RIGHT of the chain, to trust. Never the
    /// leftmost IP (that one is client-controlled and spoofable).
    #[serde(default = "default_trusted_hops")]
    pub trusted_hops: usize,
}

fn default_client_ip_header() -> String { "x-forwarded-for".to_string() }
fn default_trusted_hops() -> usize { 1 }

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            trusted_proxies: Vec::new(),
            client_ip_header: default_client_ip_header(),
            trusted_hops: default_trusted_hops(),
        }
    }
}

// ── Semantic validation (reusable by startup load AND hot reload) ──────────────

/// Highest paranoia level the contract allows. The validator guards the legal
/// space of the CONTRACT (see ARCHITECTURE §7), not the current rule set — PL4 is
/// forward-compatible even if no rule uses it yet.
pub const MAX_PARANOIA_LEVEL: u8 = 4;
/// Upper bound on `trusted_hops`: real proxy chains are short; a huge value is a
/// configuration mistake (and would make every request fall back to the peer).
pub const MAX_TRUSTED_HOPS: usize = 10;

/// A semantic configuration error. Distinct from TOML *syntax* errors (handled at
/// parse time) and from I/O errors (file missing/unreadable).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    InvalidBackend(String),
    BlockThresholdZero,
    ParanoiaOutOfRange(u8),
    SeverityWeightZero(&'static str),
    LimitZero(&'static str),
    RateLimitValueZero(&'static str),
    TrustedHopsOutOfRange(usize),
    InvalidCidr(String),
    EmptyClientIpHeader,
    ResilienceTimeoutZero,
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidBackend(b) => write!(
                f,
                "proxy.backend must be an absolute http(s) URL with a host, got {b:?}"
            ),
            Self::BlockThresholdZero =>
                write!(f, "waf.block_threshold must be >= 1 (0 would block everything)"),
            Self::ParanoiaOutOfRange(p) =>
                write!(f, "waf.paranoia_level must be in 1..={MAX_PARANOIA_LEVEL}, got {p}"),
            Self::SeverityWeightZero(name) =>
                write!(f, "waf.severity_scores.{name} must be >= 1 (a 0 weight makes the rule contribute nothing)"),
            Self::LimitZero(name) =>
                write!(f, "limits.{name} must be >= 1"),
            Self::RateLimitValueZero(name) =>
                write!(f, "rate_limit.{name} must be >= 1 when rate limiting is enabled"),
            Self::TrustedHopsOutOfRange(h) =>
                write!(f, "network.trusted_hops must be in 1..={MAX_TRUSTED_HOPS}, got {h}"),
            Self::InvalidCidr(c) =>
                write!(f, "network.trusted_proxies contains an invalid CIDR: {c:?}"),
            Self::EmptyClientIpHeader =>
                write!(f, "network.client_ip_header must not be empty"),
            Self::ResilienceTimeoutZero =>
                write!(f, "resilience.upstream_timeout_ms must be >= 1"),
        }
    }
}

impl std::error::Error for ConfigError {}

impl Config {
    /// Semantic validation, separate from TOML parsing. Called at startup (after
    /// parse, before build) and reused by hot reload. Fails fast with a specific
    /// error rather than starting with values that look valid but aren't.
    pub fn validate(&self) -> Result<(), ConfigError> {
        // proxy.backend: absolute http(s) URL with a non-empty authority.
        let backend = self.proxy.backend.trim();
        let authority = backend
            .strip_prefix("http://")
            .or_else(|| backend.strip_prefix("https://"));
        match authority {
            Some(a) if !a.is_empty() && !a.starts_with('/') => {}
            _ => return Err(ConfigError::InvalidBackend(self.proxy.backend.clone())),
        }

        // waf scoring knobs.
        if self.waf.block_threshold == 0 {
            return Err(ConfigError::BlockThresholdZero);
        }
        if !(1..=MAX_PARANOIA_LEVEL).contains(&self.waf.paranoia_level) {
            return Err(ConfigError::ParanoiaOutOfRange(self.waf.paranoia_level));
        }
        let s = &self.waf.severity_scores;
        for (name, v) in [
            ("critical", s.critical),
            ("error", s.error),
            ("warning", s.warning),
            ("notice", s.notice),
        ] {
            if v == 0 {
                return Err(ConfigError::SeverityWeightZero(name));
            }
        }

        // Defensive limits: a 0 breaks parsing/inspection.
        let l = &self.limits;
        for (name, v) in [
            ("max_body_size", l.max_body_size),
            ("max_header_size", l.max_header_size),
            ("max_headers", l.max_headers),
            ("max_params", l.max_params),
            ("max_cookies", l.max_cookies),
            ("max_json_depth", l.max_json_depth),
        ] {
            if v == 0 {
                return Err(ConfigError::LimitZero(name));
            }
        }

        // Rate limiting: only meaningful when enabled.
        if self.rate_limit.enabled {
            let r = &self.rate_limit;
            if r.requests == 0 {
                return Err(ConfigError::RateLimitValueZero("requests"));
            }
            if r.window_seconds == 0 {
                return Err(ConfigError::RateLimitValueZero("window_seconds"));
            }
            if matches!(r.burst, Some(0)) {
                return Err(ConfigError::RateLimitValueZero("burst"));
            }
            if r.max_tracked_keys == 0 {
                return Err(ConfigError::RateLimitValueZero("max_tracked_keys"));
            }
            if r.action == RateLimitAction::Score && r.score == 0 {
                return Err(ConfigError::RateLimitValueZero("score"));
            }
        }

        // Network / client-IP resolution.
        if !(1..=MAX_TRUSTED_HOPS).contains(&self.network.trusted_hops) {
            return Err(ConfigError::TrustedHopsOutOfRange(self.network.trusted_hops));
        }
        for cidr in &self.network.trusted_proxies {
            if !network::is_valid_cidr(cidr) {
                return Err(ConfigError::InvalidCidr(cidr.clone()));
            }
        }
        if self.network.client_ip_header.trim().is_empty() {
            return Err(ConfigError::EmptyClientIpHeader);
        }

        // Resilience.
        if self.resilience.upstream_timeout_ms == 0 {
            return Err(ConfigError::ResilienceTimeoutZero);
        }

        Ok(())
    }
}

// ── Rate limiting (L7, on_connection) ─────────────────────────────────────────

/// Which request attribute the rate limiter buckets on. `client_ip` is the peer
/// socket address; behind an LB/CDN this collapses to the proxy IP — see §8.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum RateLimitKey {
    #[default]
    ClientIp,
}

/// What happens when a key exceeds its budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum RateLimitAction {
    /// Reject immediately with HTTP 429 (`Decision::Reject`).
    #[default]
    Block,
    /// Contribute `score` points to the cumulative anomaly score instead.
    Score,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RateLimitConfig {
    /// Off when the `[rate_limit]` section is absent (fail-safe default).
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub key: RateLimitKey,
    /// Token refill budget per window (tokens added per `window_seconds`).
    #[serde(default = "default_rl_requests")]
    pub requests: u32,
    #[serde(default = "default_rl_window")]
    pub window_seconds: u64,
    /// Bucket capacity (max burst). Defaults to `requests` when omitted.
    #[serde(default)]
    pub burst: Option<u32>,
    #[serde(default)]
    pub action: RateLimitAction,
    /// Points added when `action = "score"` and the budget is exceeded.
    #[serde(default = "default_rl_score")]
    pub score: u32,
    /// Memory cap: when the tracked-key map reaches this size, idle (fully
    /// refilled) buckets are swept before inserting a new key.
    #[serde(default = "default_rl_max_keys")]
    pub max_tracked_keys: usize,
}

fn default_rl_requests() -> u32 { 100 }
fn default_rl_window() -> u64 { 60 }
fn default_rl_score() -> u32 { 5 }
fn default_rl_max_keys() -> usize { 100_000 }

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            key: RateLimitKey::ClientIp,
            requests: default_rl_requests(),
            window_seconds: default_rl_window(),
            burst: None,
            action: RateLimitAction::Block,
            score: default_rl_score(),
            max_tracked_keys: default_rl_max_keys(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct ModulesConfig {
    #[serde(default)]
    pub sqli: ModuleConfig,
    #[serde(default)]
    pub xss: ModuleConfig,
    #[serde(default)]
    pub path_traversal: ModuleConfig,
    #[serde(default)]
    pub rce: ModuleConfig,
    #[serde(default)]
    pub lfi_rfi: ModuleConfig,
    #[serde(default)]
    pub ssrf: ModuleConfig,
    #[serde(default)]
    pub header_injection: ModuleConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ModuleConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_true() -> bool { true }

impl Default for ModuleConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
}

/// Points assigned to each severity class. Replaces per-module hardcoded scores;
/// changing these values directly changes how much each match contributes.
#[derive(Debug, Clone, Copy, Deserialize)]
pub struct SeverityScores {
    #[serde(default = "default_critical_score")]
    pub critical: u32,
    #[serde(default = "default_error_score")]
    pub error: u32,
    #[serde(default = "default_warning_score")]
    pub warning: u32,
    #[serde(default = "default_notice_score")]
    pub notice: u32,
}

fn default_critical_score() -> u32 { 5 }
fn default_error_score() -> u32 { 4 }
fn default_warning_score() -> u32 { 3 }
fn default_notice_score() -> u32 { 2 }

impl Default for SeverityScores {
    fn default() -> Self {
        Self {
            critical: default_critical_score(),
            error: default_error_score(),
            warning: default_warning_score(),
            notice: default_notice_score(),
        }
    }
}

impl SeverityScores {
    /// Resolve a severity class to its configured point weight.
    pub fn points_for(&self, severity: Severity) -> u32 {
        match severity {
            Severity::Critical => self.critical,
            Severity::Error => self.error,
            Severity::Warning => self.warning,
            Severity::Notice => self.notice,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ProxyConfig {
    pub listen: std::net::SocketAddr,
    pub backend: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct WafConfig {
    pub mode: WafMode,
    // NOTE: the old `fail_open: bool` was removed in favour of the per-scenario
    // `[resilience]` section. A leftover `waf.fail_open` in TOML is rejected with
    // a migration hint at load time (see waf-proxy::config), never silently.
    #[serde(default = "default_block_threshold")]
    pub block_threshold: u32,
    /// Paranoia level (1..=4). Higher levels activate more (and noisier) rules.
    #[serde(default = "default_paranoia_level")]
    pub paranoia_level: u8,
    /// Point weight per severity class. Used by the pipeline to score matches.
    #[serde(default)]
    pub severity_scores: SeverityScores,
}

fn default_block_threshold() -> u32 {
    5
}

fn default_paranoia_level() -> u8 {
    1
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WafMode {
    DetectionOnly,
    Blocking,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LimitsConfig {
    #[serde(default = "default_max_body_size")]
    pub max_body_size: usize,
    #[serde(default = "default_max_header_size")]
    pub max_header_size: usize,
    #[serde(default = "default_max_headers")]
    pub max_headers: usize,
    #[serde(default = "default_max_params")]
    pub max_params: usize,
    #[serde(default = "default_max_cookies")]
    pub max_cookies: usize,
    #[serde(default = "default_max_json_depth")]
    pub max_json_depth: usize,
}

fn default_max_body_size() -> usize { 1_048_576 } // 1 MiB
fn default_max_header_size() -> usize { 8_192 }   // 8 KiB
fn default_max_headers() -> usize { 100 }
fn default_max_params() -> usize { 100 }
fn default_max_cookies() -> usize { 50 }
fn default_max_json_depth() -> usize { 20 }

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_body_size: default_max_body_size(),
            max_header_size: default_max_header_size(),
            max_headers: default_max_headers(),
            max_params: default_max_params(),
            max_cookies: default_max_cookies(),
            max_json_depth: default_max_json_depth(),
        }
    }
}

// ── Parsed / Normalized types ─────────────────────────────────────────────────

/// Parsed body, populated by the normalizer based on Content-Type.
#[derive(Debug, Clone, Default)]
pub enum ParsedBody {
    #[default]
    None,
    FormUrlEncoded(Vec<(String, String)>),
    Multipart(Vec<MultipartField>),
    /// JSON flattened to (dot-path, string-value) pairs for pattern inspection.
    JsonFlattened(Vec<(String, String)>),
    Raw(Bytes),
}

#[derive(Debug, Clone)]
pub struct MultipartField {
    pub name: String,
    pub filename: Option<String>,
    pub content_type: Option<String>,
    pub data: Bytes,
}

/// Canonicalized version of all inspectable fields.
/// Populated by the normalizer before any detection module runs.
/// Raw originals remain in RequestContext fields.
#[derive(Debug, Clone, Default)]
pub struct Normalized {
    /// URL-decoded, traversal-resolved, lowercased path.
    pub path: String,
    /// URL-decoded query string (raw, single decode).
    pub query: Option<String>,
    /// Parsed, decoded query parameters — repeated names are all kept.
    pub query_params: Vec<(String, String)>,
    /// Parsed cookies (from Cookie headers).
    pub cookies: Vec<(String, String)>,
    /// Header names lowercased, values trimmed.
    pub headers: Vec<(String, String)>,
    pub body: ParsedBody,
    /// True when any field had a percent-encoded sequence that decoded to another percent-encoded sequence.
    pub double_encoding_detected: bool,
}

// ── Scoring audit ───────────────────────────────────────────────────────────

/// One recorded contribution to the anomaly score, kept for audit/logging.
/// Populated exclusively by the pipeline as it accumulates `ctx.score`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScoreContribution {
    /// Id of the module that produced the contribution.
    pub module: String,
    /// Id of the rule that matched.
    pub rule_id: String,
    /// Severity class, when the contribution came from `Decision::Scores`.
    /// `None` for direct `Decision::Score` contributions.
    pub severity: Option<Severity>,
    /// Points actually added to `ctx.score`.
    pub points: u32,
}

// ── RequestContext ────────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct RequestContext {
    // Identity
    pub client_ip: IpAddr,
    pub request_id: String,
    pub timestamp: SystemTime,
    // Request line (raw)
    pub method: String,
    pub path: String,
    pub raw_path: String,
    pub query: Option<String>,
    pub http_version: String,
    // Headers & cookies (raw, as received)
    pub headers: Vec<(String, String)>,
    pub cookies: Vec<(String, String)>,
    // Body bytes (collected before pipeline; streaming deferred to Fase 4+)
    pub body: Bytes,
    // Canonical forms — populated by the normalizer, read by detection modules
    pub normalized: Normalized,
    // Anomaly score accumulated across modules
    pub score: u32,
    // Per-rule breakdown of how `score` was reached (filled by the pipeline)
    pub score_contributions: Vec<ScoreContribution>,
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod config_validation_tests {
    use super::*;

    fn valid() -> Config {
        Config {
            proxy: ProxyConfig {
                listen: "127.0.0.1:8080".parse().unwrap(),
                backend: "http://localhost:3000".to_string(),
            },
            waf: WafConfig {
                mode: WafMode::Blocking,
                block_threshold: 5,
                paranoia_level: 2,
                severity_scores: SeverityScores::default(),
            },
            limits: LimitsConfig::default(),
            modules: ModulesConfig::default(),
            rate_limit: RateLimitConfig::default(),
            network: NetworkConfig::default(),
            resilience: ResilienceConfig::default(),
        }
    }

    #[test]
    fn valid_config_passes() {
        assert!(valid().validate().is_ok());
    }

    #[test]
    fn paranoia_4_is_legal_forward_compatible() {
        let mut c = valid();
        c.waf.paranoia_level = MAX_PARANOIA_LEVEL; // 4: empty-but-legal
        assert!(c.validate().is_ok());
    }

    #[test]
    fn paranoia_out_of_range_rejected() {
        let mut c = valid();
        c.waf.paranoia_level = 0;
        assert_eq!(c.validate(), Err(ConfigError::ParanoiaOutOfRange(0)));
        c.waf.paranoia_level = 5;
        assert_eq!(c.validate(), Err(ConfigError::ParanoiaOutOfRange(5)));
    }

    #[test]
    fn block_threshold_zero_rejected() {
        let mut c = valid();
        c.waf.block_threshold = 0;
        assert_eq!(c.validate(), Err(ConfigError::BlockThresholdZero));
    }

    #[test]
    fn zero_severity_weight_rejected() {
        let mut c = valid();
        c.waf.severity_scores.warning = 0;
        assert_eq!(c.validate(), Err(ConfigError::SeverityWeightZero("warning")));
    }

    #[test]
    fn zero_limit_rejected() {
        let mut c = valid();
        c.limits.max_json_depth = 0;
        assert_eq!(c.validate(), Err(ConfigError::LimitZero("max_json_depth")));
    }

    #[test]
    fn invalid_backend_rejected() {
        let mut c = valid();
        c.proxy.backend = "localhost:3000".to_string(); // no scheme
        assert!(matches!(c.validate(), Err(ConfigError::InvalidBackend(_))));
        c.proxy.backend = "http://".to_string(); // no authority
        assert!(matches!(c.validate(), Err(ConfigError::InvalidBackend(_))));
    }

    #[test]
    fn rate_limit_values_checked_only_when_enabled() {
        let mut c = valid();
        // Disabled: bad values are tolerated (dead config), not a startup error.
        c.rate_limit.enabled = false;
        c.rate_limit.requests = 0;
        assert!(c.validate().is_ok());
        // Enabled: the same bad value is rejected.
        c.rate_limit.enabled = true;
        assert_eq!(c.validate(), Err(ConfigError::RateLimitValueZero("requests")));
    }

    #[test]
    fn rate_limit_score_action_requires_positive_score() {
        let mut c = valid();
        c.rate_limit.enabled = true;
        c.rate_limit.action = RateLimitAction::Score;
        c.rate_limit.score = 0;
        assert_eq!(c.validate(), Err(ConfigError::RateLimitValueZero("score")));
    }

    #[test]
    fn trusted_hops_out_of_range_rejected() {
        let mut c = valid();
        c.network.trusted_hops = 0;
        assert_eq!(c.validate(), Err(ConfigError::TrustedHopsOutOfRange(0)));
        c.network.trusted_hops = MAX_TRUSTED_HOPS + 1;
        assert_eq!(
            c.validate(),
            Err(ConfigError::TrustedHopsOutOfRange(MAX_TRUSTED_HOPS + 1))
        );
    }

    #[test]
    fn invalid_cidr_in_trusted_proxies_rejected() {
        let mut c = valid();
        c.network.trusted_proxies = vec!["10.0.0.0/8".to_string(), "999.0.0.0/8".to_string()];
        assert_eq!(
            c.validate(),
            Err(ConfigError::InvalidCidr("999.0.0.0/8".to_string()))
        );
    }

    #[test]
    fn valid_cidrs_pass() {
        let mut c = valid();
        c.network.trusted_proxies = vec!["10.0.0.0/8".to_string(), "::1".to_string()];
        assert!(c.validate().is_ok());
    }

    #[test]
    fn empty_client_ip_header_rejected() {
        let mut c = valid();
        c.network.client_ip_header = "   ".to_string();
        assert_eq!(c.validate(), Err(ConfigError::EmptyClientIpHeader));
    }

    #[test]
    fn zero_upstream_timeout_rejected() {
        let mut c = valid();
        c.resilience.upstream_timeout_ms = 0;
        assert_eq!(c.validate(), Err(ConfigError::ResilienceTimeoutZero));
    }

    #[test]
    fn resilience_defaults_match_documented_posture() {
        let r = ResilienceConfig::default();
        assert_eq!(r.on_internal_error, FailMode::FailOpen);
        assert_eq!(r.on_upstream_error, FailMode::FailClosed);
        assert_eq!(r.on_config_error, FailMode::FailOpen);
        assert_eq!(r.on_parser_limit, FailMode::FailClosed);
    }
}
