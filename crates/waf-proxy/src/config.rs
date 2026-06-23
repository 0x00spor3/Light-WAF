//! External configuration loading: path resolution + load → parse → validate.
//!
//! Precedence for the config path (most explicit/ephemeral first):
//!   1. CLI flag `--config <path>` / `--config=<path>` — per-invocation intent.
//!   2. env var `WAF_CONFIG` — deployment-level (container/systemd/CI).
//!   3. default `config.toml` — last resort.
//!
//! A missing file is ALWAYS fatal: a WAF must never start with implicit config
//! (empty trusted_proxies, rate limit off, untuned thresholds) — the
//! "looks-protected-but-isn't" failure mode. Errors print to stderr and the
//! process exits non-zero; we never start partially configured.
//!
//! `parse_and_validate` (parse + semantic `Config::validate`) is the fs/CLI-free
//! core, reused by hot reload (Pillar 3).

use std::path::{Path, PathBuf};

use waf_core::{Config, ConfigError};

pub const DEFAULT_CONFIG_PATH: &str = "config.toml";
pub const ENV_CONFIG: &str = "WAF_CONFIG";

/// Why loading the configuration failed. Each variant maps to a distinct
/// operator diagnosis (file vs syntax vs semantics).
#[derive(Debug)]
pub enum LoadError {
    /// The file does not exist — distinct from a present-but-wrong file.
    NotFound(PathBuf),
    /// The file exists but could not be read (permissions, etc.).
    Io { path: PathBuf, source: std::io::Error },
    /// TOML syntax error or a missing/incorrectly-typed required field
    /// (serde reports e.g. "missing field `backend`"). Boxed: `toml::de::Error`
    /// is large and would bloat every `Result` otherwise.
    Parse { path: PathBuf, source: Box<toml::de::Error> },
    /// Syntactically valid but semantically invalid (out-of-range, bad CIDR, …).
    Validation { path: PathBuf, source: ConfigError },
    /// A removed config key is still present — a clear migration error, never a
    /// silent no-op. Carries the offending key and the migration hint.
    RemovedKey { path: PathBuf, key: &'static str, hint: &'static str },
}

impl std::fmt::Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound(p) => write!(
                f,
                "config file not found at {}: provide --config <path>, set {ENV_CONFIG}, \
                 or create {DEFAULT_CONFIG_PATH}",
                p.display()
            ),
            Self::Io { path, source } =>
                write!(f, "cannot read config file {}: {source}", path.display()),
            Self::Parse { path, source } =>
                write!(f, "invalid config in {}: {source}", path.display()),
            Self::Validation { path, source } =>
                write!(f, "invalid config in {}: {source}", path.display()),
            Self::RemovedKey { path, key, hint } =>
                write!(f, "invalid config in {}: `{key}` has been removed — {hint}", path.display()),
        }
    }
}

impl std::error::Error for LoadError {}

/// Resolve the config path by precedence: CLI flag > env var > default.
/// `args` are the process args WITHOUT the program name; `env` is `WAF_CONFIG`.
pub fn resolve_path(args: &[String], env: Option<String>) -> PathBuf {
    if let Some(p) = cli_config(args) {
        return PathBuf::from(p);
    }
    if let Some(e) = env.filter(|s| !s.is_empty()) {
        return PathBuf::from(e);
    }
    PathBuf::from(DEFAULT_CONFIG_PATH)
}

/// Extract `--config <path>` or `--config=<path>` from the argument list.
fn cli_config(args: &[String]) -> Option<String> {
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        if let Some(value) = arg.strip_prefix("--config=") {
            return Some(value.to_string());
        }
        if arg == "--config" {
            return it.next().cloned();
        }
    }
    None
}

/// Parse + validate a TOML string. fs/CLI-free, so hot reload can reuse it.
pub fn parse_and_validate(text: &str, path: &Path) -> Result<Config, LoadError> {
    // Migration guard: `waf.fail_open` was removed in favour of [resilience].
    // Catch a leftover key explicitly (serde would otherwise ignore it silently).
    if let Ok(doc) = text.parse::<toml::Table>() {
        if doc.get("waf").and_then(|w| w.as_table()).is_some_and(|w| w.contains_key("fail_open")) {
            return Err(LoadError::RemovedKey {
                path: path.to_path_buf(),
                key: "waf.fail_open",
                hint: "configure failure behaviour via the [resilience] section",
            });
        }
    }

    let config: Config = toml::from_str(text).map_err(|source| LoadError::Parse {
        path: path.to_path_buf(),
        source: Box::new(source),
    })?;
    config.validate().map_err(|source| LoadError::Validation {
        path: path.to_path_buf(),
        source,
    })?;
    Ok(config)
}

/// Full load pipeline: read file (missing → fatal) → parse → validate.
pub fn load(path: &Path) -> Result<Config, LoadError> {
    let text = std::fs::read_to_string(path).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => LoadError::NotFound(path.to_path_buf()),
        _ => LoadError::Io { path: path.to_path_buf(), source: e },
    })?;
    parse_and_validate(&text, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    // ── path precedence ────────────────────────────────────────────────────────

    #[test]
    fn cli_flag_wins_over_env_and_default() {
        let p = resolve_path(&args(&["--config", "cli.toml"]), Some("env.toml".to_string()));
        assert_eq!(p, PathBuf::from("cli.toml"));
    }

    #[test]
    fn cli_equals_form_supported() {
        let p = resolve_path(&args(&["--config=cli.toml"]), Some("env.toml".to_string()));
        assert_eq!(p, PathBuf::from("cli.toml"));
    }

    #[test]
    fn env_wins_over_default_when_no_cli() {
        let p = resolve_path(&args(&[]), Some("env.toml".to_string()));
        assert_eq!(p, PathBuf::from("env.toml"));
    }

    #[test]
    fn default_when_no_cli_no_env() {
        let p = resolve_path(&args(&[]), None);
        assert_eq!(p, PathBuf::from(DEFAULT_CONFIG_PATH));
        // Empty env var is treated as unset.
        let p2 = resolve_path(&args(&[]), Some(String::new()));
        assert_eq!(p2, PathBuf::from(DEFAULT_CONFIG_PATH));
    }

    // ── load errors ─────────────────────────────────────────────────────────────

    fn unique_tmp(name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        p.push(format!("waf-cfg-{name}-{nanos}.toml"));
        p
    }

    const VALID_TOML: &str = r#"
[proxy]
listen = "127.0.0.1:8080"
backend = "http://localhost:3000"

[waf]
mode = "detection-only"
"#;

    #[test]
    fn missing_file_is_not_found() {
        let path = unique_tmp("missing");
        assert!(matches!(load(&path), Err(LoadError::NotFound(_))));
    }

    #[test]
    fn valid_file_loads() {
        let path = unique_tmp("valid");
        std::fs::write(&path, VALID_TOML).unwrap();
        let cfg = load(&path).expect("should load");
        assert_eq!(cfg.proxy.backend, "http://localhost:3000");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn malformed_toml_is_parse_error() {
        let path = unique_tmp("malformed");
        std::fs::write(&path, "this is = = not valid toml [[[").unwrap();
        assert!(matches!(load(&path), Err(LoadError::Parse { .. })));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn missing_required_field_is_parse_error_not_not_found() {
        // File present but `backend` missing → serde "missing field", a Parse
        // error, diagnostically distinct from a missing file.
        let path = unique_tmp("missing-field");
        std::fs::write(&path, "[proxy]\nlisten = \"127.0.0.1:8080\"\n[waf]\n").unwrap();
        assert!(matches!(load(&path), Err(LoadError::Parse { .. })));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn removed_fail_open_key_is_clear_migration_error() {
        let path = unique_tmp("legacy-fail-open");
        let toml = format!("{VALID_TOML}fail_open = true\n");
        std::fs::write(&path, toml).unwrap();
        match load(&path) {
            Err(LoadError::RemovedKey { key: "waf.fail_open", .. }) => {}
            other => panic!("expected RemovedKey for waf.fail_open, got {other:?}"),
        }
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn semantically_invalid_is_validation_error() {
        let path = unique_tmp("bad-value");
        let toml = format!("{VALID_TOML}\n[network]\ntrusted_hops = 99\n");
        std::fs::write(&path, toml).unwrap();
        match load(&path) {
            Err(LoadError::Validation { source: ConfigError::TrustedHopsOutOfRange(99), .. }) => {}
            other => panic!("expected TrustedHopsOutOfRange, got {other:?}"),
        }
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn illegal_cidr_is_validation_error() {
        let path = unique_tmp("bad-cidr");
        let toml = format!("{VALID_TOML}\n[network]\ntrusted_proxies = [\"10.0.0.0/8\", \"nonsense\"]\n");
        std::fs::write(&path, toml).unwrap();
        assert!(matches!(
            load(&path),
            Err(LoadError::Validation { source: ConfigError::InvalidCidr(_), .. })
        ));
        std::fs::remove_file(&path).ok();
    }
}
