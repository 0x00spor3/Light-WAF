// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

//! The threat-intel **feed** (ARCHITECTURE_ENTERPRISE §6): the write side that *populates* the
//! `rep:<ip>` keyspace the [`ReputationModule`](crate::ReputationModule) reads. A [`ReputationFeed`]
//! is a source of `(ip, verdict)` entries; the driver ([`crate::start_reputation_feed`]) polls the
//! sources on an interval and publishes a snapshot via [`ReputationWriter`](waf_state_redis::ReputationWriter).
//!
//! ## Frozen decisions this module encodes
//! - **F5 — verdict is per-SOURCE, not per-entry**: the remote content says WHICH ips are listed,
//!   never HOW severe. Point a blocklist at a `Malicious` source and a greylist at a `Suspicious`
//!   one. Commercial subscription APIs are a follow-on behind this same trait (mirrors how
//!   `DnsProvider` grew Cloudflare/Route53).
//! - **F3 — exact IPs only**: the read is `GET rep:<exact-ip>`, so a CIDR range cannot match
//!   without changing the (frozen) lookup shape. CIDR lines are skipped with a warn, declared a
//!   follow-on.

use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use tokio_rustls::rustls::crypto::ring;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tracing::warn;
use waf_state_redis::Reputation;

/// Why a feed fetch failed. The driver treats any error as "keep the previous snapshot"
/// (fail-to-no-opinion): a down feed must neither block nor unblock — entries just age out.
#[derive(Debug)]
pub enum FeedError {
    /// Local file could not be read.
    Io(String),
    /// HTTP request/response failure (network, non-2xx, body decode).
    Http(String),
    /// The source could not be constructed (e.g. the TLS client config).
    Config(String),
}

impl std::fmt::Display for FeedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "feed file read error: {e}"),
            Self::Http(e) => write!(f, "feed HTTP error: {e}"),
            Self::Config(e) => write!(f, "feed config error: {e}"),
        }
    }
}
impl std::error::Error for FeedError {}

/// A source of IP-reputation entries. Object-safe (async via `async_trait`) so the driver can hold
/// a `Vec<Box<dyn ReputationFeed>>` of heterogeneous sources.
#[async_trait]
// `async_trait` emits `#[must_use]` on the generated methods, whose `Pin<Box<dyn Future>>` return is
// already must-use; clippy ≥ 1.99 flags that macro output. Nothing is lost: the future stays must-use.
#[allow(clippy::double_must_use)]
pub trait ReputationFeed: Send + Sync {
    /// Short label for logs (e.g. the file path or URL).
    fn name(&self) -> &str;
    /// Fetch the current list of `(ip, verdict)` entries. An `Err` is the driver's cue to keep the
    /// previous snapshot, never to clear it.
    async fn fetch(&self) -> Result<Vec<(IpAddr, Reputation)>, FeedError>;
}

/// Parse a plaintext IP list — **one IP per line** — into `(ip, verdict)` entries, assigning the
/// source's fixed `verdict` to every IP (F5). Robust to the shapes real blocklists use:
/// - blank lines and `#` comments (whole-line or trailing) are skipped;
/// - the first whitespace token of a line is taken as the IP (so `1.2.3.4 some label` works);
/// - **CIDR** ranges (`a.b.c.d/n`) are skipped with a warn (F3: exact-IP only in v1);
/// - unparseable lines are skipped with a warn (a bad line never poisons the whole snapshot).
///
/// Pure and IO-free so the parsing contract is unit-tested without a file or a socket.
fn parse_ip_list(text: &str, verdict: Reputation, source: &str) -> Vec<(IpAddr, Reputation)> {
    let mut out = Vec::new();
    for (idx, raw) in text.lines().enumerate() {
        // Strip a trailing `# comment`, then trim; a whole-line comment becomes empty.
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        // Take the first token so `IP<space>label` (and `IP<tab>date`) lists parse.
        let token = line.split_whitespace().next().unwrap_or("");
        if token.contains('/') {
            warn!(source, line = idx + 1, entry = token, "reputation feed: CIDR unsupported (v1 exact-IP only), skipping");
            continue;
        }
        match token.parse::<IpAddr>() {
            Ok(ip) => out.push((ip, verdict)),
            Err(_) => {
                warn!(source, line = idx + 1, entry = token, "reputation feed: malformed IP, skipping");
            }
        }
    }
    out
}

/// A [`ReputationFeed`] backed by a local file (one IP per line). Useful for tests, air-gapped
/// deployments, and lists maintained out-of-band (e.g. rendered by another process).
pub struct FileFeed {
    path: PathBuf,
    verdict: Reputation,
    name: String,
}

impl FileFeed {
    /// A file source assigning `verdict` to every listed IP.
    pub fn new(path: impl Into<PathBuf>, verdict: Reputation) -> Self {
        let path = path.into();
        let name = format!("file:{}", path.display());
        Self { path, verdict, name }
    }
}

#[async_trait]
impl ReputationFeed for FileFeed {
    fn name(&self) -> &str {
        &self.name
    }

    async fn fetch(&self) -> Result<Vec<(IpAddr, Reputation)>, FeedError> {
        // A periodic read of a local file: a plain blocking read is fine on the feed's background
        // task (it sleeps for minutes between cycles), and it avoids a tokio "fs" dependency.
        let text = std::fs::read_to_string(&self.path).map_err(|e| FeedError::Io(e.to_string()))?;
        Ok(parse_ip_list(&text, self.verdict, &self.name))
    }
}

/// A [`ReputationFeed`] that GETs a plaintext IP list over HTTPS. The client uses a `ring`-based
/// rustls config (no aws-lc-rs/cmake) — the same crypto provider the core uses — matching
/// `CloudflareDns`.
pub struct HttpListFeed {
    url: String,
    verdict: Reputation,
    name: String,
    http: reqwest::Client,
}

impl HttpListFeed {
    /// An HTTPS source assigning `verdict` to every listed IP. Fails (boot-fatal at wiring) if the
    /// HTTPS client cannot be built.
    pub fn new(url: impl Into<String>, verdict: Reputation) -> Result<Self, FeedError> {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        // `ring` explicitly — reqwest carries no provider (`rustls-no-provider`).
        let tls = ClientConfig::builder_with_provider(Arc::new(ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(|e| FeedError::Config(format!("rustls client config: {e}")))?
            .with_root_certificates(roots)
            .with_no_client_auth();
        let http = reqwest::Client::builder()
            .use_preconfigured_tls(tls)
            .build()
            .map_err(|e| FeedError::Config(format!("http client: {e}")))?;
        let url = url.into();
        let name = format!("http:{url}");
        Ok(Self { url, verdict, name, http })
    }
}

#[async_trait]
impl ReputationFeed for HttpListFeed {
    fn name(&self) -> &str {
        &self.name
    }

    async fn fetch(&self) -> Result<Vec<(IpAddr, Reputation)>, FeedError> {
        let resp = self
            .http
            .get(&self.url)
            .send()
            .await
            .map_err(|e| FeedError::Http(e.to_string()))?
            .error_for_status()
            .map_err(|e| FeedError::Http(e.to_string()))?;
        let text = resp.text().await.map_err(|e| FeedError::Http(format!("read body: {e}")))?;
        Ok(parse_ip_list(&text, self.verdict, &self.name))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ips_skipping_comments_blanks_cidr_and_junk() {
        let list = "\
# a header comment
1.2.3.4
  5.6.7.8   # trailing comment
2001:db8::1

10.0.0.0/8
9.9.9.9 some-label
not-an-ip
";
        let got = parse_ip_list(list, Reputation::Malicious, "test");
        let ips: Vec<IpAddr> = got.iter().map(|(ip, _)| *ip).collect();
        assert_eq!(
            ips,
            vec![
                "1.2.3.4".parse::<IpAddr>().unwrap(),
                "5.6.7.8".parse().unwrap(),
                "2001:db8::1".parse().unwrap(),
                "9.9.9.9".parse().unwrap(),
            ],
            "comments/blanks/CIDR/junk skipped; IP-with-label kept"
        );
        assert!(got.iter().all(|(_, v)| *v == Reputation::Malicious), "verdict is per-source (F5)");
    }

    #[test]
    fn empty_or_all_junk_yields_no_entries() {
        assert!(parse_ip_list("", Reputation::Suspicious, "t").is_empty());
        assert!(parse_ip_list("# just a comment\n\n  \n", Reputation::Suspicious, "t").is_empty());
        assert!(parse_ip_list("garbage\n1.2.3/8\n", Reputation::Suspicious, "t").is_empty());
    }

    #[tokio::test]
    async fn file_feed_reads_and_parses() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("waf-feed-test-{}.txt", std::process::id()));
        std::fs::write(&path, "1.1.1.1\n# c\n2.2.2.2\n").unwrap();

        let feed = FileFeed::new(&path, Reputation::Suspicious);
        let entries = feed.fetch().await.expect("reads the file");
        std::fs::remove_file(&path).ok();

        assert_eq!(entries.len(), 2);
        assert!(entries.iter().all(|(_, v)| *v == Reputation::Suspicious));
        assert!(feed.name().starts_with("file:"));
    }

    #[tokio::test]
    async fn file_feed_missing_file_is_an_io_error() {
        let feed = FileFeed::new("/no/such/path/definitely-missing.list", Reputation::Malicious);
        assert!(matches!(feed.fetch().await, Err(FeedError::Io(_))));
    }

    #[test]
    fn http_feed_builds_with_ring_tls() {
        // Proves the ring-based rustls client + reqwest client actually build (no aws-lc/cmake).
        let feed = HttpListFeed::new("https://example.invalid/list.txt", Reputation::Malicious)
            .expect("client builds");
        assert_eq!(feed.name(), "http:https://example.invalid/list.txt");
    }
}
