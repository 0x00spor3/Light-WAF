// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: BUSL-1.1

//! ACME **DNS-01** driver (enterprise). `rustls-acme` is TLS-ALPN-01 only, so DNS-01 runs on
//! [`instant-acme`](instant_acme), used **purely as a protocol client**: it yields the issued
//! certificate PEM, and we build the rustls [`CertifiedKey`] with the **core's** rustls
//! (`tokio_rustls` 0.26). That is the load-bearing seam ("suture") — the issued chain plus a
//! key we own (generated with rcgen) become a `CertifiedKey` the core can serve. Because we
//! only consume PEM bytes from instant-acme, its internal rustls version need not match ours.
//!
//! The cert is installed into a hot-swappable [`Dns01Resolver`] handed to the core via
//! `TlsCertSource::resolver()` — rotation needs no acceptor rebuild (hitless). A background
//! task ([`start_dns01_resolver`]) issues at boot and renews on an interval.
//!
//! Propagation: before telling the CA a challenge is ready, we poll the zone's **authoritative
//! nameservers directly** (not the system resolver, which could report a stale cache), then
//! add a grace delay (the CA validates from several vantage points).
//!
//! Not yet wired (documented follow-on): on-disk cache of the ACME account + issued cert in
//! `cache_dir` for warm restarts; today each boot creates a fresh account and re-issues.

use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwapOption;
use hickory_resolver::config::{NameServerConfig, ResolverConfig};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::proto::rr::{RData, RecordType};
use hickory_resolver::TokioResolver;
use instant_acme::{
    Account, AccountCredentials, ChallengeType, Identifier, LetsEncrypt, NewAccount, NewOrder,
    RetryPolicy,
};
use tokio::time::{sleep, Instant};
use tokio_rustls::rustls::crypto::ring;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::rustls::server::{ClientHello, ResolvesServerCert};
use tokio_rustls::rustls::sign::CertifiedKey;
use tracing::{error, info, warn};

use crate::acme::{AcmeError, AcmeParams};
use crate::dns::{DnsProvider, TxtHandle};

/// Anything that can go wrong issuing a DNS-01 certificate. Boxed so the many underlying error
/// types (ACME, DNS provider, rcgen, rustls, PEM I/O) compose without a bespoke enum here.
pub type Dns01Error = Box<dyn std::error::Error + Send + Sync>;

/// Timing knobs for the DNS-01 driver. Defaults are conservative; the wiring layer overrides
/// them from `[tls.acme.dns]`.
#[derive(Debug, Clone, Copy)]
pub struct Dns01Config {
    /// Max time to wait for a TXT to become visible on the authoritative nameservers.
    pub propagation_timeout: Duration,
    /// Interval between propagation polls.
    pub poll_interval: Duration,
    /// Courtesy delay AFTER the TXT is first seen (CAs validate from multiple vantage points).
    pub grace: Duration,
    /// How long to wait between successful issuance and the next renewal attempt.
    pub renewal_interval: Duration,
    /// Backoff after a failed issuance (the current cert keeps being served meanwhile).
    pub retry_backoff: Duration,
}

impl Default for Dns01Config {
    fn default() -> Self {
        Self {
            propagation_timeout: Duration::from_secs(120),
            poll_interval: Duration::from_secs(5),
            grace: Duration::from_secs(10),
            renewal_interval: Duration::from_secs(60 * 24 * 60 * 60), // ~60 days
            retry_backoff: Duration::from_secs(300),
        }
    }
}

/// Hot-swappable server-cert resolver for ACME-managed certs. The driver installs the freshly
/// issued cert; [`resolve`](ResolvesServerCert::resolve) returns the current one lock-free, so
/// rotation never rebuilds the acceptor.
#[derive(Default)]
pub struct Dns01Resolver {
    current: ArcSwapOption<CertifiedKey>,
}

impl Dns01Resolver {
    pub fn new() -> Self {
        Self::default()
    }

    /// Install (or replace) the live certificate. Lock-free for readers.
    pub fn install(&self, ck: Arc<CertifiedKey>) {
        self.current.store(Some(ck));
    }

    /// The currently installed certificate, if any (mainly for tests/diagnostics).
    pub fn current(&self) -> Option<Arc<CertifiedKey>> {
        self.current.load_full()
    }
}

impl std::fmt::Debug for Dns01Resolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Dns01Resolver")
            .field("has_cert", &self.current.load().is_some())
            .finish()
    }
}

impl ResolvesServerCert for Dns01Resolver {
    fn resolve(&self, _client_hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        self.current.load_full()
    }
}

/// Build a rustls [`CertifiedKey`] from an issued chain PEM and our private-key PEM, using the
/// **core's** rustls + the `ring` provider — the exact same parsing path as the OPEN
/// `FileCertSource::load`. This is the suture point between instant-acme and the core.
pub fn certified_key_from_pem(chain_pem: &str, key_pem: &str) -> Result<CertifiedKey, Dns01Error> {
    let certs: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut chain_pem.as_bytes()).collect::<Result<_, _>>()?;
    if certs.is_empty() {
        return Err("issued certificate chain contained no certificates".into());
    }
    let key: PrivateKeyDer<'static> =
        rustls_pemfile::private_key(&mut key_pem.as_bytes())?.ok_or("no private key in PEM")?;
    let signing_key = ring::default_provider().key_provider.load_private_key(key)?;
    Ok(CertifiedKey::new(certs, signing_key))
}

// ── On-disk cache (warm restarts) ───────────────────────────────────────────────
//
// `cache_dir/account.json` = the ACME account credentials (so a restart reuses the account
// instead of registering a new one — Let's Encrypt rate-limits account creation).
// `cache_dir/cert.pem` + `cache_dir/key.pem` = the live cert chain and our private key, so a
// restart serves the existing cert immediately while renewal runs in the background.

/// Load a previously issued cert from `cache_dir`, if both files are present and parse.
fn load_cached_cert(cache_dir: &Path) -> Option<CertifiedKey> {
    let chain = std::fs::read_to_string(cache_dir.join("cert.pem")).ok()?;
    let key = std::fs::read_to_string(cache_dir.join("key.pem")).ok()?;
    certified_key_from_pem(&chain, &key).ok()
}

/// Persist the issued cert chain + our key to `cache_dir` (best-effort; a failure only loses
/// the warm-restart optimisation, it never fails issuance). The key file is restricted to the
/// owner on Unix.
fn store_cached_cert(cache_dir: &Path, chain_pem: &str, key_pem: &str) {
    if let Err(e) = std::fs::create_dir_all(cache_dir) {
        warn!(error = %e, "DNS-01: could not create cache dir; not persisting cert");
        return;
    }
    if let Err(e) = std::fs::write(cache_dir.join("cert.pem"), chain_pem) {
        warn!(error = %e, "DNS-01: could not write cached cert.pem");
    }
    let key_path = cache_dir.join("key.pem");
    if let Err(e) = std::fs::write(&key_path, key_pem) {
        warn!(error = %e, "DNS-01: could not write cached key.pem");
        return;
    }
    restrict_to_owner(&key_path);
}

/// Restrict a file to owner-only on Unix (the cached private key). No-op elsewhere.
#[cfg(unix)]
fn restrict_to_owner(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
}

#[cfg(not(unix))]
fn restrict_to_owner(_path: &Path) {}

/// Resolve the IPs of the authoritative nameservers for `record_name`'s zone, by querying a
/// public bootstrap resolver and walking up the labels until an `NS` set is found. Empty when
/// there is no real zone (e.g. a local `.test` domain), which the caller treats as "fall back
/// to a fixed courtesy delay".
async fn authoritative_ns_ips(boot: &TokioResolver, record_name: &str) -> Vec<IpAddr> {
    let trimmed = record_name.trim_end_matches('.');
    let labels: Vec<&str> = trimmed.split('.').collect();
    let mut start = 0usize;
    while labels.len().saturating_sub(start) >= 2 {
        let zone = labels[start..].join(".");
        if let Ok(lookup) = boot.lookup(zone, RecordType::NS).await {
            let ns_names: Vec<_> = lookup
                .answers()
                .iter()
                .filter_map(|r| match &r.data {
                    RData::NS(ns) => Some(ns.0.clone()),
                    _ => None,
                })
                .collect();
            if !ns_names.is_empty() {
                let mut ips = Vec::new();
                for n in ns_names {
                    if let Ok(lip) = boot.lookup_ip(n).await {
                        ips.extend(lip.iter());
                    }
                }
                if !ips.is_empty() {
                    return ips;
                }
            }
        }
        start += 1;
    }
    Vec::new()
}

/// True if any authoritative nameserver currently serves `expected` as a TXT value at `name`.
async fn txt_present(resolver: &TokioResolver, name: &str, expected: &str) -> bool {
    match resolver.lookup(name, RecordType::TXT).await {
        Ok(lookup) => lookup.answers().iter().any(|r| match &r.data {
            RData::TXT(txt) => {
                // A TXT record can be split into 255-byte chunks; rejoin before comparing.
                let joined: Vec<u8> = txt.txt_data.iter().flat_map(|c| c.iter().copied()).collect();
                joined == expected.as_bytes()
            }
            _ => false,
        }),
        Err(_) => false,
    }
}

/// Wait until the DNS-01 TXT `expected` at `name` is visible on the zone's AUTHORITATIVE
/// nameservers, then add a grace delay. If there is no discoverable authoritative zone (local
/// test domains), fall back to a short fixed delay so the flow still works.
async fn wait_for_propagation(name: &str, expected: &str, cfg: &Dns01Config) -> Result<(), Dns01Error> {
    let boot_cfg = ResolverConfig::from_parts(
        None,
        vec![],
        vec![
            NameServerConfig::udp(IpAddr::from([1, 1, 1, 1])),
            NameServerConfig::udp(IpAddr::from([8, 8, 8, 8])),
        ],
    );
    let boot = match TokioResolver::builder_with_config(boot_cfg, TokioRuntimeProvider::default()).build() {
        Ok(r) => r,
        Err(e) => {
            warn!(error = %e, "DNS-01: bootstrap resolver unavailable; using a fixed propagation delay");
            sleep(cfg.grace.max(Duration::from_secs(2))).await;
            return Ok(());
        }
    };

    let ns_ips = authoritative_ns_ips(&boot, name).await;
    if ns_ips.is_empty() {
        warn!(record = name, "DNS-01: no authoritative NS discovered; using a fixed propagation delay");
        sleep(cfg.grace.max(Duration::from_secs(2))).await;
        return Ok(());
    }

    let auth_cfg = ResolverConfig::from_parts(
        None,
        vec![],
        ns_ips.iter().map(|ip| NameServerConfig::udp(*ip)).collect(),
    );
    let auth = TokioResolver::builder_with_config(auth_cfg, TokioRuntimeProvider::default())
        .build()
        .map_err(|e| -> Dns01Error { format!("authoritative resolver: {e}").into() })?;

    let deadline = Instant::now() + cfg.propagation_timeout;
    loop {
        if txt_present(&auth, name, expected).await {
            info!(record = name, "DNS-01: TXT visible on authoritative NS");
            sleep(cfg.grace).await;
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "DNS-01 TXT for {name} not visible on authoritative NS within {:?}",
                cfg.propagation_timeout
            )
            .into());
        }
        sleep(cfg.poll_interval).await;
    }
}

/// Issue ONE certificate for `domains` via DNS-01 and install it into `resolver`.
///
/// Provider- and CA-agnostic: the caller supplies the [`Account`] and the [`DnsProvider`]. The
/// flow per authorization: publish the DNS-01 TXT → wait for authoritative propagation → mark
/// the challenge ready. Then: poll until valid → finalize with our own CSR → fetch the chain →
/// build the `CertifiedKey` → install. Every challenge TXT we publish is removed best-effort on
/// **all** exit paths (success OR failure), so a failed attempt never leaks orphaned records.
pub async fn issue_once(
    account: &Account,
    domains: &[String],
    provider: &dyn DnsProvider,
    resolver: &Dns01Resolver,
    cfg: &Dns01Config,
    cache_dir: Option<&Path>,
) -> Result<(), Dns01Error> {
    // Records every TXT we publish so cleanup runs on ALL exit paths below. Populated inside the
    // issuance block; drained by the unconditional cleanup loop after it, whatever the outcome.
    let mut handles: Vec<TxtHandle> = Vec::new();

    // The whole issuance. Its `?` short-circuits into `result` (NOT out of `issue_once`), so the
    // cleanup loop after always runs. `handles` is borrowed mutably here and read after — the
    // future is dropped at the end of this statement, releasing the borrow before cleanup.
    let result: Result<(), Dns01Error> = async {
        let identifiers: Vec<Identifier> = domains.iter().cloned().map(Identifier::Dns).collect();
        let mut order = account.new_order(&NewOrder::new(&identifiers)).await?;

        {
            let mut authorizations = order.authorizations();
            while let Some(authz) = authorizations.next().await {
                let mut authz = authz?;
                // The authorization identifier is the BASE domain even for a wildcard order
                // (`*.example.com` authorizes `example.com`), so the TXT name is correct as-is.
                let base = match authz.identifier().identifier {
                    Identifier::Dns(ref d) => d.clone(),
                    _ => return Err("dns-01 authorization had a non-DNS identifier".into()),
                };
                let name = format!("_acme-challenge.{base}");
                let mut challenge = authz
                    .challenge(ChallengeType::Dns01)
                    .ok_or("authorization offers no dns-01 challenge")?;
                let value = challenge.key_authorization().dns_value();
                // Record the handle BEFORE waiting: if propagation times out, the TXT is already
                // published and must still be cleaned up.
                let handle = provider.add_txt(&name, &value).await.map_err(Box::new)?;
                handles.push(handle);
                wait_for_propagation(&name, &value, cfg).await?;
                challenge.set_ready().await?;
            }
        }

        // Wait for the CA to validate every authorization, then finalize with a key WE own.
        order.poll_ready(&RetryPolicy::default()).await?;

        let key_pair = rcgen::KeyPair::generate()?;
        let mut csr_params = rcgen::CertificateParams::new(domains.to_vec())?;
        // ACME wants the identifiers in the SAN extension ONLY. rcgen otherwise stamps a default
        // subject CN ("rcgen self signed cert"), which Boulder parses as a domain to issue for and
        // rejects (`rejectedIdentifier`: the space is an invalid DNS character). Empty DN → SAN-only.
        csr_params.distinguished_name = rcgen::DistinguishedName::new();
        let csr = csr_params.serialize_request(&key_pair)?;
        order.finalize_csr(csr.der()).await?;
        let chain_pem = order.poll_certificate(&RetryPolicy::default()).await?;

        let key_pem = key_pair.serialize_pem();
        let certified = certified_key_from_pem(&chain_pem, &key_pem)?;
        resolver.install(Arc::new(certified));
        if let Some(dir) = cache_dir {
            store_cached_cert(dir, &chain_pem, &key_pem);
        }
        info!(domains = ?domains, "DNS-01: certificate issued and installed");
        Ok(())
    }
    .await;

    // Always remove the challenge TXT records we published — success or failure — so repeated
    // failures (slow propagation, finalize errors, …) never accumulate orphaned records.
    for handle in &handles {
        if let Err(e) = provider.remove_txt(handle).await {
            warn!(name = %handle.name, error = %e, "DNS-01: TXT cleanup failed (non-fatal)");
        }
    }

    result
}

/// Create the ACME account against `server_url` (a public CA the system trusts — Let's Encrypt
/// staging/production, or a configured directory). For a private Pebble CA, use the env-gated
/// integration test, which builds the account with `Account::builder_with_root`.
async fn build_account(
    server_url: &str,
    email: Option<&str>,
    cache_dir: &Path,
) -> Result<Account, Dns01Error> {
    let account_path = cache_dir.join("account.json");

    // Reuse a cached account if present (avoids re-registering on every restart).
    if let Ok(text) = std::fs::read_to_string(&account_path) {
        match serde_json::from_str::<AccountCredentials>(&text) {
            Ok(creds) => {
                info!(path = %account_path.display(), "DNS-01: reusing cached ACME account");
                return Ok(Account::builder()?.from_credentials(creds).await?);
            }
            Err(e) => warn!(error = %e, "DNS-01: cached account unreadable; registering a new one"),
        }
    }

    let contact: Vec<String> = email.map(|e| format!("mailto:{e}")).into_iter().collect();
    let contact_refs: Vec<&str> = contact.iter().map(String::as_str).collect();
    let (account, credentials) = Account::builder()?
        .create(
            &NewAccount {
                contact: &contact_refs,
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            server_url.to_string(),
            None,
        )
        .await?;

    // Cache the new credentials (best-effort; failure only loses the warm-restart optimisation).
    let _ = std::fs::create_dir_all(cache_dir);
    match serde_json::to_string(&credentials) {
        Ok(json) => {
            if let Err(e) = std::fs::write(&account_path, json) {
                warn!(error = %e, "DNS-01: could not cache ACME account credentials");
            }
        }
        Err(e) => warn!(error = %e, "DNS-01: could not serialize ACME account credentials"),
    }
    Ok(account)
}

/// Start the DNS-01 managed-cert background driver and return the hot-swappable resolver to
/// hand to the core via `TlsCertSource::resolver`. Boot-fatal only on a config error (no
/// domains); the ACME ordering/renewal is async (the resolver serves nothing until the first
/// issuance completes, exactly like the TLS-ALPN-01 path). MUST be called inside a tokio runtime.
pub fn start_dns01_resolver(
    params: &AcmeParams,
    provider: Arc<dyn DnsProvider>,
    cfg: Dns01Config,
) -> Result<Arc<dyn ResolvesServerCert>, AcmeError> {
    if params.domains.is_empty() {
        return Err(AcmeError::NoDomains);
    }

    let server_url = match &params.directory_url {
        Some(u) => u.clone(),
        None => if params.staging { LetsEncrypt::Staging } else { LetsEncrypt::Production }
            .url()
            .to_string(),
    };
    let domains = params.domains.clone();
    let email = params.email.clone();
    let cache_dir = params.cache_dir.clone();

    let resolver: Arc<Dns01Resolver> = Arc::new(Dns01Resolver::new());

    // Warm start: serve a cached cert immediately (the background loop will renew it).
    if let Some(ck) = load_cached_cert(&cache_dir) {
        resolver.install(Arc::new(ck));
        info!(cache = %cache_dir.display(), "DNS-01: serving cached certificate while renewal runs");
    }

    let resolver_for_task = Arc::clone(&resolver);
    info!(domains = ?domains, "DNS-01 resolver starting; account/order/renewal run in background");
    tokio::spawn(async move {
        let account = match build_account(&server_url, email.as_deref(), &cache_dir).await {
            Ok(a) => a,
            Err(e) => {
                error!(error = %e, "DNS-01: ACME account creation failed; no certificate will be served");
                return;
            }
        };
        loop {
            match issue_once(
                &account,
                &domains,
                provider.as_ref(),
                &resolver_for_task,
                &cfg,
                Some(&cache_dir),
            )
            .await
            {
                Ok(()) => sleep(cfg.renewal_interval).await,
                Err(e) => {
                    warn!(error = %e, "DNS-01: issuance failed; keeping current certificate, will retry");
                    sleep(cfg.retry_backoff).await;
                }
            }
        }
    });

    Ok(resolver)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    fn tmp_dir(tag: &str) -> std::path::PathBuf {
        static N: AtomicU64 = AtomicU64::new(0);
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let dir = std::env::temp_dir()
            .join(format!("waf-dns01-{tag}-{nanos}-{}", N.fetch_add(1, Ordering::Relaxed)));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Round-trip: a stored cert/key PEM pair loads back into a usable `CertifiedKey`
    /// (this also exercises the `certified_key_from_pem` suture with real PEM material).
    #[test]
    fn cert_cache_store_then_load_round_trips() {
        let issued = rcgen::generate_simple_self_signed(vec!["example.com".to_string()]).unwrap();
        let chain_pem = issued.cert.pem();
        let key_pem = issued.key_pair.serialize_pem();

        let dir = tmp_dir("cache");
        assert!(load_cached_cert(&dir).is_none(), "empty cache yields nothing");

        store_cached_cert(&dir, &chain_pem, &key_pem);
        assert!(dir.join("cert.pem").exists());
        assert!(dir.join("key.pem").exists());

        assert!(load_cached_cert(&dir).is_some(), "stored cert must load back as a CertifiedKey");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn load_cached_cert_is_none_when_only_one_file_present() {
        let dir = tmp_dir("partial");
        std::fs::write(dir.join("cert.pem"), "not even a real cert").unwrap();
        // key.pem missing → None (never serve half a pair).
        assert!(load_cached_cert(&dir).is_none());
        std::fs::remove_dir_all(&dir).ok();
    }
}
