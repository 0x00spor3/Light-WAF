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
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// The `ring` crate (digest/HKDF-free use here: SHA-256 for fingerprints + the domain-set key).
// Referenced as `::ring` because `tokio_rustls::rustls::crypto::ring` also binds `ring` below.
use ::ring::digest as rdigest;
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
use waf_state_redis::{SharedCert, SharedCertStore};

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
    /// Renewal WINDOW: renew once the served cert's remaining lifetime drops below this (compared
    /// against the leaf's real `notAfter`, not a fixed post-issuance sleep).
    pub renewal_interval: Duration,
    /// Backoff after a failed issuance (the current cert keeps being served meanwhile).
    pub retry_backoff: Duration,
    /// Cluster only: TTL of the single-writer issuance lock. Kept alive by a heartbeat while
    /// issuing; if the leader dies, the lock expires after this so another node can take over.
    pub lock_ttl: Duration,
    /// How often a healthy node re-checks (renewal due? shared cert changed?). This is the loop's
    /// idle cadence — NOT the DNS `poll_interval`.
    pub convergence_poll: Duration,
}

impl Default for Dns01Config {
    fn default() -> Self {
        Self {
            propagation_timeout: Duration::from_secs(120),
            poll_interval: Duration::from_secs(5),
            grace: Duration::from_secs(10),
            renewal_interval: Duration::from_secs(30 * 24 * 60 * 60), // renew when <30 days remain
            retry_backoff: Duration::from_secs(300),
            lock_ttl: Duration::from_secs(60),
            convergence_poll: Duration::from_secs(60),
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

/// A freshly issued certificate: the chain, OUR private key, and the leaf's real expiry. Returned
/// by [`issue_once`] so the caller can publish it to the cluster store and drive renewal off the
/// true `notAfter`.
#[derive(Debug, Clone)]
pub struct IssuedCert {
    pub chain_pem: String,
    pub key_pem: String,
    pub not_after_unix: i64,
}

/// Seconds since the Unix epoch (0 on the impossible pre-1970 clock).
fn now_unix() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// SHA-256 of a byte slice as lowercase hex — used for both the cert fingerprint (change
/// detection) and the domain-set key (Redis namespace).
fn sha256_hex(bytes: &[u8]) -> String {
    let d = rdigest::digest(&rdigest::SHA256, bytes);
    d.as_ref().iter().map(|b| format!("{b:02x}")).collect()
}

/// Fingerprint of an issued chain — the **primary** discriminant for "is the shared cert newer
/// than mine" (clock-skew-proof, unlike comparing `notAfter` timestamps across nodes).
fn cert_fingerprint(chain_pem: &str) -> String {
    sha256_hex(chain_pem.as_bytes())
}

/// Stable, order-independent key for a set of domains (apex + wildcard hash to the same key), so
/// every node coordinates on `cert:<key>` / `issuance_lock:<key>` for the same certificate.
fn domainset_key(domains: &[String]) -> String {
    let mut ds: Vec<&str> = domains.iter().map(String::as_str).collect();
    ds.sort_unstable();
    ds.dedup();
    sha256_hex(ds.join("\n").as_bytes())
}

/// A per-process lock-holder id (host process + a startup nonce), unique enough that two nodes
/// never collide on the compare-and-set lock value.
fn make_node_id() -> String {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
    format!("node-{}-{}", std::process::id(), nanos)
}

/// The leaf's `notAfter` as a Unix timestamp. On a parse failure (extremely unlikely for a real
/// issued cert) fall back to "valid for ~80 days" so a bad parse can never spin the renewal loop.
fn leaf_not_after_unix(chain_pem: &str) -> i64 {
    use x509_parser::prelude::*;
    match Pem::iter_from_buffer(chain_pem.as_bytes()).next() {
        Some(Ok(pem)) => match pem.parse_x509() {
            Ok(cert) => return cert.validity().not_after.timestamp(),
            Err(e) => warn!(error = %e, "DNS-01: could not parse leaf notAfter; assuming ~80d"),
        },
        _ => warn!("DNS-01: issued chain had no leaf PEM; assuming ~80d validity"),
    }
    now_unix() + 80 * 24 * 60 * 60
}

/// Whether a cooperative-abort flag is set (used to bail out of a long issuance when the cluster
/// issuance lock is lost — see [`start_dns01_resolver`]).
fn aborted(flag: Option<&AtomicBool>) -> bool {
    flag.is_some_and(|f| f.load(Ordering::SeqCst))
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
async fn wait_for_propagation(
    name: &str,
    expected: &str,
    cfg: &Dns01Config,
    abort: Option<&AtomicBool>,
) -> Result<(), Dns01Error> {
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
        // Bail out promptly if the cluster issuance lock was lost mid-flight (this is the longest
        // wait in the whole flow, so checking here gives a responsive abort with TXT cleanup).
        if aborted(abort) {
            return Err("DNS-01 issuance aborted: issuance lock lost".into());
        }
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
    abort: Option<&AtomicBool>,
) -> Result<IssuedCert, Dns01Error> {
    // Records every TXT we publish so cleanup runs on ALL exit paths below. Populated inside the
    // issuance block; drained by the unconditional cleanup loop after it, whatever the outcome.
    let mut handles: Vec<TxtHandle> = Vec::new();

    // The whole issuance. Its `?` short-circuits into `result` (NOT out of `issue_once`), so the
    // cleanup loop after always runs. `handles` is borrowed mutably here and read after — the
    // future is dropped at the end of this statement, releasing the borrow before cleanup.
    let result: Result<IssuedCert, Dns01Error> = async {
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
                wait_for_propagation(&name, &value, cfg, abort).await?;
                challenge.set_ready().await?;
            }
        }

        // Lock lost while validating? Abort before spending an order finalize (double issuance).
        if aborted(abort) {
            return Err("DNS-01 issuance aborted: issuance lock lost".into());
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
        let not_after_unix = leaf_not_after_unix(&chain_pem);
        info!(domains = ?domains, not_after = not_after_unix, "DNS-01: certificate issued and installed");
        Ok(IssuedCert { chain_pem, key_pem, not_after_unix })
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

/// Run one issuance while holding the cluster issuance lock. A background heartbeat extends the
/// lock every `lock_ttl/3`; if an extend fails (the lock was lost to a Redis blip), it signals a
/// cooperative ABORT so we stop ordering under a lock another node may now hold (R2) and retry
/// later. `store_cert`'s compare-and-set (R3) is the second line of defence. Returns the issued
/// cert on success.
#[allow(clippy::too_many_arguments)]
async fn issue_as_leader(
    store: &Arc<dyn SharedCertStore>,
    cert_key: &str,
    node_id: &str,
    account: &Account,
    domains: &[String],
    provider: &dyn DnsProvider,
    resolver: &Dns01Resolver,
    cfg: &Dns01Config,
    cache_dir: &Path,
) -> Result<IssuedCert, Dns01Error> {
    let abort = Arc::new(AtomicBool::new(false));
    let heartbeat = {
        let store = Arc::clone(store);
        let cert_key = cert_key.to_string();
        let node_id = node_id.to_string();
        let abort = Arc::clone(&abort);
        let ttl = cfg.lock_ttl;
        let beat = (ttl / 3).max(Duration::from_secs(1));
        tokio::spawn(async move {
            loop {
                sleep(beat).await;
                if !store.extend_lock(&cert_key, &node_id, ttl) {
                    warn!(key = %cert_key, "DNS-01 cluster: lost the issuance lock mid-flight; signalling abort");
                    abort.store(true, Ordering::SeqCst);
                    return;
                }
            }
        })
    };

    let result =
        issue_once(account, domains, provider, resolver, cfg, Some(cache_dir), Some(abort.as_ref())).await;
    heartbeat.abort();
    result
}

/// Start the DNS-01 managed-cert background driver and return the hot-swappable resolver to
/// hand to the core via `TlsCertSource::resolver`. Boot-fatal only on a config error (no
/// domains); the ACME ordering/renewal is async (the resolver serves nothing until the first
/// issuance completes, exactly like the TLS-ALPN-01 path). MUST be called inside a tokio runtime.
///
/// `shared` = the cluster cert store (`[tls.acme].cluster`). When `Some`, nodes coordinate: the
/// lock holder issues ONCE for the cluster and publishes the cert; the others converge on it
/// without issuing. When `None`, this is the single-node path (issue + local disk cache only).
pub fn start_dns01_resolver(
    params: &AcmeParams,
    provider: Arc<dyn DnsProvider>,
    cfg: Dns01Config,
    shared: Option<Arc<dyn SharedCertStore>>,
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
    let cert_key = domainset_key(&domains);
    let node_id = make_node_id();

    let resolver: Arc<Dns01Resolver> = Arc::new(Dns01Resolver::new());

    // Warm start: serve a cached cert immediately, and seed its fingerprint + expiry so a restart
    // with a still-valid cert does not needlessly re-issue (which would burn LE rate limit).
    let mut warm_fp: Option<String> = None;
    let mut warm_not_after: Option<i64> = None;
    if let Some(ck) = load_cached_cert(&cache_dir) {
        resolver.install(Arc::new(ck));
        if let Ok(chain) = std::fs::read_to_string(cache_dir.join("cert.pem")) {
            warm_fp = Some(cert_fingerprint(&chain));
            warm_not_after = Some(leaf_not_after_unix(&chain));
        }
        info!(cache = %cache_dir.display(), "DNS-01: serving cached certificate while renewal runs");
    }

    let resolver_for_task = Arc::clone(&resolver);
    info!(domains = ?domains, cluster = shared.is_some(), "DNS-01 resolver starting; account/order/renewal run in background");
    tokio::spawn(async move {
        let account = match build_account(&server_url, email.as_deref(), &cache_dir).await {
            Ok(a) => a,
            Err(e) => {
                error!(error = %e, "DNS-01: ACME account creation failed; no certificate will be served");
                return;
            }
        };

        let mut installed_fp = warm_fp;
        let mut installed_not_after = warm_not_after;

        loop {
            // 1. Converge on the cluster cert (source of truth in cluster mode). Install only when
            //    the fingerprint differs (skew-proof), i.e. someone issued/renewed elsewhere.
            if let Some(store) = shared.as_ref() {
                if let Some(sc) = store.load_cert(&cert_key) {
                    let fp = cert_fingerprint(&sc.chain_pem);
                    if installed_fp.as_deref() != Some(fp.as_str()) {
                        match certified_key_from_pem(&sc.chain_pem, &sc.key_pem) {
                            Ok(ck) => {
                                resolver_for_task.install(Arc::new(ck));
                                store_cached_cert(&cache_dir, &sc.chain_pem, &sc.key_pem);
                                installed_fp = Some(fp);
                                installed_not_after = Some(sc.not_after_unix);
                                info!(key = %cert_key, "DNS-01 cluster: converged on shared certificate");
                            }
                            Err(e) => warn!(error = %e, "DNS-01 cluster: shared cert failed to load"),
                        }
                    } else {
                        installed_not_after = Some(sc.not_after_unix);
                    }
                }
            }

            // 2. Renewal due? (No cert yet, or the leaf is inside the renewal window.)
            let need = match installed_not_after {
                Some(na) => na - now_unix() < cfg.renewal_interval.as_secs() as i64,
                None => true,
            };
            if !need {
                sleep(cfg.convergence_poll).await;
                continue;
            }

            // 3. Issue (leader / single-node) or wait for the leader to publish (follower).
            match shared.as_ref() {
                Some(store) => {
                    if store.try_lock(&cert_key, &node_id, cfg.lock_ttl) {
                        info!(key = %cert_key, node = %node_id, "DNS-01 cluster: acquired issuance lock (leader)");
                        let outcome = issue_as_leader(
                            store, &cert_key, &node_id, &account, &domains,
                            provider.as_ref(), &resolver_for_task, &cfg, &cache_dir,
                        )
                        .await;
                        match outcome {
                            Ok(issued) => {
                                let sc = SharedCert {
                                    chain_pem: issued.chain_pem.clone(),
                                    key_pem: issued.key_pem.clone(),
                                    not_after_unix: issued.not_after_unix,
                                };
                                if store.store_cert(&cert_key, &node_id, &sc) {
                                    info!(key = %cert_key, "DNS-01 cluster: published issued cert to shared store");
                                } else {
                                    warn!(key = %cert_key, "DNS-01 cluster: could not publish cert (lock lost?)");
                                }
                                store.unlock(&cert_key, &node_id);
                                installed_fp = Some(cert_fingerprint(&issued.chain_pem));
                                installed_not_after = Some(issued.not_after_unix);
                                sleep(cfg.convergence_poll).await;
                            }
                            Err(e) => {
                                store.unlock(&cert_key, &node_id);
                                warn!(error = %e, "DNS-01 cluster: issuance failed; keeping current cert, will retry");
                                sleep(cfg.retry_backoff).await;
                            }
                        }
                    } else {
                        // Follower: another node holds the lock and is issuing → poll to converge.
                        info!(key = %cert_key, "DNS-01 cluster: issuance in progress elsewhere; waiting to converge");
                        sleep(cfg.convergence_poll).await;
                    }
                }
                None => {
                    // Single-node: today's path, now renewing off the leaf's real notAfter.
                    match issue_once(
                        &account, &domains, provider.as_ref(), &resolver_for_task, &cfg,
                        Some(&cache_dir), None,
                    )
                    .await
                    {
                        Ok(issued) => {
                            installed_fp = Some(cert_fingerprint(&issued.chain_pem));
                            installed_not_after = Some(issued.not_after_unix);
                            sleep(cfg.convergence_poll).await;
                        }
                        Err(e) => {
                            warn!(error = %e, "DNS-01: issuance failed; keeping current certificate, will retry");
                            sleep(cfg.retry_backoff).await;
                        }
                    }
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

    #[test]
    fn domainset_key_is_order_independent_and_dedup() {
        // apex + wildcard in any order → the SAME key (so every node coordinates on one cert).
        let a = domainset_key(&["example.com".into(), "*.example.com".into()]);
        let b = domainset_key(&["*.example.com".into(), "example.com".into()]);
        let c = domainset_key(&["*.example.com".into(), "example.com".into(), "example.com".into()]);
        assert_eq!(a, b, "domain order must not change the key");
        assert_eq!(a, c, "duplicates must not change the key");
        // A different domain set → a different key.
        assert_ne!(a, domainset_key(&["other.com".into()]));
    }

    #[test]
    fn cert_fingerprint_is_stable_and_distinguishes_chains() {
        let x = cert_fingerprint("chain-A");
        assert_eq!(x, cert_fingerprint("chain-A"), "same input → same fingerprint");
        assert_ne!(x, cert_fingerprint("chain-B"), "different chain → different fingerprint");
        assert_eq!(x.len(), 64, "SHA-256 hex is 64 chars");
    }

    #[test]
    fn leaf_not_after_parses_a_real_cert() {
        // A real (self-signed) cert's notAfter must parse to a future timestamp — this is what
        // drives the renewal decision. A garbage chain falls back to ~80 days (never 0 → no loop).
        let issued = rcgen::generate_simple_self_signed(vec!["example.com".to_string()]).unwrap();
        let na = leaf_not_after_unix(&issued.cert.pem());
        assert!(na > now_unix(), "issued cert must expire in the future");

        let fallback = leaf_not_after_unix("not a certificate");
        assert!(fallback > now_unix() + 70 * 24 * 60 * 60, "unparseable ⇒ ~80d fallback, not 0");
    }

    #[test]
    fn node_ids_are_unique_per_call() {
        assert_ne!(make_node_id(), make_node_id(), "each node id must be distinct");
    }

    #[test]
    fn aborted_flag_reads_through_the_option() {
        assert!(!aborted(None), "no flag ⇒ never aborted");
        let f = AtomicBool::new(false);
        assert!(!aborted(Some(&f)));
        f.store(true, Ordering::SeqCst);
        assert!(aborted(Some(&f)));
    }
}
