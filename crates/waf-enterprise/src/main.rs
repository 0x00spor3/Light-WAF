// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: BUSL-1.1

//! Light WAF — ENTERPRISE binary.
//!
//! The published OPEN binary (`waf`) calls `Proxy::bind` directly and therefore
//! cannot load enterprise seams. This binary exists precisely because the
//! `Proxy::builder` is the ONLY extension point (BOUNDARY.md §4): it reuses the
//! core's config loading verbatim (`waf_proxy::config`), then injects the at-scale
//! implementations before `build()`. Today that is the distributed Redis
//! `StateStore`; `.cert_source(..)` and `.modules(..)` are the next seams (the
//! hook points are marked below).

mod config;

use std::path::Path;
use std::sync::Arc;

use tracing::{error, info, warn};
use waf_proxy::tls::FileCertSource;
use waf_proxy::Proxy;
use waf_state_redis::{CertCipher, RedisStore, RedisStoreOptions, SharedCertStore};
use waf_tls_managed::acme::ChallengeStrategy;
use waf_tls_managed::dns::{CloudflareDns, DnsProvider, Route53Dns};
use waf_tls_managed::{acme, acme_dns01, mtls, ManagedTlsCertSource};
use waf_threatintel::{ReputationConfig, ReputationModule};

/// Build the DNS-01 [`DnsProvider`] selected by `[tls.acme].provider`. Secrets come from the
/// environment, never the config file. Boot-fatal on a missing token / unknown provider.
fn build_dns_provider(
    acme_cfg: &config::AcmeSection,
) -> Result<Arc<dyn DnsProvider>, Box<dyn std::error::Error + Send + Sync>> {
    match acme_cfg.provider.as_deref().unwrap_or("cloudflare") {
        "cloudflare" => {
            let token = std::env::var("CF_API_TOKEN").map_err(|_| {
                "[tls.acme] provider=cloudflare requires the CF_API_TOKEN environment variable"
            })?;
            if acme_cfg.dns.zone_id.is_empty() {
                return Err("[tls.acme.dns].zone_id is required for the cloudflare provider".into());
            }
            Ok(Arc::new(CloudflareDns::new(token, acme_cfg.dns.zone_id.clone())?))
        }
        "route53" => {
            // Standard AWS credential env vars; Route 53 is global, region is signing-only.
            let access = std::env::var("AWS_ACCESS_KEY_ID")
                .map_err(|_| "[tls.acme] provider=route53 requires AWS_ACCESS_KEY_ID")?;
            let secret = std::env::var("AWS_SECRET_ACCESS_KEY")
                .map_err(|_| "[tls.acme] provider=route53 requires AWS_SECRET_ACCESS_KEY")?;
            let session = std::env::var("AWS_SESSION_TOKEN").ok();
            let region = std::env::var("AWS_REGION").unwrap_or_else(|_| "us-east-1".to_string());
            if acme_cfg.dns.zone_id.is_empty() {
                return Err("[tls.acme.dns].zone_id (the Route 53 hosted-zone id) is required for route53".into());
            }
            Ok(Arc::new(Route53Dns::new(
                access,
                secret,
                session,
                region,
                acme_cfg.dns.zone_id.clone(),
            )))
        }
        other => {
            Err(format!("unknown [tls.acme] provider {other:?} (use \"cloudflare\" or \"route53\")").into())
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    // Install ONE process-level rustls CryptoProvider before any TLS is built. The dependency
    // graph links both `ring` (core, instant-acme's hyper-rustls ACME client, the Cloudflare
    // client) and `aws-lc-rs` (pulled transitively by the AWS SDK for the Route 53 provider), so
    // rustls can no longer auto-determine a default and panics on the first `ClientConfig::builder`
    // — which is exactly the DNS-01 ACME client on a background worker. Pin `ring`, the provider
    // the core already uses. `install_default` errors only if one is already set; ignore that.
    let _ = rustls::crypto::ring::default_provider().install_default();

    // Identical config resolution to the OPEN binary — no duplication.
    let args: Vec<String> = std::env::args().skip(1).collect();
    let config_path =
        waf_proxy::config::resolve_path(&args, std::env::var(waf_proxy::config::ENV_CONFIG).ok());
    let config = match waf_proxy::config::load(&config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("waf-enterprise: {e}");
            std::process::exit(2);
        }
    };

    info!(
        listen = %config.proxy.listen,
        backend = %config.proxy.backend,
        mode = ?config.waf.mode,
        "WAF (enterprise) starting"
    );

    // Enterprise-only settings live in `[enterprise]` / `[tls.acme]` / `[tls.mtls]` of the
    // SAME file (the core's Config ignores those tables). Re-read the file — it already
    // parsed/validated as a Config, so a failure here is a typed enterprise-config error.
    let ent_file = match std::fs::read_to_string(&config_path) {
        Ok(text) => match config::EnterpriseFile::from_toml_str(&text) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("waf-enterprise: invalid enterprise config: {e}");
                std::process::exit(2);
            }
        },
        Err(e) => {
            eprintln!("waf-enterprise: cannot re-read config for enterprise tables: {e}");
            std::process::exit(2);
        }
    };
    let ent = &ent_file.enterprise;

    // Cluster cert-sharing (SharedCertStore): opt-in via `[tls.acme].cluster`, only for DNS-01
    // with TLS on. It needs Redis (the shared cert store) AND `WAF_CERT_STORE_KEY` (the private
    // key is encrypted at rest) — both boot-fatal if missing. The cipher is built here so it can
    // be attached to the SINGLE `RedisStore` constructed for Seam 1 (one pool, three capabilities).
    let acme_is_dns01 =
        matches!(ent_file.tls.acme.challenge_strategy(), Ok(ChallengeStrategy::Dns01 { .. }));
    let cluster_certs = config.tls.enabled
        && ent_file.tls.acme.enabled
        && ent_file.tls.acme.cluster
        && acme_is_dns01;
    if ent_file.tls.acme.cluster && !cluster_certs {
        warn!("[tls.acme].cluster = true ignored (needs [tls].enabled + [tls.acme].enabled + strategy = dns-01)");
    }
    let mut cert_cipher: Option<CertCipher> = None;
    if cluster_certs {
        match std::env::var("WAF_CERT_STORE_KEY") {
            Ok(k) if !k.is_empty() => cert_cipher = Some(CertCipher::from_secret(&k)),
            _ => {
                eprintln!("waf-enterprise: [tls.acme].cluster = true requires the WAF_CERT_STORE_KEY environment variable");
                std::process::exit(2);
            }
        }
    }
    // Set from the Seam-1 Redis store when cluster mode is active; handed to the DNS-01 driver.
    let mut shared_cert_store: Option<Arc<dyn SharedCertStore>> = None;

    let mut builder = Proxy::builder(&config);

    // ── Seam 1: distributed state on Redis — rate-limit StateStore AND/OR cluster-wide
    // IP-reputation. ONE `RedisStore` (one pool) backs both: it implements `StateStore`
    // (rate-limit) and `ReputationStore` (reputation), with separate keyspaces. URL source is
    // `WAF_REDIS_URL` (env wins) else `[enterprise].redis_url`. The injected store survives
    // SIGHUP (process-lifetime state); the reputation MODULE, added via `.add_module`, does NOT
    // survive a reload yet (core `.module_factory` is the TBD seam for that).
    let (redis_url, url_src) = match std::env::var("WAF_REDIS_URL").ok().filter(|s| !s.is_empty()) {
        Some(u) => (Some(u), "WAF_REDIS_URL env"),
        None => (ent.redis_url.clone(), "[enterprise].redis_url"),
    };
    let reputation_on = ent.reputation.enabled;
    let needs_store = config.rate_limit.enabled || reputation_on || cluster_certs;
    match redis_url {
        Some(url) if needs_store => {
            let mut opts = RedisStoreOptions::default();
            if let Some(ps) = ent.pool_size {
                opts.pool_size = ps;
            }
            opts.fail_open = ent.fail_open;
            // Boot-time validation: a configured-but-unreachable Redis is fatal — silently
            // degrading would be "looks-protected-but-isn't". (Runtime: rate-limit follows
            // `fail_open`; reputation always fails to `Unknown`.)
            let store = match RedisStore::connect_with_options(&url, opts) {
                // Attach the cert cipher in cluster mode → the same pool ALSO backs the
                // `SharedCertStore` (cert coordination), alongside rate-limit + reputation.
                Ok(s) => match cert_cipher.take() {
                    Some(c) => Arc::new(s.with_cert_cipher(c)),
                    None => Arc::new(s),
                },
                Err(e) => {
                    error!(error = %e, "configured Redis unreachable; refusing to start");
                    return Err(e.into());
                }
            };
            if config.rate_limit.enabled {
                info!(
                    redis = %url, source = url_src, pool_size = opts.pool_size, fail_open = opts.fail_open,
                    "wiring distributed rate-limit StateStore (Redis)"
                );
                builder = builder.state_store(store.clone());
            }
            if reputation_on {
                let (malicious, suspicious) = match ent.reputation.severities() {
                    Ok(s) => s,
                    Err(e) => {
                        eprintln!("waf-enterprise: {e}");
                        std::process::exit(2);
                    }
                };
                info!(redis = %url, source = url_src, "wiring cluster-wide IP-reputation module");
                builder = builder.add_module(Box::new(ReputationModule::new(
                    store.clone(),
                    ReputationConfig { enabled: true, malicious, suspicious },
                )));
            }
            if cluster_certs {
                // The SAME store also backs cluster cert coordination (Step 3): the DNS-01 driver
                // (Seam 2) uses it as the SharedCertStore. RedisStore impls the trait.
                info!(redis = %url, source = url_src, "wiring cluster-wide SharedCertStore (multi-node cert coordination)");
                shared_cert_store = Some(store.clone());
            }
        }
        // Redis configured but nothing consumes it.
        Some(_) => warn!(
            source = url_src,
            "redis_url configured but neither [rate_limit] nor [enterprise.reputation] is enabled — Redis NOT wired"
        ),
        // Cluster-wide reputation REQUIRES Redis (there is no in-memory reputation); rate-limit
        // alone falls back to the OPEN in-memory store.
        None if reputation_on => {
            error!("[enterprise.reputation].enabled = true but no redis_url — reputation needs Redis; refusing to start");
            return Err("[enterprise.reputation] enabled without redis_url".into());
        }
        // Cluster cert-sharing likewise has no in-memory fallback (there is no shared store).
        None if cluster_certs => {
            error!("[tls.acme].cluster = true but no redis_url — cluster cert-sharing needs Redis; refusing to start");
            return Err("[tls.acme].cluster enabled without redis_url".into());
        }
        None => info!("no redis_url ([enterprise] or WAF_REDIS_URL) — using the OPEN in-memory rate-limit store (single-node)"),
    }

    // ── Seam 2: managed TLS — ACME server certs (hitless) and/or mTLS client auth.
    // Wired only when [tls.acme] or [tls.mtls] is enabled AND [tls] termination is on.
    let acme_on = ent_file.tls.acme.enabled;
    let mtls_on = ent_file.tls.mtls.enabled;
    if acme_on || mtls_on {
        if !config.tls.enabled {
            warn!("[tls.acme]/[tls.mtls] enabled but [tls].enabled is false — managed TLS NOT wired (no TLS listener)");
        } else {
            let mut mb = ManagedTlsCertSource::builder();

            if acme_on {
                let acme_cfg = &ent_file.tls.acme;
                let strategy = match acme_cfg.challenge_strategy() {
                    Ok(s) => s,
                    Err(e) => {
                        eprintln!("waf-enterprise: {e}");
                        std::process::exit(2);
                    }
                };
                let params = acme::AcmeParams {
                    domains: acme_cfg.domains.clone(),
                    email: acme_cfg.email.clone(),
                    cache_dir: acme_cfg.cache_dir.clone().into(),
                    staging: acme_cfg.staging,
                    directory_url: acme_cfg.directory_url.clone(),
                    strategy,
                };
                // The challenge strategy is GLOBAL to this `[tls.acme]` block, so a domain can
                // never run under both TLS-ALPN-01 and DNS-01 at once (R3: mutual exclusion by
                // construction — no per-domain conflict possible with this config shape).
                let resolver = match &params.strategy {
                    ChallengeStrategy::TlsAlpn01 => {
                        info!(domains = ?params.domains, staging = params.staging, "wiring managed ACME (TLS-ALPN-01, hitless)");
                        acme::start_resolver(&params).map_err(|e| {
                            error!(error = %e, "ACME resolver could not start; refusing to start");
                            e
                        })?
                    }
                    ChallengeStrategy::Dns01 { .. } => {
                        let provider = build_dns_provider(acme_cfg).map_err(|e| {
                            error!(error = %e, "DNS-01 provider could not be built; refusing to start");
                            e
                        })?;
                        info!(domains = ?params.domains, staging = params.staging, provider = ?acme_cfg.provider, cluster = shared_cert_store.is_some(), "wiring managed ACME (DNS-01, hitless)");
                        // Cluster mode passes the Redis SharedCertStore (Seam 1); None ⇒ single-node.
                        acme_dns01::start_dns01_resolver(&params, provider, acme_cfg.dns.to_config(), shared_cert_store.clone())
                            .map_err(|e| {
                                error!(error = %e, "DNS-01 resolver could not start; refusing to start");
                                e
                            })?
                    }
                };
                mb = mb.resolver(resolver);
            } else {
                // mTLS-only: the server cert still comes from the configured file pair
                // (the core's resolver-less path calls load()).
                mb = mb.file_fallback(FileCertSource::new(
                    config.tls.cert_path.clone(),
                    config.tls.key_path.clone(),
                ));
            }

            if mtls_on {
                let ca_path = ent_file.tls.mtls.ca_path.clone();
                info!(ca = %ca_path, "wiring mTLS client-cert verification");
                let verifier = mtls::verifier_from_ca_file(Path::new(&ca_path)).map_err(|e| {
                    error!(error = %e, "mTLS verifier could not be built; refusing to start");
                    e
                })?;
                mb = mb.client_verifier(verifier);
            }

            builder = builder.cert_source(Arc::new(mb.build()));
        }
    }

    // ── Seam 2 (follow-on): enterprise TLS cert source (ACME / managed PKI / mTLS).
    //     builder = builder.cert_source(Arc::new(AcmeCertSource::new(..)));
    // ── Seam 3 (follow-on): premium detection modules.
    //     builder = builder.modules(premium_modules);
    //     NOTE: extra modules do NOT survive SIGHUP yet (core `.module_factory` TBD).

    let proxy = builder.build().await?;
    info!(addr = %proxy.local_addr()?, "listening (enterprise)");

    // Hot reload (SIGHUP) — same wiring as the OPEN binary; the injected seams are
    // preserved across the validate-then-swap.
    #[cfg(unix)]
    {
        let reloader = proxy.reloader();
        let reload_path = config_path.clone();
        tokio::spawn(async move {
            let mut hangup = match tokio::signal::unix::signal(
                tokio::signal::unix::SignalKind::hangup(),
            ) {
                Ok(s) => s,
                Err(e) => {
                    warn!(error = %e, "cannot install SIGHUP handler; hot reload disabled");
                    return;
                }
            };
            while hangup.recv().await.is_some() {
                info!(path = %reload_path.display(), "SIGHUP received; reloading config");
                if let Err(e) = reloader.reload_from(&reload_path) {
                    error!(error = %e, "SIGHUP reload failed; current config kept");
                }
            }
        });
    }

    proxy.run().await
}
