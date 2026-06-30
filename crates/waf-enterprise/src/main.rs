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
use waf_state_redis::{RedisStore, RedisStoreOptions};
use waf_tls_managed::{acme, mtls, ManagedTlsCertSource};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

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

    let mut builder = Proxy::builder(&config);

    // ── Seam 1: distributed rate-limit StateStore (Redis). Source for the URL is
    // `WAF_REDIS_URL` (env wins, for ops overrides) else `[enterprise].redis_url`.
    // The injected store survives SIGHUP (it lives in the proxy's process-lifetime
    // state), so distributed limiting is not reset to single-node on a reload.
    let (redis_url, url_src) = match std::env::var("WAF_REDIS_URL").ok().filter(|s| !s.is_empty()) {
        Some(u) => (Some(u), "WAF_REDIS_URL env"),
        None => (ent.redis_url.clone(), "[enterprise].redis_url"),
    };
    match redis_url {
        Some(url) if config.rate_limit.enabled => {
            let mut opts = RedisStoreOptions::default();
            if let Some(ps) = ent.pool_size {
                opts.pool_size = ps;
            }
            opts.fail_open = ent.fail_open;
            info!(
                redis = %url, source = url_src, pool_size = opts.pool_size, fail_open = opts.fail_open,
                "wiring distributed rate-limit StateStore (Redis)"
            );
            // Boot-time validation: a configured-but-unreachable Redis is fatal —
            // silently degrading to in-memory would be "looks-protected-but-isn't".
            // (Runtime Redis errors follow `fail_open`, inside the store.)
            let store = match RedisStore::connect_with_options(&url, opts) {
                Ok(s) => s,
                Err(e) => {
                    error!(error = %e, "configured Redis unreachable; refusing to start");
                    return Err(e.into());
                }
            };
            builder = builder.state_store(Arc::new(store));
        }
        Some(_) => warn!(source = url_src, "redis_url configured but [rate_limit] is disabled — Redis store NOT wired"),
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
                info!(domains = ?params.domains, staging = params.staging, "wiring managed ACME server certs (hitless)");
                let resolver = acme::start_resolver(&params).map_err(|e| {
                    error!(error = %e, "ACME resolver could not start; refusing to start");
                    e
                })?;
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
