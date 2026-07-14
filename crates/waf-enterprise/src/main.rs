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
use waf_state_redis::{
    CertCipher, DistributedLock, RedisStore, RedisStoreOptions, ReputationWriter, SharedCertStore,
};
use waf_tls_managed::acme::ChallengeStrategy;
use waf_tls_managed::dns::{CloudflareDns, DnsProvider, Route53Dns};
use waf_tls_managed::{acme, acme_dns01, mtls, ManagedTlsCertSource};
use waf_detection::crs::CrsModule;
use waf_marketplace::{load_verified_plugin, WasmOptions};
use waf_modules_premium::{
    BotDetectionConfig, BotDetectionModule, GraphqlSchemaModule, GrpcSchemaEnforcementConfig,
    GrpcSchemaModule, SchemaEnforcementConfig,
};
use waf_threatintel::{
    start_reputation_feed, FileFeed, HttpListFeed, ReputationConfig, ReputationFeed,
    ReputationModule,
};

/// Owned copy of one signed-WASM plugin's paths, captured by the module factory (core 0.3) so
/// the plugin is re-read and re-verified on every reload — never a borrow of the parsed config.
struct WasmPluginSpec {
    name: String,
    wasm_path: String,
    sig_path: String,
    config: Option<String>,
}

/// Owned spec for the signed-WASM module set, captured by the module factory (core 0.3).
struct WasmFactorySpec {
    plugins: Vec<WasmPluginSpec>,
    trusted_keys: Vec<String>,
    opts: WasmOptions,
}

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

/// Build the threat-intel feed sources from `[enterprise.reputation.feed.sources]`. The verdict and
/// kind are validated here; an HTTP source can also fail while building its TLS client. Boot-fatal
/// on any error (a misconfigured feed must not silently do nothing).
fn build_feed_sources(
    feed: &config::FeedSection,
) -> Result<Vec<Box<dyn ReputationFeed>>, Box<dyn std::error::Error + Send + Sync>> {
    let mut sources: Vec<Box<dyn ReputationFeed>> = Vec::new();
    for s in &feed.sources {
        let verdict = s.verdict()?;
        match s.kind.trim().to_ascii_lowercase().as_str() {
            "file" => sources.push(Box::new(FileFeed::new(s.location.clone(), verdict))),
            "http" => sources.push(Box::new(HttpListFeed::new(s.location.clone(), verdict)?)),
            other => {
                return Err(format!(
                    "unknown [enterprise.reputation.feed] source kind {other:?} (use \"file\" or \"http\")"
                )
                .into())
            }
        }
    }
    Ok(sources)
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

    // Demo builds gate startup on a signed, time-limited license (no-op otherwise).
    demo_license::enforce();

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
    // Keeps the threat-intel feed's background task alive for the process lifetime (§6).
    let mut _feed_handle: Option<tokio::task::JoinHandle<()>> = None;

    // ── core-0.3 module_factory: owned specs for the injected premium modules. We validate
    // config up front (boot-fatal on error, as before) and stash owned, cloneable specs here;
    // ONE factory closure (built just before `builder.build()`) rebuilds the modules from these.
    // The factory runs at boot AND on every reload, so these modules survive a SIGHUP — the
    // core no longer drops them to `Vec::new()`. `.add_module` is NOT used for them any more.
    let mut rep_spec: Option<(Arc<RedisStore>, ReputationConfig)> = None;
    let mut crs_curated_on = false;
    let mut se_cfg: Option<SchemaEnforcementConfig> = None;
    let mut ge_cfg: Option<GrpcSchemaEnforcementConfig> = None;
    let mut bd_cfg: Option<BotDetectionConfig> = None;
    let mut wasm_spec: Option<WasmFactorySpec> = None;

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
    // The feed populates `rep:<ip>` in Redis; it needs the store but NOT the local reputation
    // module (a node can be a dedicated feed-writer while others read). So it drives `needs_store`
    // on its own.
    let feed_on = ent.reputation.feed.enabled;
    let needs_store = config.rate_limit.enabled || reputation_on || cluster_certs || feed_on;
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
                // Captured by the module factory (survives reload). Store is process-lifetime.
                rep_spec = Some((store.clone(), ReputationConfig { enabled: true, malicious, suspicious }));
            }
            if cluster_certs {
                // The SAME store also backs cluster cert coordination (Step 3): the DNS-01 driver
                // (Seam 2) uses it as the SharedCertStore. RedisStore impls the trait.
                info!(redis = %url, source = url_src, "wiring cluster-wide SharedCertStore (multi-node cert coordination)");
                shared_cert_store = Some(store.clone());
            }
            if feed_on {
                // §6 threat-intel feed: the SAME store is both the ReputationWriter (writes
                // `rep:<ip>`) and the DistributedLock (single-writer per cycle — F4). A background
                // task refreshes the snapshot the reputation module reads.
                if !reputation_on {
                    warn!("[enterprise.reputation.feed] is enabled but [enterprise.reputation] is not — this node only POPULATES reputation for other nodes to read");
                }
                let sources = match build_feed_sources(&ent.reputation.feed) {
                    Ok(s) => s,
                    Err(e) => {
                        eprintln!("waf-enterprise: {e}");
                        std::process::exit(2);
                    }
                };
                if sources.is_empty() {
                    warn!("[enterprise.reputation.feed].enabled = true but no sources configured — feed NOT started");
                } else {
                    info!(redis = %url, source = url_src, sources = sources.len(), "starting threat-intel reputation feed (single-writer)");
                    let writer: Arc<dyn ReputationWriter> = store.clone();
                    let lock: Arc<dyn DistributedLock> = store.clone();
                    _feed_handle =
                        Some(start_reputation_feed(sources, writer, lock, ent.reputation.feed.to_config()));
                }
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
        // The feed writes to the shared store; there is no in-memory reputation to populate.
        None if feed_on => {
            error!("[enterprise.reputation.feed].enabled = true but no redis_url — the feed writes to Redis; refusing to start");
            return Err("[enterprise.reputation.feed] enabled without redis_url".into());
        }
        None => info!("no redis_url ([enterprise] or WAF_REDIS_URL) — using the OPEN in-memory rate-limit store (single-node)"),
    }

    // ── Seam 3: premium detection modules — curated CRS ruleset content (§6).
    // The `seclang` engine is OPEN; here we load the enterprise `waf-crs-curated` CONTENT and
    // inject it as a `WafModule`. Premium-additive: it contributes to the SAME cumulative score
    // as the native modules (double-count accepted — the operator tunes the threshold with CRS on).
    if ent.crs_curated.enabled {
        // Validate the load once at boot (the factory rebuilds it identically on each reload —
        // the curated source is embedded, so a reload cannot make it fail). The loaded-count gate
        // stays here as a boot-time diagnostic.
        let module = CrsModule::from_source(&waf_crs_curated::curated_source());
        info!(expected = waf_crs_curated::EXPECTED_LOADED, "wiring curated premium CRS ruleset: {}", module.report());
        if module.loaded_count() < waf_crs_curated::EXPECTED_LOADED {
            warn!(
                loaded = module.loaded_count(),
                expected = waf_crs_curated::EXPECTED_LOADED,
                "curated CRS: fewer rules loaded than expected — the OPEN engine subset may have changed"
            );
        }
        crs_curated_on = true;
    }

    // ── Seam 3: premium detection modules — GraphQL schema-enforcement (§4-B).
    // Validates each GraphQL operation against the app's REAL SDL schema. Premium-additive: it
    // contributes to the SAME cumulative anomaly score as the native modules (governance of the
    // schema, not baseline detection — the OPEN §6/Phase-11 modules keep value-injection and DoS caps).
    if ent.schema_enforcement.enabled {
        let cfg = match ent.schema_enforcement.to_config() {
            Ok(c) => c,
            Err(e) => {
                eprintln!("waf-enterprise: {e}");
                std::process::exit(2);
            }
        };
        info!(
            schema = %cfg.schema_path.display(),
            paths = ?cfg.paths,
            "wiring GraphQL schema-enforcement module (§4-B)"
        );
        // The SDL is loaded (and re-loaded on reload) inside the module factory via the SAME pure
        // `load_schema`: boot-fatal on an invalid schema; on a reload that goes invalid the whole
        // reload aborts and the last-good module is kept (core-0.3 whole-set fallibility).
        se_cfg = Some(cfg);
    }

    // ── Seam 3: premium detection modules — gRPC schema-enforcement (§4-B part 2).
    // Validates each unary gRPC message against the app's compiled FileDescriptorSet. Same posture
    // as the GraphQL module: governance of the schema, additive `Decision::Scores`, zero core.
    if ent.grpc_schema_enforcement.enabled {
        let cfg = match ent.grpc_schema_enforcement.to_config() {
            Ok(c) => c,
            Err(e) => {
                eprintln!("waf-enterprise: {e}");
                std::process::exit(2);
            }
        };
        info!(
            descriptor = %cfg.descriptor_path.display(),
            flag_unknown_fields = cfg.flag_unknown_fields,
            "wiring gRPC schema-enforcement module (§4-B part 2)"
        );
        // The descriptor is loaded (and re-loaded on reload) inside the module factory: boot-fatal
        // on a missing/invalid descriptor; whole-set abort keeps the last-good module on a bad reload.
        ge_cfg = Some(cfg);
    }

    // ── Seam 3: premium detection modules — client-integrity / bot detection (§4-A).
    // Native cross-header heuristics (browser impersonation). Additive `Decision::Scores`, zero core.
    if ent.bot_detection.enabled {
        let cfg = match ent.bot_detection.to_config() {
            Ok(c) => c,
            Err(e) => {
                eprintln!("waf-enterprise: {e}");
                std::process::exit(2);
            }
        };
        // Construction is infallible (native heuristics — no schema/file to load), so the factory
        // rebuilds it identically on every reload.
        info!("wiring client-integrity / bot-detection module (§4-A)");
        bd_cfg = Some(cfg);
    }

    // ── Seam 3: signed WASM plugins — verify a minisign signature before loading (§4-C).
    // A signed plugin that does not verify is boot-fatal (fail-closed, K5); this is the enterprise
    // trust gate on top of the OPEN Proxy-Wasm runtime.
    if ent.wasm.enabled {
        // K6 enforcement: `exclusive` refuses to boot if the OPEN [modules.wasm] also loads plugins
        // (which would be UNSIGNED, bypassing the gate).
        if ent.wasm.exclusive_conflict(&config.modules.wasm) {
            eprintln!(
                "waf-enterprise: [enterprise.wasm].exclusive = true but [modules.wasm] loads {} \
                 unsigned plugin(s) — refusing to boot (they would bypass signature verification)",
                config.modules.wasm.plugins.len()
            );
            std::process::exit(2);
        }
        if ent.wasm.trusted_keys.is_empty() {
            eprintln!("waf-enterprise: [enterprise.wasm].enabled but no trusted_keys — nothing can verify");
            std::process::exit(2);
        }
        // The plugin is re-read from disk AND its signature re-verified inside the module factory,
        // at boot AND on every reload — so a signed plugin rotated on disk is picked up (and a
        // tampered one is rejected) on reload, fail-closed. Only owned paths/keys are captured.
        let plugins = ent
            .wasm
            .plugins
            .iter()
            .map(|p| WasmPluginSpec {
                name: std::path::Path::new(&p.wasm_path)
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("plugin")
                    .to_string(),
                wasm_path: p.wasm_path.clone(),
                sig_path: p.sig_path.clone(),
                config: p.config.clone(),
            })
            .collect();
        info!(plugins = ent.wasm.plugins.len(), "wiring signed WASM plugins (§4-C, verified in the module factory)");
        wasm_spec = Some(WasmFactorySpec {
            plugins,
            trusted_keys: ent.wasm.trusted_keys.clone(),
            opts: ent.wasm.to_options(),
        });
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

    // ── core-0.3 module_factory: ONE closure that (re)builds every injected premium module from
    // the owned specs gathered above. The core runs it at bind AND on every reload, so these
    // modules SURVIVE a SIGHUP and are re-`init`'d — the old `.add_module` set was silently
    // dropped by the core's `Vec::new()` on reload. Whole-set fallibility: if any module fails to
    // rebuild (e.g. an SDL/descriptor went invalid, or a signed WASM plugin no longer verifies),
    // the factory returns `Err`, the core aborts that reload, and the last-good modules are kept.
    let has_factory_modules = rep_spec.is_some()
        || crs_curated_on
        || se_cfg.is_some()
        || ge_cfg.is_some()
        || bd_cfg.is_some()
        || wasm_spec.is_some();
    if has_factory_modules {
        builder = builder.module_factory(move || {
            let mut mods: Vec<Box<dyn waf_core::WafModule>> = Vec::new();
            if let Some((store, cfg)) = &rep_spec {
                mods.push(Box::new(ReputationModule::new(store.clone(), *cfg)));
            }
            if crs_curated_on {
                mods.push(Box::new(CrsModule::from_source(&waf_crs_curated::curated_source())));
            }
            if let Some(cfg) = &se_cfg {
                let m = GraphqlSchemaModule::from_config(cfg)
                    .map_err(|e| format!("GraphQL schema-enforcement: {e}"))?;
                mods.push(Box::new(m));
            }
            if let Some(cfg) = &ge_cfg {
                let m = GrpcSchemaModule::from_config(cfg)
                    .map_err(|e| format!("gRPC schema-enforcement: {e}"))?;
                mods.push(Box::new(m));
            }
            if let Some(cfg) = &bd_cfg {
                mods.push(Box::new(BotDetectionModule::from_config(cfg)));
            }
            if let Some(w) = &wasm_spec {
                for p in &w.plugins {
                    let wasm = std::fs::read(&p.wasm_path)
                        .map_err(|e| format!("cannot read {}: {e}", p.wasm_path))?;
                    let sig = std::fs::read_to_string(&p.sig_path)
                        .map_err(|e| format!("cannot read {}: {e}", p.sig_path))?;
                    let cfg_bytes = p.config.as_deref().unwrap_or("").as_bytes();
                    let m = load_verified_plugin(&p.name, &wasm, &sig, &w.trusted_keys, cfg_bytes, &w.opts)
                        .map_err(|e| format!("signed WASM plugin {:?}: {e}", p.name))?;
                    mods.push(Box::new(m));
                }
            }
            Ok(mods)
        });
    }

    // ── Seam 2 (follow-on): enterprise TLS cert source (ACME / managed PKI / mTLS).
    //     builder = builder.cert_source(Arc::new(AcmeCertSource::new(..)));

    let proxy = builder.build().await?;
    info!(addr = %proxy.local_addr()?, "listening (enterprise)");

    // Hot reload (SIGHUP) — same wiring as the OPEN binary. All injected extension points now
    // survive the validate-then-swap: the *seams* (`state_store` via the shared rate-limit state,
    // `cert_source` on the immutable acceptor) as before, AND the injected *modules* — the core-0.3
    // `.module_factory` re-runs the closure above on every reload (in place of the old `Vec::new()`),
    // so reputation / curated CRS / schema-enforcement / bot / signed-WASM are rebuilt and re-`init`'d
    // (e.g. a changed GraphQL SDL is reloaded). A rebuild that fails aborts that reload, last-good kept.
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

/// Demo-license gate: on a `demo-license` build, verify the license at boot (terminate if invalid or
/// expired) and spawn a watchdog that stops the process when it later expires. A plain build is a no-op.
#[cfg(feature = "demo-license")]
mod demo_license {
    pub fn enforce() {
        waf_license::enforce_boot();
        tokio::spawn(waf_license::watchdog(std::time::Duration::from_secs(900)));
    }
}
#[cfg(not(feature = "demo-license"))]
mod demo_license {
    pub fn enforce() {}
}
