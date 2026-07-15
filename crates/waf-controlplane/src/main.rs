// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: BUSL-1.1

//! Light WAF control-plane service (§7). Loads config, connects to Postgres + migrates, starts the
//! background `/metrics` scraper, and serves the HTTP surface (ingest endpoint + health; the read
//! API is added in Phase 3). Config path = argv[1] or `controlplane.toml`.

use std::process::ExitCode;
use std::sync::Arc;

use tracing::{error, info, warn};
use waf_controlplane::gov_api::setup_governance;
use waf_controlplane::scraper::run_scraper;
use waf_controlplane::{
    app, run_evaluator, AppState, ControlPlaneConfig, EventBus, Ingestor, SiemForwarder, Store,
};

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            error!(error = %e, "control plane failed to start");
            ExitCode::from(2)
        }
    }
}

async fn run() -> waf_controlplane::Result<()> {
    // The `reqwest` scrape client is built with `rustls-no-provider`, so install ONE process-level
    // ring provider (mirrors the other enterprise crates) — needed only if a node's /metrics is https.
    let _ = rustls::crypto::ring::default_provider().install_default();

    // Demo builds gate startup on a signed, time-limited license (no-op otherwise).
    demo_license::enforce();

    let path = std::env::args().nth(1).unwrap_or_else(|| "controlplane.toml".to_string());
    let config = ControlPlaneConfig::load(&path)?;
    config.validate()?;

    let db_url = config.require_database_url()?;
    let store = Store::connect(db_url).await?;
    store.migrate().await?;
    info!("control plane: connected to Postgres and applied migrations");

    // Governance (§8): apply the schema, load the audit key, bootstrap the first admin. `None` when
    // disabled (the control plane then keeps the single static bearer, no sessions — backward-compat).
    let governance = setup_governance(&config, &store).await?;

    // Live change bus for the dashboard SSE stream — shared by the ingest handler (events) and the
    // alert evaluator (alerts), consumed by `GET /api/stream`.
    let bus = EventBus::new();

    // Background /metrics scraper (no-op if no nodes configured).
    tokio::spawn(run_scraper(store.clone(), config.nodes.clone(), config.scrape_interval_seconds));

    // Background alert evaluator (v2), only when enabled.
    if config.alerting.enabled {
        info!(rules = config.alerts.len(), "alerting enabled; starting evaluator");
        tokio::spawn(run_evaluator(
            store.clone(),
            config.alerts.clone(),
            config.alerting.webhook_url.clone(),
            config.alerting.eval_interval_seconds,
            bus.clone(),
        ));
    }

    // SIEM export forwarder (§9), only when enabled. Grab the shared status handle for the API, then
    // spawn the background flush loop (zero-datapath: it reads the stores; the WAF is unaware).
    let siem = if config.siem.enabled {
        info!(destinations = config.siem.destinations.len(), "siem export enabled; starting forwarder");
        let forwarder = SiemForwarder::new(store.clone(), config.siem.clone());
        let handle = forwarder.status();
        tokio::spawn(forwarder.run());
        Some((config.siem.clone(), handle))
    } else {
        None
    };

    // API-inventory classification spec (§4-B pt3 discovery). Optional; a missing/invalid spec is
    // NOT fatal (the control plane is off-path) — the inventory is just served unclassified.
    let api_routes = match config.api_inventory.spec_path.as_deref() {
        Some(path) => match std::fs::read_to_string(path) {
            Ok(json) => match waf_controlplane::inventory::SpecRoutes::from_spec_json(&json) {
                Some(r) => {
                    info!(spec = %path, "loaded OpenAPI spec for API-inventory classification");
                    Some(r)
                }
                None => {
                    warn!(spec = %path, "api_inventory spec is not valid JSON — inventory served unclassified");
                    None
                }
            },
            Err(e) => {
                warn!(spec = %path, error = %e, "cannot read api_inventory spec — inventory served unclassified");
                None
            }
        },
        None => None,
    };

    // HTTP surface.
    if config.api_token.is_none() {
        warn!("no [controlplane].api_token (nor WAF_CP_API_TOKEN) — the ingest endpoint is UNAUTHENTICATED (dev only)");
    }
    let state = Arc::new(AppState {
        ingestor: Ingestor::new(store.clone()),
        store,
        alert_rules: config.alerts.clone(),
        ui_dir: config.ui_dir.clone(),
        api_token: config.api_token.clone(),
        governance,
        siem,
        bus,
        api_routes,
    });
    let listener = tokio::net::TcpListener::bind(&config.listen).await?;
    info!(listen = %config.listen, nodes = config.nodes.len(), "control plane HTTP listening (ingest + health)");
    axum::serve(listener, app(state)).await?;
    Ok(())
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
