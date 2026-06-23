// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

use tracing::info;
use waf_proxy::Proxy;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    // Path precedence: CLI --config > env WAF_CONFIG > default config.toml.
    let args: Vec<String> = std::env::args().skip(1).collect();
    let config_path =
        waf_proxy::config::resolve_path(&args, std::env::var(waf_proxy::config::ENV_CONFIG).ok());

    // Fail-fast: any error (missing file, bad TOML, invalid value) → stderr + exit 2.
    let config = match waf_proxy::config::load(&config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("waf: {e}");
            std::process::exit(2);
        }
    };

    info!(
        listen = %config.proxy.listen,
        backend = %config.proxy.backend,
        mode = ?config.waf.mode,
        "WAF starting"
    );

    let proxy = Proxy::bind(&config).await?;
    info!(addr = %proxy.local_addr()?, "listening");

    // Hot reload trigger (Fase 6 / Pillar 3): SIGHUP re-reads the same config
    // path and atomically swaps. Unix-only — the signal is just the button; the
    // validate-then-swap logic (`Reloader`) is OS-agnostic and what tests drive.
    #[cfg(unix)]
    {
        use tracing::{error, warn};
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
                // Distinguish "signal received" from "reload ok/failed".
                info!(path = %reload_path.display(), "SIGHUP received; reloading config");
                if let Err(e) = reloader.reload_from(&reload_path) {
                    error!(error = %e, "SIGHUP reload failed; current config kept");
                }
            }
        });
    }

    proxy.run().await
}
