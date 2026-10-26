// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

//! Light WAF node-agent binary (§7 write-path v3). Loads config, then polls the control plane forever:
//! each cycle pulls the current ruleset, and on a new version pre-validates → writes the managed file
//! → runs `reload_command` (SIGHUP) → reports the outcome. Config path = argv[1] or `node-agent.toml`.

use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

use tracing::{error, info, warn};
use waf_node_agent::{poll_once, run_reload_command, AgentClient, AgentConfig, PollOutcome};

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
            error!(error = %e, "node agent failed to start");
            ExitCode::from(2)
        }
    }
}

async fn run() -> Result<(), String> {
    // reqwest is built with `rustls-no-provider`; install ONE process-level ring provider (mirrors
    // the other enterprise crates) — needed only if the control-plane URL is https.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let path = std::env::args().nth(1).unwrap_or_else(|| "node-agent.toml".to_string());
    let config = AgentConfig::load(&path)?;
    if config.token.is_none() {
        warn!("no [agent].token (nor WAF_AGENT_TOKEN) — requests to the control plane are unauthenticated");
    }

    let client = AgentClient::new(config.control_plane_url.clone(), config.token.clone());
    let managed = Path::new(&config.managed_file).to_path_buf();
    let interval = Duration::from_secs(config.poll_interval_seconds.max(1));
    info!(
        node = %config.node_name,
        control_plane = %config.control_plane_url,
        managed_file = %config.managed_file,
        poll_interval_seconds = config.poll_interval_seconds,
        "node agent started"
    );

    let mut last_applied: Option<i64> = None;
    loop {
        let reload_command = config.reload_command.clone();
        let outcome =
            poll_once(&client, &config.node_name, &managed, last_applied, || run_reload_command(&reload_command)).await;
        match outcome {
            PollOutcome::Unchanged => {}
            PollOutcome::Applied(v) => {
                last_applied = Some(v);
                info!(version = v, "applied new ruleset version and reloaded the WAF");
            }
            PollOutcome::Rejected { version, reason } => {
                warn!(version, reason, "rejected ruleset version (pre-validation failed); WAF untouched");
            }
            PollOutcome::Error(msg) => {
                error!(error = %msg, "poll cycle failed");
            }
        }
        tokio::time::sleep(interval).await;
    }
}
