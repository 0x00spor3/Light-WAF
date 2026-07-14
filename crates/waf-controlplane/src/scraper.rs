// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: BUSL-1.1

//! Background `/metrics` scraper. Every `interval` it GETs each node's Prometheus endpoint, extracts
//! the `waf_requests_total{decision}` counters and stores a per-decision rollup snapshot (long-term
//! retention / time-series, since Prometheus itself keeps only its own window). Errors are logged,
//! never fatal — a dead node must not take the control plane down.

use std::time::Duration;

use time::OffsetDateTime;
use tracing::{info, warn};

use crate::config::NodeConfig;
use crate::model::MetricRollup;
use crate::prometheus::{parse_latency_buckets, parse_requests_total};
use crate::store::Store;

type BoxErr = Box<dyn std::error::Error + Send + Sync>;

/// Run the scrape loop forever (spawn it as a background task). No-op if no nodes are configured.
pub async fn run_scraper(store: Store, nodes: Vec<NodeConfig>, interval_secs: u64) {
    if nodes.is_empty() {
        info!("scraper: no [[controlplane.nodes]] configured; /metrics scraping disabled");
        return;
    }
    let client = match reqwest::Client::builder().timeout(Duration::from_secs(10)).build() {
        Ok(c) => c,
        Err(e) => {
            warn!(error = %e, "scraper: cannot build HTTP client; scraping disabled");
            return;
        }
    };
    let mut ticker = tokio::time::interval(Duration::from_secs(interval_secs.max(1)));
    loop {
        ticker.tick().await;
        for node in &nodes {
            match scrape_node(&client, &store, node).await {
                Ok(n) => info!(node = %node.name, samples = n, "scraped /metrics"),
                Err(e) => warn!(node = %node.name, url = %node.metrics_url, error = %e, "scrape failed"),
            }
        }
    }
}

/// Scrape one node and store its per-decision rollups. Returns how many samples were stored.
async fn scrape_node(client: &reqwest::Client, store: &Store, node: &NodeConfig) -> Result<usize, BoxErr> {
    let text = client.get(&node.metrics_url).send().await?.error_for_status()?.text().await?;
    let counts = parse_requests_total(&text);
    let buckets = parse_latency_buckets(&text);
    let ts = OffsetDateTime::now_utc();
    // Raw snapshot (long-term time-series history) …
    for c in &counts {
        store
            .insert_metric_rollup(&MetricRollup {
                ts,
                node: node.name.clone(),
                decision: c.decision.clone(),
                count: c.count,
            })
            .await?;
    }
    if !buckets.is_empty() {
        store.insert_latency_buckets(&node.name, ts, &buckets).await?;
    }
    // … plus the reset-aware running totals that drive the dashboard's cumulative volumes + lifetime
    // latency (these survive WAF restarts, when the Prometheus counters reset to zero).
    store.accumulate_metric_totals(&node.name, &counts, ts).await?;
    if !buckets.is_empty() {
        store.accumulate_latency_totals(&node.name, &buckets, ts).await?;
    }
    Ok(counts.len() + buckets.len())
}
