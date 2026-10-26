// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

//! SIEM forwarder (§9, S2/S3): the delivery engine. It polls new stored events per `(destination,
//! stream)` cursor, formats a batch (via the pluggable `SiemFormatter`) and POSTs it to the sink.
//! Delivery is **at-least-once**: the cursor advances ONLY after the WHOLE batch is acked (HTTP 2xx);
//! on any failure it stays put and the batch is retransmitted next cycle (the SIEM dedups on the stable
//! `event.id`).
//!
//! Backpressure is bounded by Postgres itself (retention) — there is no in-memory queue; a sink that is
//! down just lets the cursor lag, which is the key operational signal (surfaced by `GET /api/siem/status`
//! + logged). Zero-datapath: it reads the control-plane stores; the WAF is unaware of the SIEM.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use time::OffsetDateTime;
use tracing::{info, warn};
use waf_governance::store as gov_store;

use crate::config::{SiemConfig, SiemDestination, SiemStream};
use crate::siem::{alert_to_siem, audit_to_siem, decision_to_siem, formatter_for, SiemEvent};
use crate::store::Store;

/// Whether an HTTP status counts as a successful delivery (the cursor may advance).
pub fn is_success(status: u16) -> bool {
    (200..300).contains(&status)
}

/// Live delivery status for one `(destination, stream)` — surfaced by `GET /api/siem/status`.
#[derive(Debug, Clone, Default)]
pub struct StreamStatus {
    /// The last cursor value persisted on a successful delivery.
    pub last_cursor: i64,
    /// Events delivered in the last successful batch.
    pub last_delivered: u64,
    pub last_success_at: Option<OffsetDateTime>,
    pub last_error: Option<String>,
    pub last_error_at: Option<OffsetDateTime>,
}

/// Shared, in-memory per-`(destination, stream)` status (updated by the forwarder, read by the API).
pub type SiemStatusHandle = Arc<Mutex<HashMap<(String, String), StreamStatus>>>;

/// The head (max id/seq) of a stream — for the export lag (`head - cursor`).
pub async fn stream_head(store: &Store, stream: SiemStream) -> crate::Result<i64> {
    match stream {
        SiemStream::Decisions => store.decisions_max_id().await,
        SiemStream::Audit => gov_store::audit_max_seq(store.pool())
            .await
            .map_err(|e| crate::Error::Config(e.to_string())),
        SiemStream::Alerts => store.alerts_max_id().await,
    }
}

/// The SIEM forwarder: a store handle + config + one reusable HTTP client + shared live status.
pub struct SiemForwarder {
    store: Store,
    config: SiemConfig,
    client: reqwest::Client,
    status: SiemStatusHandle,
}

impl SiemForwarder {
    pub fn new(store: Store, config: SiemConfig) -> Self {
        Self { store, config, client: reqwest::Client::new(), status: Arc::new(Mutex::new(HashMap::new())) }
    }

    /// A cheap clone of the shared status handle (share it with `AppState` before spawning `run`).
    pub fn status(&self) -> SiemStatusHandle {
        Arc::clone(&self.status)
    }

    /// Fetch one batch for a stream since `after` → `(events, max_id)`. `max_id` is the highest id/seq
    /// in the batch (the cursor to persist on success); `after` when the batch is empty.
    async fn fetch(&self, stream: SiemStream, after: i64) -> crate::Result<(Vec<SiemEvent>, i64)> {
        let limit = self.config.batch_size;
        let (events, max_id) = match stream {
            SiemStream::Decisions => {
                let rows = self.store.fetch_decisions_since(after, limit).await?;
                let max = rows.last().map(|(id, _)| *id).unwrap_or(after);
                (rows.iter().map(|(id, ev)| decision_to_siem(*id, ev)).collect(), max)
            }
            SiemStream::Audit => {
                let rows = gov_store::audit_since(self.store.pool(), after, limit)
                    .await
                    .map_err(|e| crate::Error::Config(e.to_string()))?;
                let max = rows.last().map(|r| r.seq).unwrap_or(after);
                (rows.iter().map(audit_to_siem).collect(), max)
            }
            SiemStream::Alerts => {
                let rows = self.store.fetch_alerts_since(after, limit).await?;
                let max = rows.last().map(|(id, _)| *id).unwrap_or(after);
                (rows.iter().map(|(id, a)| alert_to_siem(*id, a)).collect(), max)
            }
        };
        Ok((events, max_id))
    }

    /// POST a formatted batch to the destination; `Ok` only on a 2xx ack. `auth_header` is sent as the
    /// `Authorization` header value (e.g. `Splunk <token>` / `ApiKey <key>`).
    async fn deliver(&self, dest: &SiemDestination, bytes: Vec<u8>, content_type: &str) -> Result<(), String> {
        let mut req = self
            .client
            .post(&dest.endpoint)
            .header(reqwest::header::CONTENT_TYPE, content_type)
            .body(bytes);
        if let Some(h) = &dest.auth_header {
            req = req.header(reqwest::header::AUTHORIZATION, h);
        }
        let resp = req.send().await.map_err(|e| e.to_string())?;
        let status = resp.status().as_u16();
        if is_success(status) {
            Ok(())
        } else {
            Err(format!("HTTP {status}"))
        }
    }

    fn record_success(&self, dest: &str, stream: SiemStream, cursor: i64, delivered: usize) {
        let mut m = self.status.lock().unwrap();
        let s = m.entry((dest.to_string(), stream.as_str().to_string())).or_default();
        s.last_cursor = cursor;
        s.last_delivered = delivered as u64;
        s.last_success_at = Some(OffsetDateTime::now_utc());
    }

    fn record_error(&self, dest: &str, stream: SiemStream, err: &str) {
        let mut m = self.status.lock().unwrap();
        let s = m.entry((dest.to_string(), stream.as_str().to_string())).or_default();
        s.last_error = Some(err.to_string());
        s.last_error_at = Some(OffsetDateTime::now_utc());
    }

    /// Forward one stream for one destination: read cursor → fetch batch → deliver → advance ONLY on
    /// a 2xx ack. Empty batch = caught up. Returns the number of events delivered.
    async fn forward_stream(&self, dest: &SiemDestination, stream: SiemStream) -> Result<usize, String> {
        let cursor = self
            .store
            .siem_get_cursor(&dest.name, stream.as_str())
            .await
            .map_err(|e| e.to_string())?;
        let (events, max_id) = self.fetch(stream, cursor).await.map_err(|e| e.to_string())?;
        if events.is_empty() {
            return Ok(0);
        }
        let fmt = formatter_for(dest.format);
        let bytes = fmt.format_batch(&events);
        match self.deliver(dest, bytes, fmt.content_type()).await {
            Ok(()) => {
                // Advance the cursor ONLY now (whole batch acked).
                self.store
                    .siem_set_cursor(&dest.name, stream.as_str(), max_id)
                    .await
                    .map_err(|e| e.to_string())?;
                self.record_success(&dest.name, stream, max_id, events.len());
                let lag = stream_head(&self.store, stream).await.unwrap_or(max_id) - max_id;
                info!(destination = %dest.name, stream = stream.as_str(), delivered = events.len(), cursor = max_id, lag, "siem batch delivered");
                Ok(events.len())
            }
            Err(e) => {
                // Cursor NOT advanced → the batch is retransmitted next cycle (at-least-once).
                self.record_error(&dest.name, stream, &e);
                Err(e)
            }
        }
    }

    /// Run one flush cycle over every destination × stream. A per-stream failure is logged (the lag
    /// grows) but never blocks the other streams/destinations.
    pub async fn forward_once(&self) {
        for dest in &self.config.destinations {
            for &stream in &dest.streams {
                if let Err(e) = self.forward_stream(dest, stream).await {
                    warn!(destination = %dest.name, stream = stream.as_str(), error = %e, "siem forward failed (will retry)");
                }
            }
        }
    }

    /// Background driver: flush on `flush_interval_seconds` forever. Spawn after grabbing [`Self::status`].
    pub async fn run(self) {
        let interval = Duration::from_secs(self.config.flush_interval_seconds.max(1));
        info!(destinations = self.config.destinations.len(), "siem forwarder started");
        loop {
            self.forward_once().await;
            tokio::time::sleep(interval).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_success_is_2xx_only() {
        assert!(is_success(200));
        assert!(is_success(202));
        assert!(is_success(299));
        assert!(!is_success(300));
        assert!(!is_success(400));
        assert!(!is_success(500));
    }
}
