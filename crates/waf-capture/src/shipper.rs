// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: BUSL-1.1

//! The HTTP shipper — the decision-path half of the transport.
//!
//! Captures leave the ring on the (rare) denied path and are handed to a bounded channel; a single
//! background task drains it and `POST`s each capture to the control-plane `/ingest/captures` with a
//! short retry. The channel is **bounded** and the hand-off is non-blocking ([`CaptureSink::enqueue`]
//! uses `try_send`): under a burst the shipper drops rather than back-pressuring the request path —
//! availability of the proxy always wins over completeness of forensics. Dropped/failed counts are
//! surfaced (atomic counter + periodic log) so the loss is visible, never silent.
//!
//! The reqwest client mirrors `waf-threatintel`'s `HttpListFeed`: `rustls-no-provider` + an explicit
//! `ring` provider, so capture shipping pulls no second crypto stack (no aws-lc-rs/cmake).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;
use tokio_rustls::rustls::crypto::ring;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tracing::{debug, info, warn};

use crate::{CaptureConfig, CapturedRequest};

/// Max POST attempts per capture before it is given up (best-effort).
const MAX_ATTEMPTS: u32 = 3;
/// Upstream round-trip timeout — a stalled control-plane must not pin the shipper.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

/// The producer half held by the verdict-join layer: a non-blocking handle onto the shipper queue.
/// Cloneable and cheap; dropping the last clone closes the channel and ends the shipper task.
#[derive(Clone)]
pub struct CaptureSink {
    tx: mpsc::Sender<CapturedRequest>,
    dropped: Arc<AtomicU64>,
}

impl CaptureSink {
    /// Create a sink and its receiver. Shared by [`CaptureShipper::spawn`] and tests.
    pub(crate) fn channel(capacity: usize) -> (Self, mpsc::Receiver<CapturedRequest>) {
        let (tx, rx) = mpsc::channel(capacity.max(1));
        (Self { tx, dropped: Arc::new(AtomicU64::new(0)) }, rx)
    }

    /// Enqueue a capture without blocking. On a full queue the capture is dropped and counted — the
    /// request path is never stalled by a slow/unreachable control-plane.
    pub fn enqueue(&self, capture: CapturedRequest) {
        if self.tx.try_send(capture).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Number of captures dropped because the queue was full (observability).
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

/// Spawns and owns the background shipping task.
pub struct CaptureShipper;

impl CaptureShipper {
    /// Build the HTTPS-capable client, spawn the drain-and-POST task, and return the producer sink.
    /// `token` (from the environment) is sent as a bearer on each POST when present. Errors only if
    /// the TLS/client cannot be built (boot-fatal at wiring).
    pub fn spawn(cfg: &CaptureConfig, token: Option<String>) -> Result<CaptureSink, String> {
        let client = build_client()?;
        let url = format!("{}/ingest/captures", cfg.controlplane_url.trim_end_matches('/'));
        let (sink, rx) = CaptureSink::channel(cfg.queue_capacity);
        let dropped = Arc::clone(&sink.dropped);
        tokio::spawn(ship_loop(rx, client, url, token, dropped));
        Ok(sink)
    }
}

/// reqwest client with a `ring`-based rustls config (public CA roots). Mirrors `HttpListFeed`.
fn build_client() -> Result<reqwest::Client, String> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let tls = ClientConfig::builder_with_provider(Arc::new(ring::default_provider()))
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("rustls client config: {e}"))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    reqwest::Client::builder()
        .use_preconfigured_tls(tls)
        .timeout(REQUEST_TIMEOUT)
        .build()
        .map_err(|e| format!("http client: {e}"))
}

/// Drain the queue, POSTing each capture with a short retry. Ends when every sink clone is dropped.
async fn ship_loop(
    mut rx: mpsc::Receiver<CapturedRequest>,
    client: reqwest::Client,
    url: String,
    token: Option<String>,
    dropped: Arc<AtomicU64>,
) {
    let (mut shipped, mut failed) = (0u64, 0u64);
    while let Some(capture) = rx.recv().await {
        let mut ok = false;
        for attempt in 1..=MAX_ATTEMPTS {
            let mut rb = client.post(&url).json(&capture);
            if let Some(t) = &token {
                rb = rb.bearer_auth(t);
            }
            match rb.send().await {
                Ok(resp) if resp.status().is_success() => {
                    ok = true;
                    break;
                }
                Ok(resp) => debug!(status = %resp.status(), attempt, "capture ship: non-2xx"),
                Err(e) => debug!(error = %e, attempt, "capture ship: request error"),
            }
            if attempt < MAX_ATTEMPTS {
                tokio::time::sleep(Duration::from_millis(200 * u64::from(attempt))).await;
            }
        }
        if ok {
            shipped += 1;
        } else {
            failed += 1;
            warn!(request_id = %capture.request_id, "capture shipping failed after retries; dropping");
        }
        // Periodic visibility without a log line per request.
        if (shipped + failed).is_multiple_of(50) {
            info!(shipped, failed, dropped = dropped.load(Ordering::Relaxed), "capture shipper stats");
        }
    }
}
