// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

//! The verdict-join `tracing::Layer`.
//!
//! The capture module cannot see the WAF's final verdict (the pipeline decides it after every module
//! runs). The decision, however, is emitted as a structured `tracing` event — `request blocked` /
//! `request rejected`, carrying `request_id` — which the control-plane ingest already relies on. This
//! layer reads those same events: on a denial it pulls the matching capture out of the ring and hands
//! it to the shipper. Everything else ages out of the ring unshipped.
//!
//! # Deferred arming
//! The enterprise subscriber is installed at the very top of `main`, *before* the config is read, so
//! the layer is created disarmed and the ring + sink are attached later via [`CaptureHandle::arm`]
//! once `[enterprise.capture]` is known (and only when the feature is enabled). While disarmed —
//! including for the whole life of a process that never enables capture — `on_event` is a single
//! atomic load and a return: effectively free.

use std::fmt;
use std::sync::{Arc, OnceLock};

use tracing::field::{Field, Visit};
use tracing::{Event, Subscriber};
use tracing_subscriber::layer::{Context, Layer};

use crate::{CaptureRing, CaptureSink};

/// Shared state attached once the config is known. Behind a `OnceLock` so the disarmed hot path is a
/// lock-free load.
struct Armed {
    ring: Arc<CaptureRing>,
    sink: CaptureSink,
}

/// Handle shared between the installed [`CaptureLayer`] and `main`. `main` keeps one clone to
/// [`arm`](CaptureHandle::arm) after loading the config; the layer keeps another to read it.
#[derive(Clone, Default)]
pub struct CaptureHandle {
    armed: Arc<OnceLock<Armed>>,
}

impl CaptureHandle {
    /// A fresh, disarmed handle.
    pub fn new() -> Self {
        Self::default()
    }

    /// Attach the ring + shipper sink, enabling capture. Idempotent: a second call is a no-op (the
    /// feature is armed exactly once at boot).
    pub fn arm(&self, ring: Arc<CaptureRing>, sink: CaptureSink) {
        let _ = self.armed.set(Armed { ring, sink });
    }

    fn armed(&self) -> Option<&Armed> {
        self.armed.get()
    }
}

/// The layer. Zero-cost while disarmed; on a denial event it does one ring `take` + one non-blocking
/// enqueue.
pub struct CaptureLayer {
    handle: CaptureHandle,
}

impl CaptureLayer {
    /// Build the layer over a (typically disarmed) handle. `main` arms the same handle later.
    pub fn new(handle: CaptureHandle) -> Self {
        Self { handle }
    }
}

impl<S: Subscriber> Layer<S> for CaptureLayer {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let Some(armed) = self.handle.armed() else {
            return; // disarmed → free
        };
        let mut visitor = DecisionVisitor::default();
        event.record(&mut visitor);
        if !visitor.is_denial() {
            return;
        }
        let Some(request_id) = visitor.request_id else {
            return;
        };
        // The capture was inserted by the module microseconds earlier, on the same request.
        if let Some(capture) = armed.ring.take(&request_id) {
            armed.sink.enqueue(capture);
        }
    }
}

/// Extracts the `message` and `request_id` fields from a decision-log event. The proxy emits both via
/// the `%`/message sigils → `record_debug` with `format_args` (no surrounding quotes); `record_str`
/// is handled too in case a field is ever recorded as a plain `&str`.
#[derive(Default)]
struct DecisionVisitor {
    message: Option<String>,
    request_id: Option<String>,
}

impl DecisionVisitor {
    fn is_denial(&self) -> bool {
        matches!(self.message.as_deref(), Some("request blocked") | Some("request rejected"))
    }
}

impl Visit for DecisionVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        match field.name() {
            "message" => self.message = Some(format!("{value:?}")),
            "request_id" if self.request_id.is_none() => {
                self.request_id = Some(format!("{value:?}"));
            }
            _ => {}
        }
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "request_id" {
            self.request_id = Some(value.to_string());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tracing_subscriber::layer::SubscriberExt;

    use crate::CapturedRequest;

    fn sample(id: &str) -> CapturedRequest {
        CapturedRequest {
            request_id: id.to_string(),
            method: "POST".to_string(),
            path: "/x".to_string(),
            query: None,
            http_version: "HTTP/1.1".to_string(),
            headers: vec![],
            cookies: vec![],
            body_b64: String::new(),
            body_size: 0,
            body_truncated: false,
            redacted: vec![],
        }
    }

    fn armed_layer() -> (CaptureHandle, Arc<CaptureRing>, tokio::sync::mpsc::Receiver<CapturedRequest>) {
        let ring = Arc::new(CaptureRing::new(8, 1 << 20, Duration::from_secs(5)));
        let (sink, rx) = CaptureSink::channel(8);
        let handle = CaptureHandle::new();
        handle.arm(Arc::clone(&ring), sink);
        (handle, ring, rx)
    }

    #[test]
    fn denial_event_takes_from_ring_and_ships() {
        let (handle, ring, mut rx) = armed_layer();
        ring.insert(sample("req-1"));
        let subscriber = tracing_subscriber::registry().with(CaptureLayer::new(handle));
        tracing::subscriber::with_default(subscriber, || {
            let rid = "req-1";
            // Mirror the proxy's emission: `%` sigil for request_id, static message.
            tracing::warn!(request_id = %rid, rule_id = "sqli", "request blocked");
        });
        let got = rx.try_recv().expect("capture shipped");
        assert_eq!(got.request_id, "req-1");
        assert!(ring.is_empty(), "capture removed from the ring");
    }

    #[test]
    fn rejected_event_also_ships() {
        let (handle, ring, mut rx) = armed_layer();
        ring.insert(sample("req-2"));
        let subscriber = tracing_subscriber::registry().with(CaptureLayer::new(handle));
        tracing::subscriber::with_default(subscriber, || {
            let rid = "req-2";
            tracing::warn!(request_id = %rid, status = 429, "request rejected");
        });
        assert_eq!(rx.try_recv().expect("shipped").request_id, "req-2");
    }

    #[test]
    fn non_denial_event_ships_nothing() {
        let (handle, ring, mut rx) = armed_layer();
        ring.insert(sample("req-3"));
        let subscriber = tracing_subscriber::registry().with(CaptureLayer::new(handle));
        tracing::subscriber::with_default(subscriber, || {
            let rid = "req-3";
            tracing::info!(request_id = %rid, method = "GET", "→ request");
        });
        assert!(rx.try_recv().is_err(), "no capture for a non-denial event");
        assert_eq!(ring.len(), 1, "ring untouched");
    }

    #[test]
    fn disarmed_layer_is_inert() {
        // A denial event with no armed handle must not panic and must ship nothing.
        let subscriber = tracing_subscriber::registry().with(CaptureLayer::new(CaptureHandle::new()));
        tracing::subscriber::with_default(subscriber, || {
            let rid = "req-x";
            tracing::warn!(request_id = %rid, "request blocked");
        });
    }
}
