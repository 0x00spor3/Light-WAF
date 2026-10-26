// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

//! Live change notifications for the dashboard (SSE). A tiny in-process pub/sub: the ingest handler
//! and the alert evaluator publish a lightweight "something changed" notice; the `GET /api/stream`
//! SSE endpoint fans it out to connected browsers, which then re-fetch the affected view.
//!
//! This is **notify-then-pull**: the notices carry no event payload (so nothing sensitive rides the
//! stream and it stays cheap), only *which* view changed. It is best-effort — if a client lags past
//! the channel capacity it simply misses notices, and the view's periodic poll still catches up.
//! Zero-datapath: the bus lives entirely in the control plane.

use tokio::sync::broadcast;

/// Which dashboard view a notice refers to. The SSE `event:` name is [`Self::as_str`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamKind {
    /// New decision events were ingested (Events view + Overview denied series).
    Events,
    /// A new alert fired (Alerts view).
    Alerts,
}

impl StreamKind {
    /// The SSE event name sent to the browser.
    pub fn as_str(self) -> &'static str {
        match self {
            StreamKind::Events => "events",
            StreamKind::Alerts => "alerts",
        }
    }
}

/// A cheap, clonable handle to publish change notices and to subscribe to them. Held in `AppState`
/// and passed to the evaluator. Cloning shares the same channel.
#[derive(Clone)]
pub struct EventBus {
    tx: broadcast::Sender<StreamKind>,
}

impl EventBus {
    /// Create a bus with a small ring buffer. A slow subscriber that falls behind loses the oldest
    /// notices (it will resync on its next poll) — notices are hints, not a durable queue.
    pub fn new() -> Self {
        let (tx, _rx) = broadcast::channel(64);
        Self { tx }
    }

    /// Subscribe a new SSE connection to the stream of notices.
    pub fn subscribe(&self) -> broadcast::Receiver<StreamKind> {
        self.tx.subscribe()
    }

    /// Publish a notice. A no-op when there are no subscribers (no connected dashboards).
    pub fn notify(&self, kind: StreamKind) {
        let _ = self.tx.send(kind);
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new()
    }
}
