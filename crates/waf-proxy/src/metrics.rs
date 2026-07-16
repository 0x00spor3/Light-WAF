// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

//! Prometheus metrics (B1). **OPEN baseline** (`BOUNDARY.md` §1.6).
//!
//! Hand-rolled on purpose: the model is **fixed-bucket histograms + `_sum`/`_count`** with
//! NO in-process quantiles — Prometheus computes them at scrape time via `histogram_quantile()`.
//! That keeps the whole thing ~N `AtomicU64` + a trivial text serializer, not worth a dep tree.
//!
//! The metric NAMES and label VALUES are **ABI** (a renamed metric breaks every downstream
//! Grafana query). `decision` is a CLOSED, low-cardinality set; **never** put user-derived data
//! (path, IP, rule_id) in a label — that is the classic cardinality-explosion footgun.
//!
//! Instrumentation is a **pure side effect**: every counter is `AtomicU64` with `Relaxed`
//! ordering, no lock or `.await` on the hot path, so recording can never change a verdict nor
//! perturb the latency it measures. The `Metrics` type is exporter-neutral; [`Metrics::render`]
//! is the Prometheus exporter (the only Prometheus-specific piece). A future OTLP sink would be
//! a second renderer, not a rewrite.

use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::time::Duration;

/// Final disposition of a request — the closed value set of the `decision` label.
/// Discriminants are the array index into the counters; keep `Outcome::ALL` in sync.
#[derive(Clone, Copy)]
pub enum Outcome {
    /// Forwarded to the backend (whatever status the app returned).
    Allowed,
    /// Anomaly/high-confidence block (403).
    Blocked,
    /// Rate limit exceeded (429).
    RateLimited,
    /// Rejected before forwarding for a malformed/over-limit request (400).
    BadRequest,
    /// The BACKEND failed/timed out/was unreachable — structured upstream error (502/503).
    UpstreamError,
    /// The WAF's OWN machinery errored unexpectedly — catch-all `handle` 502. Distinct from
    /// `UpstreamError` so "backend is down" and "we have a bug" are not conflated.
    InternalError,
}

impl Outcome {
    const ALL: [Outcome; 6] = [
        Outcome::Allowed,
        Outcome::Blocked,
        Outcome::RateLimited,
        Outcome::BadRequest,
        Outcome::UpstreamError,
        Outcome::InternalError,
    ];

    fn label(self) -> &'static str {
        match self {
            Outcome::Allowed => "allowed",
            Outcome::Blocked => "blocked",
            Outcome::RateLimited => "rate_limited",
            Outcome::BadRequest => "bad_request",
            Outcome::UpstreamError => "upstream_error",
            Outcome::InternalError => "internal_error",
        }
    }
}

/// Latency histogram upper bounds in **seconds** (Prometheus base unit). Cumulative `le`
/// buckets are derived at render time; observations above the last bound land only in `+Inf`.
const BUCKETS_SECONDS: [f64; 14] =
    [0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0];

/// Process-lifetime metrics registry. Shared via `Arc`; lives in `StaticState` so it survives
/// config reloads (like the rate-limit store).
pub struct Metrics {
    /// One counter per `Outcome`, indexed by discriminant.
    requests: [AtomicU64; Outcome::ALL.len()],
    /// Non-cumulative per-bucket counts; rendered cumulatively.
    hist_buckets: [AtomicU64; BUCKETS_SECONDS.len()],
    /// Total observations (the `+Inf` bucket and `_count`).
    hist_count: AtomicU64,
    /// Sum of observed durations, in nanoseconds (integer accumulation; rendered as seconds).
    hist_sum_nanos: AtomicU64,
}

impl Metrics {
    pub fn new() -> Self {
        Self {
            requests: std::array::from_fn(|_| AtomicU64::new(0)),
            hist_buckets: std::array::from_fn(|_| AtomicU64::new(0)),
            hist_count: AtomicU64::new(0),
            hist_sum_nanos: AtomicU64::new(0),
        }
    }

    /// Record one finished request: its decision + total handling latency. Pure side effect.
    pub fn record(&self, outcome: Outcome, elapsed: Duration) {
        self.requests[outcome as usize].fetch_add(1, Relaxed);

        let secs = elapsed.as_secs_f64();
        let mut i = 0;
        while i < BUCKETS_SECONDS.len() && secs > BUCKETS_SECONDS[i] {
            i += 1;
        }
        if i < BUCKETS_SECONDS.len() {
            self.hist_buckets[i].fetch_add(1, Relaxed);
        }
        self.hist_count.fetch_add(1, Relaxed);
        self.hist_sum_nanos.fetch_add(elapsed.as_nanos() as u64, Relaxed);
    }

    /// Serialize the current snapshot in Prometheus text exposition format. This is the
    /// Prometheus-specific exporter; the counters above are exporter-neutral.
    pub fn render(&self) -> String {
        let mut out = String::with_capacity(1024);

        out.push_str("# HELP waf_up 1 if the WAF process is running.\n");
        out.push_str("# TYPE waf_up gauge\n");
        out.push_str("waf_up 1\n");

        out.push_str("# HELP waf_build_info Build information.\n");
        out.push_str("# TYPE waf_build_info gauge\n");
        out.push_str(&format!(
            "waf_build_info{{version=\"{}\"}} 1\n",
            env!("CARGO_PKG_VERSION")
        ));

        out.push_str("# HELP waf_requests_total Total requests by final decision.\n");
        out.push_str("# TYPE waf_requests_total counter\n");
        for outcome in Outcome::ALL {
            let n = self.requests[outcome as usize].load(Relaxed);
            out.push_str(&format!("waf_requests_total{{decision=\"{}\"}} {}\n", outcome.label(), n));
        }

        out.push_str("# HELP waf_request_duration_seconds Request handling latency in seconds.\n");
        out.push_str("# TYPE waf_request_duration_seconds histogram\n");
        let mut cumulative = 0u64;
        for (i, bound) in BUCKETS_SECONDS.iter().enumerate() {
            cumulative += self.hist_buckets[i].load(Relaxed);
            out.push_str(&format!(
                "waf_request_duration_seconds_bucket{{le=\"{}\"}} {}\n",
                bound, cumulative
            ));
        }
        let count = self.hist_count.load(Relaxed);
        out.push_str(&format!(
            "waf_request_duration_seconds_bucket{{le=\"+Inf\"}} {}\n",
            count
        ));
        let sum_seconds = self.hist_sum_nanos.load(Relaxed) as f64 / 1e9;
        out.push_str(&format!("waf_request_duration_seconds_sum {}\n", sum_seconds));
        out.push_str(&format!("waf_request_duration_seconds_count {}\n", count));

        out
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_has_all_decision_labels_and_histogram_shape() {
        let m = Metrics::new();
        m.record(Outcome::Allowed, Duration::from_millis(2));
        m.record(Outcome::Blocked, Duration::from_micros(300));
        m.record(Outcome::RateLimited, Duration::from_secs(20)); // overflow → only +Inf

        let text = m.render();
        // Every closed-set decision label is present (even zero-valued).
        for label in ["allowed", "blocked", "rate_limited", "bad_request", "upstream_error", "internal_error"] {
            assert!(text.contains(&format!("decision=\"{label}\"")), "missing {label}");
        }
        assert!(text.contains("waf_requests_total{decision=\"allowed\"} 1"));
        assert!(text.contains("waf_requests_total{decision=\"bad_request\"} 0"));
        // +Inf counts every observation (3); count line matches.
        assert!(text.contains("le=\"+Inf\"} 3"));
        assert!(text.contains("waf_request_duration_seconds_count 3"));
        assert!(text.contains("waf_up 1"));
    }

    #[test]
    fn buckets_are_cumulative_and_monotonic() {
        let m = Metrics::new();
        // Three small observations all fall under 0.01s → every le>=0.01 bucket counts them.
        for _ in 0..3 {
            m.record(Outcome::Allowed, Duration::from_micros(800)); // 0.0008s
        }
        let text = m.render();
        // 0.0008 > 0.0005 but <= 0.001 → first counted bucket is le="0.001".
        assert!(text.contains("le=\"0.0005\"} 0"));
        assert!(text.contains("le=\"0.001\"} 3"));
        assert!(text.contains("le=\"0.01\"} 3"));
        assert!(text.contains("le=\"+Inf\"} 3"));
    }
}
