// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

//! Request capture for [Light WAF](https://github.com/0x00spor3/Light-WAF): keep the **full** HTTP
//! request (method, path, query, headers, cookies, body) of every request the WAF blocks or rejects,
//! and ship it to the control plane for the event drill-down. Optional, default off.
//!
//! Three pieces, no change to the core:
//!
//! 1. [`CaptureModule`] — a detection module that never scores: it clones each request into a bounded
//!    [`CaptureRing`] keyed by request id (cheap: the body is a ref-counted `Bytes`).
//! 2. [`CaptureLayer`] — a `tracing` layer that watches the `request blocked` / `request rejected`
//!    decision-log events and pulls the matching capture out of the ring.
//! 3. [`CaptureShipper`] — a bounded queue with best-effort retry that POSTs captures to the control
//!    plane's `/ingest/captures`; it drops on overflow and never puts backpressure on the datapath.
//!
//! Privacy: capture is raw by default; [`RedactionConfig`] replaces header and body-field values with
//! `***REDACTED***` on the node, and [`CaptureConfig::max_body_bytes`] caps the body. Retention and
//! access control are enforced by the control plane.

mod capture;
mod layer;
mod module;
mod ring;
mod shipper;

pub use capture::{CapturedRequest, REDACTED};
pub use layer::{CaptureHandle, CaptureLayer};
pub use module::CaptureModule;
pub use ring::CaptureRing;
pub use shipper::{CaptureShipper, CaptureSink};

use std::time::Duration;

/// Which header names and body field names to strip from a capture before it is stored/shipped.
///
/// Both lists are matched **case-insensitively**. Empty lists (the default) mean *raw capture* —
/// nothing is stripped. Redaction is applied node-side by the capture module (C1), so a redacted
/// value never travels to the control-plane.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RedactionConfig {
    /// Header names whose value is replaced with `***REDACTED***` (e.g. `authorization`, `cookie`,
    /// `set-cookie`). Compared case-insensitively against the request header names.
    pub headers: Vec<String>,
    /// Body field names (JSON keys / form parameters) whose value is replaced with `***REDACTED***`
    /// (e.g. `password`, `token`, `card`). Compared case-insensitively.
    pub body_fields: Vec<String>,
}

impl RedactionConfig {
    /// Whether `name` (a request header name) must be redacted. Case-insensitive.
    pub fn header_redacted(&self, name: &str) -> bool {
        self.headers.iter().any(|h| h.eq_ignore_ascii_case(name))
    }

    /// Whether `name` (a body field / form parameter name) must be redacted. Case-insensitive.
    pub fn field_redacted(&self, name: &str) -> bool {
        self.body_fields.iter().any(|f| f.eq_ignore_ascii_case(name))
    }

    /// True when nothing is configured to redact — i.e. a raw capture.
    pub fn is_empty(&self) -> bool {
        self.headers.is_empty() && self.body_fields.is_empty()
    }
}

/// Typed configuration for the request-capture feature. Built by the enterprise wiring from the
/// `[enterprise.capture]` TOML section. Every field has a fail-safe default and the feature is OFF by
/// default, so a config without the section behaves exactly like the plain enterprise proxy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureConfig {
    /// Off by default → the capture module is never even instantiated (zero datapath cost).
    pub enabled: bool,
    /// Base URL of the control-plane ingest (e.g. `http://controlplane:8080`). The shipper appends
    /// `/ingest/captures`. Required when `enabled` (the wiring rejects an empty URL).
    pub controlplane_url: String,
    /// Name of the environment variable holding the bearer token for the ingest POST. The token
    /// itself is NEVER read from the TOML file (same discipline as the other enterprise secrets).
    pub token_env: String,
    /// Cap on how many body bytes are captured; a larger body is truncated and flagged. Bounds both
    /// datapath memory and the size shipped to the control-plane.
    pub max_body_bytes: usize,
    /// Max number of in-flight captures held in the ring (bound by entry count).
    pub ring_capacity: usize,
    /// Max total bytes held across all ring entries (bound by size — evicts oldest past this).
    pub ring_bytes: usize,
    /// How long a capture lives in the ring before it is evicted unshipped. A request/decision pair
    /// is microseconds apart, so a few seconds is ample; allowed requests age out and are dropped.
    pub ring_ttl: Duration,
    /// Bound on the shipper's outbound queue. When full, new captures are dropped (logged/metered),
    /// never blocking the request path.
    pub queue_capacity: usize,
    /// Node-side redaction of sensitive headers / body fields. Empty = raw capture (the default).
    pub redaction: RedactionConfig,
}

impl Default for CaptureConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            controlplane_url: String::new(),
            token_env: "WAF_CAPTURE_TOKEN".to_string(),
            max_body_bytes: 64 * 1024,
            ring_capacity: 1024,
            ring_bytes: 32 * 1024 * 1024,
            ring_ttl: Duration::from_secs(5),
            queue_capacity: 256,
            redaction: RedactionConfig::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_default_is_off_and_raw() {
        let c = CaptureConfig::default();
        assert!(!c.enabled, "capture must default OFF");
        assert!(c.redaction.is_empty(), "default is raw capture (no redaction)");
        assert_eq!(c.token_env, "WAF_CAPTURE_TOKEN");
        assert_eq!(c.max_body_bytes, 64 * 1024);
        assert_eq!(c.ring_ttl, Duration::from_secs(5));
    }

    #[test]
    fn redaction_matches_case_insensitively() {
        let r = RedactionConfig {
            headers: vec!["Authorization".to_string(), "Cookie".to_string()],
            body_fields: vec!["password".to_string()],
        };
        assert!(r.header_redacted("authorization"));
        assert!(r.header_redacted("COOKIE"));
        assert!(!r.header_redacted("user-agent"));
        assert!(r.field_redacted("PASSWORD"));
        assert!(!r.field_redacted("username"));
        assert!(!r.is_empty());
    }
}
