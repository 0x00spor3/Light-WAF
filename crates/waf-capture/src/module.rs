// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

//! The capture `WafModule` — the request-path half of the feature.
//!
//! It is injected via the core-0.3 `module_factory` seam and, on every request, clones the request
//! into the shared [`CaptureRing`]. It **never** produces a verdict (`inspect` always returns
//! `Decision::Allow`): it is a pure observer. The verdict-join `tracing::Layer` (C2) later takes the
//! matching capture out of the ring for the requests the WAF actually denied; everything else ages
//! out. The module cannot itself see the verdict — that is precisely why the join is a separate step.
//!
//! **Phase = `RequestLine`, `structural = true`.** The pipeline `break`s at the first block, so a
//! capture module in a late phase would miss requests denied earlier. `RequestLine` is the first
//! inspection phase, so the capture runs before every content-rule / anomaly-threshold block (which
//! land in `Headers`/`Body`). `structural = true` also keeps it running on the content fast-path
//! skip. Not captured (by construction): `Phase::Connection` denials (rate-limit / request
//! smuggling) run before inspection, and a hard block from a `RequestLine` module ordered ahead of
//! this one — both remain metadata-only in the decision-log. The body is available regardless of
//! phase (collected before the pipeline runs).

use std::sync::Arc;

use waf_core::{Config, Decision, Phase, RequestContext, WafModule};

use crate::{CaptureConfig, CaptureRing, CapturedRequest, RedactionConfig};

/// Observer module that mirrors each request into the ring. Holds an `Arc` to the ring it shares
/// with the verdict-join layer; the `module_factory` rebuilds the module on reload but keeps the
/// same ring, so in-flight captures survive a config reload.
pub struct CaptureModule {
    enabled: bool,
    max_body_bytes: usize,
    redaction: RedactionConfig,
    ring: Arc<CaptureRing>,
}

impl CaptureModule {
    /// Build the module from the typed config, sharing `ring` with the verdict-join layer.
    pub fn new(cfg: &CaptureConfig, ring: Arc<CaptureRing>) -> Self {
        Self {
            enabled: cfg.enabled,
            max_body_bytes: cfg.max_body_bytes,
            redaction: cfg.redaction.clone(),
            ring,
        }
    }
}

impl WafModule for CaptureModule {
    fn id(&self) -> &str {
        "request-capture"
    }

    fn phase(&self) -> Phase {
        Phase::RequestLine
    }

    /// Structural so the content fast-path never skips it (it is not a content rule).
    fn structural(&self) -> bool {
        true
    }

    fn init(&mut self, _cfg: &Config) {}

    fn inspect(&self, ctx: &RequestContext) -> Decision {
        if self.enabled {
            let capture = CapturedRequest::from_ctx(ctx, self.max_body_bytes, &self.redaction);
            self.ring.insert(capture);
        }
        // Pure observer — never contributes to the score, never denies.
        Decision::Allow
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use waf_core::testkit::Request;

    fn ring() -> Arc<CaptureRing> {
        Arc::new(CaptureRing::new(16, 1 << 20, Duration::from_secs(5)))
    }

    #[test]
    fn enabled_module_captures_into_ring_and_allows() {
        let ring = ring();
        let cfg = CaptureConfig { enabled: true, ..Default::default() };
        let m = CaptureModule::new(&cfg, Arc::clone(&ring));

        let ctx = Request::new().request_id("req-1").method("POST").path("/x").json_body("{}").build();
        assert!(matches!(m.inspect(&ctx), Decision::Allow), "observer never denies");

        let cap = ring.take("req-1").expect("captured");
        assert_eq!(cap.method, "POST");
        assert_eq!(cap.path, "/x");
    }

    #[test]
    fn disabled_module_captures_nothing() {
        let ring = ring();
        let cfg = CaptureConfig { enabled: false, ..Default::default() };
        let m = CaptureModule::new(&cfg, Arc::clone(&ring));

        let ctx = Request::new().request_id("req-2").build();
        assert!(matches!(m.inspect(&ctx), Decision::Allow));
        assert!(ring.is_empty(), "disabled → nothing captured");
    }

    #[test]
    fn module_metadata_is_structural_requestline() {
        let m = CaptureModule::new(&CaptureConfig::default(), ring());
        assert_eq!(m.id(), "request-capture");
        assert_eq!(m.phase(), Phase::RequestLine);
        assert!(m.structural(), "must run on the content fast-path skip");
    }
}
