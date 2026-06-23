// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

use tracing::info;
use waf_core::{Config, Decision, Phase, RequestContext, WafModule};

/// Passes every request through unchanged, emitting a structured log line.
/// Used to validate the pipeline in Fase 1 before real detection modules exist.
pub struct NoopLogger;

impl WafModule for NoopLogger {
    fn id(&self) -> &str {
        "noop_logger"
    }

    fn phase(&self) -> Phase {
        Phase::RequestLine
    }

    fn init(&mut self, _cfg: &Config) {}

    fn inspect(&self, ctx: &RequestContext) -> Decision {
        info!(
            request_id = %ctx.request_id,
            module = "noop_logger",
            method = %ctx.method,
            path = %ctx.path,
            "request logged"
        );
        Decision::Allow
    }
}
