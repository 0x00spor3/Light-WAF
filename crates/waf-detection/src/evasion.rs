// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

//! Structural evasion signals (F-1).
//!
//! Unlike every other detection module, this one runs NO content regexes. It cables
//! two booleans the normalizer already computes into scored contributions:
//!
//!   - `null_byte_detected` — a NUL byte was present in the DECODED path before the
//!     normalizer stripped it. The WAF forwards the request RAW, so a double-encoded
//!     `%2500` still truncates a filename at the backend (serving e.g. `secret.bak`
//!     from `secret.bak%2500.md`). The stripped path leaves `pt-null-byte` blind and
//!     the request otherwise scores 0 — the exact "no trace" disclosure of F-1. →
//!     `evasion-null-byte`, **Critical** (blocks on own merit + records the evasion).
//!   - `double_encoding_detected` — a field decoded through two percent layers. A
//!     deliberate evasion tell, but legitimate proxies/gateways re-encode redirect
//!     URLs, so → `evasion-double-encoding`, **Warning** (contributory: blocks only in
//!     accumulation, never alone).
//!
//! `structural() == true`: the flags are set by the normalizer, so this must run even
//! when the content fast-path (Pillar 3) proves no content rule can match — otherwise a
//! benign-looking path (`/ftp/secret.bak.md` after strip) would skip inspection and the
//! signal would be lost, which is precisely the bug. Scope is PATH-only for the NUL (see
//! `Normalized::null_byte_detected`), so this never double-counts `pt-null-byte`
//! (which stays live on query/cookie/body where the NUL survives).

use tracing::warn;
use waf_core::{Config, Decision, Phase, RequestContext, ScoreItem, Severity, WafModule};

/// Rule ids emitted by [`EvasionModule`]. Public so tests/inventories can assert them.
pub const RULE_NULL_BYTE: &str = "evasion-null-byte";
pub const RULE_DOUBLE_ENCODING: &str = "evasion-double-encoding";

#[derive(Default)]
pub struct EvasionModule;

impl EvasionModule {
    pub fn new() -> Self {
        Self
    }
}

impl WafModule for EvasionModule {
    fn id(&self) -> &str {
        "evasion"
    }

    fn phase(&self) -> Phase {
        Phase::Body
    }

    /// The signals are normalizer-computed flags, not content-rule matches, so the
    /// content fast-path cannot prove this module inert — it must run on the skip path.
    fn structural(&self) -> bool {
        true
    }

    fn init(&mut self, _cfg: &Config) {}

    fn inspect(&self, ctx: &RequestContext) -> Decision {
        let mut items: Vec<ScoreItem> = Vec::new();

        if ctx.normalized.null_byte_detected {
            warn!(
                request_id = %ctx.request_id,
                rule_id = RULE_NULL_BYTE,
                severity = ?Severity::Critical,
                "evasion detection"
            );
            items.push(ScoreItem {
                rule_id: RULE_NULL_BYTE.to_string(),
                severity: Severity::Critical,
            });
        }

        if ctx.normalized.double_encoding_detected {
            warn!(
                request_id = %ctx.request_id,
                rule_id = RULE_DOUBLE_ENCODING,
                severity = ?Severity::Warning,
                "evasion detection"
            );
            items.push(ScoreItem {
                rule_id: RULE_DOUBLE_ENCODING.to_string(),
                severity: Severity::Warning,
            });
        }

        if items.is_empty() {
            Decision::Allow
        } else {
            Decision::Scores(items)
        }
    }
}
