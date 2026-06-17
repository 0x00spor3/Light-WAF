//! HTTP request-smuggling defence (Fase 6 / Pillar 4).
//!
//! This is NOT content-inspection: it validates HTTP **framing** — how the
//! request body boundary is declared (`Content-Length` vs `Transfer-Encoding`).
//! Smuggling is a disagreement between how two parsers (the WAF and the upstream)
//! interpret those boundaries; forwarding an *ambiguous* framing is the attack
//! vector. So this runs in `Phase::Connection`, BEFORE normalization/detection,
//! and on confirmed-ambiguous framing it **rejects with 400** (binary, never a
//! score).
//!
//! Boundary (shared with `header_injection`, see ARCHITECTURE §8): hyper parses
//! and re-serializes the request, rejecting obs-fold / whitespace-before-colon and
//! trimming OWS *before* this module sees the headers, and regenerating CL/TE
//! toward the backend. This module is defence-in-depth over the semantic framing
//! ambiguities that still reach it (CL+TE, duplicate/invalid CL, obfuscated/
//! duplicate TE). If the HTTP parser is ever changed, or a path without
//! re-serialization is introduced, the raw-byte checks (whitespace-before-colon,
//! obs-fold) must be re-implemented here — see the explicit assumption in §8.

use waf_core::{Config, Decision, Phase, RequestContext, WafModule};

#[derive(Default)]
pub struct RequestSmugglingModule {
    enabled: bool,
}

impl RequestSmugglingModule {
    pub fn new() -> Self {
        Self::default()
    }
}

fn reject(reason: &'static str) -> Decision {
    Decision::Reject {
        rule_id: "request-smuggling".to_string(),
        reason: reason.to_string(),
        status: 400,
        retry_after: None,
    }
}

/// A valid request `Content-Length` is a single run of ASCII digits (no sign, no
/// list, no spaces). hyper has already trimmed OWS, so anything else is illegal.
fn is_valid_content_length(v: &str) -> bool {
    !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit())
}

impl WafModule for RequestSmugglingModule {
    fn id(&self) -> &str {
        "request_smuggling"
    }

    fn phase(&self) -> Phase {
        // Connection phase → runs in `run_connection`, before normalization, so
        // illegal framing is refused without paying for parsing/detection.
        Phase::Connection
    }

    fn init(&mut self, cfg: &Config) {
        self.enabled = cfg.modules.request_smuggling.enabled;
    }

    fn inspect(&self, ctx: &RequestContext) -> Decision {
        if !self.enabled {
            return Decision::Allow;
        }

        // Header names are the lowercase canonical form; duplicates are preserved
        // as separate entries by the proxy's context builder.
        let cl: Vec<&str> = ctx
            .headers
            .iter()
            .filter(|(n, _)| n == "content-length")
            .map(|(_, v)| v.as_str())
            .collect();
        let te: Vec<&str> = ctx
            .headers
            .iter()
            .filter(|(n, _)| n == "transfer-encoding")
            .map(|(_, v)| v.as_str())
            .collect();

        // Rule 1: Content-Length AND Transfer-Encoding together. RFC tells ONE
        // upstream to prefer TE, but an in-path WAF that forwards the ambiguity has
        // no guarantee the backend resolves it identically → reject, don't propagate.
        if !cl.is_empty() && !te.is_empty() {
            return reject("content-length and transfer-encoding both present");
        }

        // Rule 2: Content-Length integrity.
        if !cl.is_empty() {
            if cl.len() > 1 {
                return reject("duplicate content-length headers");
            }
            if !is_valid_content_length(cl[0]) {
                return reject("malformed content-length value");
            }
        }

        // Rule 3: Transfer-Encoding integrity. Strict posture: the only accepted
        // request TE is the single token "chunked" (case-insensitive). Lists like
        // "gzip, chunked" and obfuscations like "xchunked"/"chunked, chunked" are
        // the preferred smuggling ground; we re-serialize toward the backend, so we
        // never need to honour exotic client transfer-codings.
        if !te.is_empty() {
            if te.len() > 1 {
                return reject("duplicate transfer-encoding headers");
            }
            if !te[0].eq_ignore_ascii_case("chunked") {
                return reject("obfuscated or non-chunked transfer-encoding");
            }
        }

        Decision::Allow
    }
}
