// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

//! gRPC structural protections (gRPC phase).
//!
//! Like `graphql`/`request_smuggling`, this is a STRUCTURAL control, NOT content
//! inspection: it enforces DoS/abuse caps on the SHAPE of the framed protobuf body a
//! request carries — total message size, protobuf field count, sub-message nesting depth —
//! plus a policy for COMPRESSED (un-inspectable) payloads. The metrics come from the
//! [`grpc_extract`] pass, so the module does NOT join the content-rule prefilter union.
//!
//! **Accounting (deliberate).** The protobuf field *content* (a SQLi/XSS smuggled inside a
//! string field) is caught by the normal content modules via the §6 derived channel — the
//! normalizer feeds them the extracted leaf strings. This module owns ONLY the structural
//! signal (size/field/depth/compressed/malformed → `Reject{400}`). Keeping the two apart
//! is the point: a content catch is credited to §6, not to gRPC.
//!
//! Recognised by `Content-Type: application/grpc*` on a `ParsedBody::Raw` body (the framed
//! message is binary, so the normalizer leaves it raw). Default OFF (`[modules.grpc]`).

use waf_core::{
    CompressedPolicy, Config, Decision, GrpcConfig, ParsedBody, Phase, RequestContext, WafModule,
};
use waf_normalizer::grpc::{grpc_extract, GrpcLimits};

#[derive(Default)]
pub struct GrpcModule {
    cfg: GrpcConfig,
}

impl GrpcModule {
    pub fn new() -> Self {
        Self::default()
    }
}

fn content_type(ctx: &RequestContext) -> &str {
    ctx.normalized
        .headers
        .iter()
        .find(|(k, _)| k == "content-type")
        .map(|(_, v)| v.as_str())
        .unwrap_or("")
}

/// A `grpc-encoding` other than `identity` (or, by the per-message flag) means the payload
/// is compressed → opaque to inspection. NB: an ABSENT `grpc-encoding` means `identity`
/// (gRPC spec) → inspectable; we must not treat absent as compressed.
fn header_compressed(ctx: &RequestContext) -> bool {
    ctx.normalized
        .headers
        .iter()
        .find(|(k, _)| k == "grpc-encoding")
        .map(|(_, v)| !v.trim().eq_ignore_ascii_case("identity"))
        .unwrap_or(false)
}

fn reject(reason: &'static str) -> Decision {
    Decision::Reject {
        rule_id: "grpc".to_string(),
        reason: reason.to_string(),
        status: 400,
        retry_after: None,
    }
}

impl WafModule for GrpcModule {
    fn id(&self) -> &str {
        "grpc"
    }

    fn phase(&self) -> Phase {
        Phase::Body
    }

    /// Structural: its caps are not content-rule matches, so the content fast-path must
    /// not skip it (else a gRPC DoS with no content signature would bypass). Same rule as
    /// the GraphQL module.
    fn structural(&self) -> bool {
        true
    }

    fn init(&mut self, cfg: &Config) {
        self.cfg = cfg.modules.grpc.clone();
    }

    fn inspect(&self, ctx: &RequestContext) -> Decision {
        if !self.cfg.enabled {
            return Decision::Allow;
        }
        // gRPC is identified by Content-Type (`application/grpc`, `+proto`, `-web`, …).
        if !content_type(ctx).trim_start().starts_with("application/grpc") {
            return Decision::Allow;
        }
        // The framed protobuf body is binary → the normalizer leaves it Raw.
        let ParsedBody::Raw(body) = &ctx.normalized.body else {
            return Decision::Allow;
        };

        // The module needs only the STRUCTURAL metrics (leaves go to the §6 channel via the
        // normalizer), so it asks the parser for no leaves (`max_leaves = 0`).
        let limits = GrpcLimits {
            max_depth: self.cfg.max_depth,
            max_fields: self.cfg.max_fields,
            max_leaves: 0,
        };
        let ex = grpc_extract(body, limits);

        // Illegal framing / wire format → reject (a malformed gRPC body is not benign).
        if ex.malformed {
            return reject("malformed gRPC framing");
        }
        // Size cap applies even to compressed frames (the length is in the frame header).
        if ex.total_payload_bytes > self.cfg.max_message_bytes {
            return reject("gRPC message size exceeds limit");
        }
        // Compressed payload = opaque → apply the configured policy (default fail-closed).
        if ex.compressed || header_compressed(ctx) {
            return match self.cfg.on_compressed {
                CompressedPolicy::Reject => reject("gRPC compressed payload is not inspectable"),
                // Passthrough: forward uninspected (declared). Size was already capped above;
                // field/depth caps cannot be checked on an unparsed payload.
                CompressedPolicy::Passthrough => Decision::Allow,
            };
        }
        if ex.depth_exceeded {
            return reject("gRPC message nesting depth exceeds limit");
        }
        if ex.fields_exceeded {
            return reject("gRPC field count exceeds limit");
        }
        Decision::Allow
    }
}
