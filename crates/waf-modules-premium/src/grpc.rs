// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: BUSL-1.1

//! gRPC schema-enforcement (§4-B part 2). Validates each unary gRPC request message (protobuf)
//! against the app's REAL compiled schema (a `FileDescriptorSet` `.bin` from `protoc`/`buf`): the
//! `:path` (`/pkg.Service/Method`) selects the RPC's input message type, and the message bytes are
//! decoded against it. An unknown method or an un-decodable message is a query the real client never
//! sends → it contributes to the SAME cumulative anomaly score (governance of the schema, not
//! baseline detection — field content stays in the OPEN §6 channel, DoS caps in the OPEN `grpc`
//! module which runs first).
//!
//! **STEP 1 (scaffold + registry).** The crate now carries the `schema-grpc-*` registry leaves and a
//! working `GrpcSchemaModule` (Content-Type gated, `structural()` `Phase::Body`) proven on the real
//! `Pipeline`. Two signals wired: `schema-grpc-unknown-method` (Critical) and `schema-grpc-decode-error`
//! (Warning). The boot-fatal descriptor load from a `.bin` path + config (Step 2), and unknown-field
//! detection (H3, opt-in — Step 4), land next. See the frozen plan (H1–H7).

use std::path::{Path, PathBuf};

use prost_reflect::{DescriptorPool, DynamicMessage, MessageDescriptor};
use waf_core::{Config, Decision, ParsedBody, Phase, RequestContext, ScoreItem, Severity, WafModule};

use crate::rules;

/// Configuration for the gRPC schema-enforcement module. Built by the enterprise wiring from
/// `[enterprise.grpc_schema_enforcement]` (Step 5) and handed to [`GrpcSchemaModule::from_config`].
#[derive(Debug, Clone)]
pub struct GrpcSchemaEnforcementConfig {
    /// Off by default → the module is inert.
    pub enabled: bool,
    /// Path to the app's compiled `FileDescriptorSet` (`.bin` from `protoc`/`buf build`).
    pub descriptor_path: PathBuf,
    /// H3: flag messages carrying fields NOT in the descriptor. **Default off** — protobuf tolerates
    /// unknown fields by design (forward-compat), so a newer client legitimately carries them.
    pub flag_unknown_fields: bool,
    /// Severity for a `:path` not in the descriptor (Critical — targeted probing).
    pub unknown_method_severity: Severity,
    /// Severity for a message that does not decode against its input type (Warning — malformed).
    pub decode_error_severity: Severity,
    /// Severity for an unknown-field hit (only used when `flag_unknown_fields`; low — FP-prone).
    pub unknown_field_severity: Severity,
}

impl Default for GrpcSchemaEnforcementConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            descriptor_path: PathBuf::new(),
            flag_unknown_fields: false,
            unknown_method_severity: Severity::Critical,
            decode_error_severity: Severity::Warning,
            unknown_field_severity: Severity::Notice,
        }
    }
}

/// How a gRPC request message validates against the loaded descriptor pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrpcValidity {
    /// Decodes cleanly against the RPC's input type.
    Valid,
    /// The `:path` service/method is not in the descriptor (targeted probing).
    UnknownMethod,
    /// The bytes do not decode against the input type (malformed / wrong message).
    DecodeError,
    /// Decodes, but carries a **top-level** field not in the descriptor (opt-in, H3). Protobuf
    /// tolerates unknown fields by design, so this is only reported when `flag_unknown_fields`.
    UnknownField,
}

/// Pure, re-entrant descriptor load (H5 reload-readiness): FileDescriptorSet **bytes** → pool, no
/// global state, no I/O. The testable core of descriptor loading.
pub fn parse_descriptors(fds_bytes: &[u8]) -> Result<DescriptorPool, String> {
    DescriptorPool::decode(fds_bytes).map_err(|e| format!("invalid FileDescriptorSet: {e}"))
}

/// Load a compiled descriptor set **from a file** (H5 reload-ready entry point): read → parse. Called
/// at construction so the boot can fail-closed on a missing/invalid descriptor.
pub fn load_descriptors(path: &Path) -> Result<DescriptorPool, String> {
    let bytes = std::fs::read(path)
        .map_err(|e| format!("cannot read descriptor file {}: {e}", path.display()))?;
    parse_descriptors(&bytes)
}

/// Resolve the input message type for a gRPC `:path` (`/pkg.Service/Method`). `None` ⇒ the service
/// or method is not in the pool (unknown method).
fn resolve_input(pool: &DescriptorPool, path: &str) -> Option<MessageDescriptor> {
    let (service, method) = path.strip_prefix('/')?.split_once('/')?;
    let svc = pool.get_service_by_name(service)?;
    let m = svc.methods().find(|m| m.name() == method)?;
    Some(m.input())
}

/// Validate one request message (raw protobuf bytes) against the RPC selected by `path`. When
/// `flag_unknown` is set, a decoded message carrying a top-level field not in the descriptor is
/// reported as [`GrpcValidity::UnknownField`] (H3, opt-in).
pub fn validate_message(
    pool: &DescriptorPool,
    path: &str,
    msg: &[u8],
    flag_unknown: bool,
) -> GrpcValidity {
    let Some(input) = resolve_input(pool, path) else {
        return GrpcValidity::UnknownMethod;
    };
    match DynamicMessage::decode(input.clone(), msg) {
        Err(_) => GrpcValidity::DecodeError,
        Ok(_) => {
            // The bytes are well-formed (decode succeeded), so the tag walk is safe. v1 checks
            // TOP-LEVEL fields only (nested unknown fields = declared follow-on).
            if flag_unknown {
                let known: Vec<u32> = input.fields().map(|f| f.number()).collect();
                if has_unknown_field(&known, msg) {
                    return GrpcValidity::UnknownField;
                }
            }
            GrpcValidity::Valid
        }
    }
}

/// Read a base-128 varint at `*i`, advancing it. `None` on truncation / overlong.
fn read_varint(b: &[u8], i: &mut usize) -> Option<u64> {
    let mut result: u64 = 0;
    for k in 0..10 {
        let byte = *b.get(*i)?;
        *i += 1;
        result |= ((byte & 0x7f) as u64) << (7 * k);
        if byte & 0x80 == 0 {
            return Some(result);
        }
    }
    None
}

/// Walk the top-level protobuf tags of `msg` (already known to decode) and report whether any field
/// number is absent from `known`. Skips each field's value by wire type.
fn has_unknown_field(known: &[u32], msg: &[u8]) -> bool {
    let mut i = 0;
    while i < msg.len() {
        let Some(tag) = read_varint(msg, &mut i) else { return false };
        let field = (tag >> 3) as u32;
        let wire = (tag & 7) as u8;
        if field != 0 && !known.contains(&field) {
            return true;
        }
        let ok = match wire {
            0 => read_varint(msg, &mut i).is_some(), // varint
            1 => {
                i += 8;
                true
            } // 64-bit
            2 => match read_varint(msg, &mut i) {
                Some(len) => {
                    i += len as usize;
                    true
                }
                None => false,
            }, // length-delimited
            5 => {
                i += 4;
                true
            } // 32-bit
            _ => false, // groups (3/4) / invalid — stop (decode already validated the shape)
        };
        if !ok || i > msg.len() {
            return false;
        }
    }
    false
}

/// De-frame a gRPC body into its message payloads. Each frame is
/// `[compressed-flag:1][length:4 big-endian][message:length]`. **Compressed** frames (flag != 0) are
/// opaque here → skipped (never flagged as decode errors). Mirrors the OPEN normalizer's framing;
/// `GrpcExtract` does not expose the raw frames, so we re-derive the tiny loop.
fn frames(body: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let mut pos = 0;
    while pos + 5 <= body.len() {
        let flag = body[pos];
        let len = u32::from_be_bytes([body[pos + 1], body[pos + 2], body[pos + 3], body[pos + 4]])
            as usize;
        pos += 5;
        if pos + len > body.len() {
            break; // truncated framing — stop (the OPEN grpc module owns the structural signal)
        }
        if flag == 0 {
            out.push(&body[pos..pos + len]);
        }
        pos += len;
    }
    out
}

fn content_type(ctx: &RequestContext) -> &str {
    ctx.normalized
        .headers
        .iter()
        .find(|(k, _)| k == "content-type")
        .map(|(_, v)| v.as_str())
        .unwrap_or("")
}

/// STEP-0 probe module. Validates the unary gRPC request message(s) against the descriptor pool.
pub struct GrpcSchemaModule {
    pool: DescriptorPool,
    enabled: bool,
    flag_unknown_fields: bool,
    unknown_method_severity: Severity,
    decode_error_severity: Severity,
    unknown_field_severity: Severity,
}

impl GrpcSchemaModule {
    /// Production constructor: load the compiled descriptor set from `cfg.descriptor_path`.
    /// **Boot-fatal** on a missing/invalid descriptor — `init(&Config)` gets the core config (no
    /// descriptor path) and returns `()`, so the fail-closed load MUST happen here at construction.
    pub fn from_config(cfg: &GrpcSchemaEnforcementConfig) -> Result<Self, String> {
        Ok(Self {
            pool: load_descriptors(&cfg.descriptor_path)?,
            enabled: cfg.enabled,
            flag_unknown_fields: cfg.flag_unknown_fields,
            unknown_method_severity: cfg.unknown_method_severity,
            decode_error_severity: cfg.decode_error_severity,
            unknown_field_severity: cfg.unknown_field_severity,
        })
    }

    /// Test/embedding constructor from FileDescriptorSet **bytes** (no file), default config
    /// (unknown-field flagging OFF, severities Critical/Warning/Notice).
    pub fn from_fds_bytes(fds_bytes: &[u8], enabled: bool) -> Result<Self, String> {
        let cfg = GrpcSchemaEnforcementConfig::default();
        Ok(Self {
            pool: parse_descriptors(fds_bytes)?,
            enabled,
            flag_unknown_fields: cfg.flag_unknown_fields,
            unknown_method_severity: cfg.unknown_method_severity,
            decode_error_severity: cfg.decode_error_severity,
            unknown_field_severity: cfg.unknown_field_severity,
        })
    }

    /// Test constructor with unknown-field flagging forced ON.
    #[cfg(test)]
    fn from_fds_bytes_flagging(fds_bytes: &[u8]) -> Result<Self, String> {
        Ok(Self { flag_unknown_fields: true, ..Self::from_fds_bytes(fds_bytes, true)? })
    }
}

impl WafModule for GrpcSchemaModule {
    fn id(&self) -> &str {
        "schema-grpc"
    }

    fn phase(&self) -> Phase {
        Phase::Body
    }

    fn structural(&self) -> bool {
        true
    }

    fn init(&mut self, _cfg: &Config) {}

    fn inspect(&self, ctx: &RequestContext) -> Decision {
        if !self.enabled {
            return Decision::Allow;
        }
        // Recognised by Content-Type, like the OPEN grpc module. The framed body stays Raw.
        if !content_type(ctx).trim_start().starts_with("application/grpc") {
            return Decision::Allow;
        }
        let ParsedBody::Raw(body) = &ctx.normalized.body else {
            return Decision::Allow;
        };
        let msgs = frames(body);
        if msgs.is_empty() {
            return Decision::Allow;
        }
        // gRPC service/method names are CASE-SENSITIVE, so resolve against the raw `ctx.path` — NOT
        // `ctx.normalized.path`, which the normalizer lowercases (that would make every method look
        // unknown). The framed body still comes from `normalized.body` (the raw binary is untouched).
        let path = &ctx.path;
        // Dedup by kind (a batch of frames is one signal, not N).
        let mut unknown_method = false;
        let mut decode_error = false;
        let mut unknown_field = false;
        for msg in &msgs {
            match validate_message(&self.pool, path, msg, self.flag_unknown_fields) {
                GrpcValidity::Valid => {}
                GrpcValidity::UnknownMethod => unknown_method = true,
                GrpcValidity::DecodeError => decode_error = true,
                GrpcValidity::UnknownField => unknown_field = true,
            }
        }
        let mut items = Vec::new();
        if unknown_method {
            items.push(ScoreItem {
                rule_id: rules::GRPC_UNKNOWN_METHOD.id(),
                severity: self.unknown_method_severity,
            });
        }
        if decode_error {
            items.push(ScoreItem {
                rule_id: rules::GRPC_DECODE_ERROR.id(),
                severity: self.decode_error_severity,
            });
        }
        if unknown_field {
            items.push(ScoreItem {
                rule_id: rules::GRPC_UNKNOWN_FIELD.id(),
                severity: self.unknown_field_severity,
            });
        }
        if items.is_empty() {
            Decision::Allow
        } else {
            Decision::Scores(items)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message;

    /// Compile the fixture `.proto` to a FileDescriptorSet (`.bin` bytes), mirroring the real flow
    /// (operator ships a compiled descriptor from protoc/buf). Uses protox — no `protoc` binary.
    fn fixture_fds() -> Vec<u8> {
        // Unique per call: tests run in parallel in one process, so a PID-only dir would race
        // (one test's remove_dir_all vs another's compile).
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "waf-grpc-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let proto = dir.join("greeter.proto");
        std::fs::write(
            &proto,
            r#"
                syntax = "proto3";
                package test.v1;
                message HelloRequest { string name = 1; }
                message HelloReply { string message = 1; }
                service Greeter { rpc SayHello(HelloRequest) returns (HelloReply); }
            "#,
        )
        .unwrap();
        let fds = protox::compile([&proto], [&dir]).expect("compile proto");
        let _ = std::fs::remove_dir_all(&dir);
        fds.encode_to_vec()
    }

    const SAYHELLO: &str = "/test.v1.Greeter/SayHello";

    /// Convenience for the runbook: emit the demo `FileDescriptorSet` to `$WAF_FDS_OUT` (so a live
    /// wire check works without `protoc`/`buf` installed). Ignored by default.
    /// Run: `WAF_FDS_OUT=app.bin cargo test -p waf-modules-premium emit_fixture_descriptor -- --ignored`
    #[test]
    #[ignore]
    fn emit_fixture_descriptor() {
        let out = std::env::var("WAF_FDS_OUT").expect("set WAF_FDS_OUT to the output .bin path");
        std::fs::write(&out, fixture_fds()).unwrap();
        eprintln!("wrote demo FileDescriptorSet to {out}");
    }

    #[test]
    fn valid_descriptor_loads() {
        assert!(parse_descriptors(&fixture_fds()).is_ok());
    }

    #[test]
    fn invalid_descriptor_bytes_are_rejected() {
        assert!(parse_descriptors(b"not a descriptor set").is_err());
    }

    #[test]
    fn valid_message_against_known_method_is_valid() {
        let pool = parse_descriptors(&fixture_fds()).unwrap();
        // HelloRequest { name = "x" } → field 1, wire-type 2, len 1, 'x'.
        let msg = [0x0a, 0x01, b'x'];
        assert_eq!(validate_message(&pool, SAYHELLO, &msg, false), GrpcValidity::Valid);
    }

    #[test]
    fn unknown_method_is_flagged() {
        let pool = parse_descriptors(&fixture_fds()).unwrap();
        assert_eq!(
            validate_message(&pool, "/test.v1.Greeter/DoesNotExist", &[0x0a, 0x01, b'x'], false),
            GrpcValidity::UnknownMethod
        );
        assert_eq!(
            validate_message(&pool, "/test.v1.Unknown/SayHello", &[], false),
            GrpcValidity::UnknownMethod
        );
    }

    #[test]
    fn undecodable_message_is_decode_error() {
        let pool = parse_descriptors(&fixture_fds()).unwrap();
        // field 1, wire-type 2, length 255 but no data → truncated → decode error.
        assert_eq!(validate_message(&pool, SAYHELLO, &[0x0a, 0xff], false), GrpcValidity::DecodeError);
    }

    // ── Step 4: unknown-field detection (H3, opt-in) ────────────────────────────

    // HelloRequest has only field 1. Field 5 (0x2a = 5<<3 | 2) is unknown to the descriptor but a
    // legal protobuf wire field (forward-compat).
    const MSG_WITH_UNKNOWN_FIELD: [u8; 6] = [0x0a, 0x01, b'x', 0x2a, 0x01, b'y'];

    #[test]
    fn unknown_field_reported_only_when_flag_on() {
        let pool = parse_descriptors(&fixture_fds()).unwrap();
        // Flag ON → reported.
        assert_eq!(
            validate_message(&pool, SAYHELLO, &MSG_WITH_UNKNOWN_FIELD, true),
            GrpcValidity::UnknownField
        );
        // Flag OFF (default) → tolerated as Valid (protobuf forward-compat; H3 opt-in).
        assert_eq!(
            validate_message(&pool, SAYHELLO, &MSG_WITH_UNKNOWN_FIELD, false),
            GrpcValidity::Valid
        );
    }

    #[test]
    fn known_only_message_is_valid_even_with_flag_on() {
        let pool = parse_descriptors(&fixture_fds()).unwrap();
        // Only field 1 → no FP even with flagging on.
        assert_eq!(validate_message(&pool, SAYHELLO, &[0x0a, 0x01, b'x'], true), GrpcValidity::Valid);
    }

    #[test]
    fn has_unknown_field_walks_top_level_tags() {
        assert!(has_unknown_field(&[1], &MSG_WITH_UNKNOWN_FIELD)); // field 5 not known
        assert!(!has_unknown_field(&[1, 5], &MSG_WITH_UNKNOWN_FIELD)); // both known
        assert!(!has_unknown_field(&[1], &[0x0a, 0x01, b'x'])); // only field 1
    }

    fn temp_path(tag: &str) -> std::path::PathBuf {
        let uniq = format!(
            "waf-fds-{tag}-{}-{:?}.bin",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        );
        std::env::temp_dir().join(uniq)
    }

    #[test]
    fn load_descriptors_reads_and_validates_a_file() {
        let path = temp_path("ok");
        std::fs::write(&path, fixture_fds()).unwrap();
        let loaded = load_descriptors(&path);
        let _ = std::fs::remove_file(&path);
        assert!(loaded.is_ok());
    }

    #[test]
    fn load_descriptors_missing_file_is_err() {
        assert!(load_descriptors(&temp_path("missing")).is_err());
    }

    #[test]
    fn from_config_is_boot_fatal_on_invalid_descriptor() {
        let path = temp_path("bad");
        std::fs::write(&path, b"not a descriptor set").unwrap();
        let cfg = GrpcSchemaEnforcementConfig { descriptor_path: path.clone(), ..Default::default() };
        let built = GrpcSchemaModule::from_config(&cfg);
        let _ = std::fs::remove_file(&path);
        assert!(built.is_err(), "an invalid descriptor file must fail construction (fail-closed boot)");
    }

    #[test]
    fn from_config_builds_from_a_valid_file() {
        let path = temp_path("good");
        std::fs::write(&path, fixture_fds()).unwrap();
        let cfg = GrpcSchemaEnforcementConfig {
            enabled: true,
            descriptor_path: path.clone(),
            ..Default::default()
        };
        let built = GrpcSchemaModule::from_config(&cfg);
        let _ = std::fs::remove_file(&path);
        assert!(built.is_ok());
    }

    #[test]
    fn default_config_is_off_and_unknown_fields_disabled() {
        let c = GrpcSchemaEnforcementConfig::default();
        assert!(!c.enabled);
        assert!(!c.flag_unknown_fields, "unknown-field flagging is opt-in (H3)");
    }

    #[test]
    fn deframes_and_skips_compressed() {
        // one uncompressed frame [0][len][msg] + one compressed frame [1][len][msg]
        let mut body = vec![0u8];
        body.extend_from_slice(&3u32.to_be_bytes());
        body.extend_from_slice(&[0x0a, 0x01, b'x']);
        body.push(1u8); // compressed flag
        body.extend_from_slice(&2u32.to_be_bytes());
        body.extend_from_slice(&[0xaa, 0xbb]);
        let f = frames(&body);
        assert_eq!(f.len(), 1, "compressed frame must be skipped");
        assert_eq!(f[0], &[0x0a, 0x01, b'x']);
    }

    #[test]
    fn frames_empty_and_truncated_are_safe() {
        assert!(frames(&[]).is_empty());
        // header claims a 9-byte message but only 2 bytes follow → stop, no panic, no partial.
        let mut trunc = vec![0u8];
        trunc.extend_from_slice(&9u32.to_be_bytes());
        trunc.extend_from_slice(&[0x0a, 0x01]);
        assert!(frames(&trunc).is_empty());
    }

    // ── Step 3: extraction / gating through inspect ─────────────────────────────
    use waf_core::{Bytes, Normalized};

    fn frame(msg: &[u8]) -> Vec<u8> {
        let mut b = vec![0u8];
        b.extend_from_slice(&(msg.len() as u32).to_be_bytes());
        b.extend_from_slice(msg);
        b
    }

    fn ctx(path: &str, ctype: &str, body: ParsedBody) -> RequestContext {
        let normalized = Normalized {
            path: path.to_string(),
            headers: vec![("content-type".to_string(), ctype.to_string())],
            body,
            ..Default::default()
        };
        RequestContext {
            client_ip: "127.0.0.1".parse().unwrap(),
            request_id: "t".to_string(),
            timestamp: std::time::SystemTime::now(),
            method: "POST".to_string(),
            path: path.to_string(),
            raw_path: path.to_string(),
            query: None,
            http_version: "HTTP/2".to_string(),
            headers: vec![],
            cookies: vec![],
            body: Bytes::new(),
            normalized,
            score: 0,
            score_contributions: vec![],
        }
    }

    fn module() -> GrpcSchemaModule {
        GrpcSchemaModule::from_fds_bytes(&fixture_fds(), true).unwrap()
    }

    fn scored(d: &Decision) -> Vec<String> {
        match d {
            Decision::Scores(items) => items.iter().map(|i| i.rule_id.clone()).collect(),
            _ => vec![],
        }
    }

    #[test]
    fn inspect_dedups_multi_frame_unknown_method() {
        // Two frames, both to a non-existent method → one deduped unknown-method contribution.
        let mut body = frame(&[0x0a, 0x01, b'x']);
        body.extend_from_slice(&frame(&[0x0a, 0x01, b'y']));
        let c = ctx("/test.v1.Greeter/Nope", "application/grpc", ParsedBody::Raw(Bytes::from(body)));
        assert_eq!(scored(&module().inspect(&c)), vec![rules::GRPC_UNKNOWN_METHOD.id()]);
    }

    #[test]
    fn inspect_scores_decode_error_on_a_known_method_ignoring_valid_frames() {
        // Frame 1 valid + frame 2 undecodable, on a KNOWN method → only decode-error (valid is inert).
        let mut body = frame(&[0x0a, 0x01, b'x']);
        body.extend_from_slice(&frame(&[0x0a, 0xff])); // truncated → decode error
        let c = ctx("/test.v1.Greeter/SayHello", "application/grpc", ParsedBody::Raw(Bytes::from(body)));
        assert_eq!(scored(&module().inspect(&c)), vec![rules::GRPC_DECODE_ERROR.id()]);
    }

    #[test]
    fn inspect_accepts_grpc_proto_content_type_variant() {
        let c = ctx(
            "/test.v1.Greeter/Nope",
            "application/grpc+proto",
            ParsedBody::Raw(Bytes::from(frame(&[0x0a, 0x01, b'x']))),
        );
        assert_eq!(scored(&module().inspect(&c)), vec![rules::GRPC_UNKNOWN_METHOD.id()]);
    }

    #[test]
    fn inspect_ignores_non_grpc_content_type() {
        let c = ctx(
            "/test.v1.Greeter/Nope",
            "application/json",
            ParsedBody::Raw(Bytes::from(frame(&[0x0a, 0x01, b'x']))),
        );
        assert_eq!(module().inspect(&c), Decision::Allow);
    }

    #[test]
    fn inspect_ignores_non_raw_body() {
        // A parsed JSON body is not a framed gRPC message → nothing to validate.
        let c = ctx(
            "/test.v1.Greeter/Nope",
            "application/grpc",
            ParsedBody::JsonFlattened(vec![("a".to_string(), "b".to_string())]),
        );
        assert_eq!(module().inspect(&c), Decision::Allow);
    }

    #[test]
    fn inspect_flags_unknown_field_only_with_flagging_module() {
        let body = ParsedBody::Raw(Bytes::from(frame(&MSG_WITH_UNKNOWN_FIELD)));
        let c = ctx("/test.v1.Greeter/SayHello", "application/grpc", body);

        // Default module (flagging off) → the unknown field is tolerated (no contribution).
        assert_eq!(module().inspect(&c), Decision::Allow);

        // Flagging module → emits the opt-in unknown-field signal.
        let flagging = GrpcSchemaModule::from_fds_bytes_flagging(&fixture_fds()).unwrap();
        assert_eq!(scored(&flagging.inspect(&c)), vec![rules::GRPC_UNKNOWN_FIELD.id()]);
    }

    #[test]
    fn inspect_resolves_method_from_case_sensitive_raw_path() {
        // Wire regression: the normalizer lowercases `normalized.path`, but gRPC service/method
        // names are case-sensitive → resolution must use the raw `ctx.path`. A valid call must NOT
        // be misread as unknown-method.
        let mut c = ctx(
            "/test.v1.Greeter/SayHello",
            "application/grpc",
            ParsedBody::Raw(Bytes::from(frame(&[0x0a, 0x01, b'x']))),
        );
        c.normalized.path = "/test.v1.greeter/sayhello".to_string(); // as the normalizer sets it
        assert_eq!(module().inspect(&c), Decision::Allow);
    }
}
