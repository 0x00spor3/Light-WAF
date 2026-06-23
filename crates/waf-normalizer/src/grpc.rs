// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

//! Minimal gRPC framing + protobuf wire-format extractor (the 9th custom parser in this
//! crate, fuzzed — see ARCHITECTURE §13). Two layers, one linear pass, never panics:
//!
//! 1. **gRPC framing**: a body is a sequence of length-prefixed messages
//!    `[compressed-flag:1][length:4 big-endian][message:length]`. We de-frame, count
//!    messages/bytes, and flag any **compressed** frame (the per-message flag bit) — a
//!    compressed payload is opaque here, the policy (`on_compressed`) lives in the module.
//!
//! 2. **protobuf wire-format (NO schema)**: each field is `tag = (field<<3)|wire_type`
//!    (varint) followed by its value. We walk the fields and, for **length-delimited**
//!    (wire-type 2) fields, apply the heuristic: *valid UTF-8 → a leaf string*
//!    (a content-inspection candidate, fed to the §6 derived channel); *otherwise →
//!    recurse as a nested sub-message* (depth-capped). Varint/fixed fields are skipped.
//!
//! **Honesty (best-effort).** The wire format is schema-less and therefore *ambiguous* by
//! construction: a length-delimited field may be a string, opaque bytes, or an embedded
//! message, and they are indistinguishable without the `.proto`. So content extraction is
//! **best-effort** (the same status as GraphQL `max_complexity`). The *guaranteed*
//! deliverable is the **structural** signal — message size, field count, nesting depth,
//! compressed/malformed flags — which the `grpc` module turns into a `Reject`. NB: a
//! sub-message whose raw bytes are valid UTF-8 is kept as ONE leaf string; the nested
//! field *content* is still a substring of it, so a content rule still matches — only the
//! per-field structure is lost, not the payload text.

/// Caps that bound the parser's own work (anti-DoS during parsing) and surface the
/// structural signal. `max_depth`/`max_fields` doubling as the parser bound and the
/// module's cap is deliberate: parsing past a cap that already forces a `Reject` is wasted
/// work. `max_leaves` bounds the extracted content surface.
#[derive(Debug, Clone, Copy)]
pub struct GrpcLimits {
    pub max_depth: u32,
    pub max_fields: u32,
    pub max_leaves: usize,
}

impl Default for GrpcLimits {
    fn default() -> Self {
        Self { max_depth: 16, max_fields: 4096, max_leaves: 1024 }
    }
}

/// Structural metrics + extracted content of a gRPC body.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct GrpcExtract {
    /// Number of length-prefixed frames.
    pub messages: u32,
    /// Sum of message lengths (the inspectable payload size).
    pub total_payload_bytes: u64,
    /// Largest single frame length.
    pub max_message_len: u32,
    /// Total protobuf fields walked (across frames).
    pub fields: u32,
    /// Deepest sub-message nesting actually entered (≤ `max_depth`).
    pub max_depth: u32,
    /// A sub-message at the depth cap tried to nest deeper (depth-bomb signal).
    pub depth_exceeded: bool,
    /// The field cap was hit (field-bomb signal); parsing of that message stopped.
    pub fields_exceeded: bool,
    /// At least one frame carried the per-message COMPRESSED flag (payload not parsed).
    pub compressed: bool,
    /// Framing or wire-format parse hit something illegal/truncated.
    pub malformed: bool,
    /// UTF-8 length-delimited fields — content-inspection candidates (best-effort).
    pub leaves: Vec<String>,
}

/// Read a base-128 varint at `*i`, advancing `*i`. `None` on truncation or >10 bytes.
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
    None // more than 10 continuation bytes → malformed
}

/// De-frame `body` and extract its [`GrpcExtract`]. Linear, bounded by `limits`, no panic.
pub fn grpc_extract(body: &[u8], limits: GrpcLimits) -> GrpcExtract {
    let mut out = GrpcExtract::default();
    let mut pos = 0;
    while pos + 5 <= body.len() {
        let flag = body[pos];
        let len = u32::from_be_bytes([body[pos + 1], body[pos + 2], body[pos + 3], body[pos + 4]]) as usize;
        let msg_start = pos + 5;
        let Some(msg_end) = msg_start.checked_add(len) else {
            out.malformed = true;
            return out;
        };
        if msg_end > body.len() {
            out.malformed = true; // truncated frame
            return out;
        }
        out.messages = out.messages.saturating_add(1);
        out.total_payload_bytes = out.total_payload_bytes.saturating_add(len as u64);
        out.max_message_len = out.max_message_len.max(len as u32);

        let msg = &body[msg_start..msg_end];
        match flag {
            0 => parse_message(msg, 1, &limits, &mut out),
            1 => out.compressed = true, // compressed payload — policy upstream (on_compressed)
            _ => out.malformed = true,  // only 0/1 are defined flag values
        }
        pos = msg_end;
    }
    // Trailing bytes that do not form a full 5-byte header = a partial/illegal frame.
    if pos != body.len() {
        out.malformed = true;
    }
    out
}

/// Walk one protobuf message at `depth`, mutating `out`. Stops (without panic) on the
/// first malformed field or when a cap is hit.
fn parse_message(buf: &[u8], depth: u32, limits: &GrpcLimits, out: &mut GrpcExtract) {
    out.max_depth = out.max_depth.max(depth);
    let mut i = 0;
    while i < buf.len() {
        let Some(tag) = read_varint(buf, &mut i) else {
            out.malformed = true;
            return;
        };
        out.fields = out.fields.saturating_add(1);
        if out.fields > limits.max_fields {
            out.fields_exceeded = true;
            return;
        }
        match (tag & 0x7) as u8 {
            0 => {
                // VARINT
                if read_varint(buf, &mut i).is_none() {
                    out.malformed = true;
                    return;
                }
            }
            1 => {
                // I64 (8 bytes)
                if i + 8 > buf.len() {
                    out.malformed = true;
                    return;
                }
                i += 8;
            }
            5 => {
                // I32 (4 bytes)
                if i + 4 > buf.len() {
                    out.malformed = true;
                    return;
                }
                i += 4;
            }
            2 => {
                // LEN (length-delimited): string | bytes | sub-message.
                let Some(len) = read_varint(buf, &mut i) else {
                    out.malformed = true;
                    return;
                };
                let end = match i.checked_add(len as usize) {
                    Some(e) if e <= buf.len() => e,
                    _ => {
                        out.malformed = true;
                        return;
                    }
                };
                let field = &buf[i..end];
                i = end;
                match std::str::from_utf8(field) {
                    // valid UTF-8 → a leaf string (content-inspection candidate)
                    Ok(s) if !s.is_empty() => {
                        if out.leaves.len() < limits.max_leaves {
                            out.leaves.push(s.to_string());
                        }
                    }
                    Ok(_) => {} // empty field: nothing to inspect
                    // not UTF-8 → try as a nested sub-message, depth-capped
                    Err(_) => {
                        if depth >= limits.max_depth {
                            out.depth_exceeded = true;
                        } else {
                            parse_message(field, depth + 1, limits, out);
                        }
                    }
                }
            }
            // groups (3/4, deprecated) or an illegal wire type → stop this message.
            _ => {
                out.malformed = true;
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── protobuf / gRPC encoders (test helpers) ──────────────────────────────────

    fn varint(mut v: u64, out: &mut Vec<u8>) {
        loop {
            let mut byte = (v & 0x7f) as u8;
            v >>= 7;
            if v != 0 {
                byte |= 0x80;
            }
            out.push(byte);
            if v == 0 {
                break;
            }
        }
    }

    /// A length-delimited (wire-type 2) field: `field` number carrying `data`.
    fn len_field(field: u64, data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        varint((field << 3) | 2, &mut out);
        varint(data.len() as u64, &mut out);
        out.extend_from_slice(data);
        out
    }

    /// A varint (wire-type 0) field — useful to force NON-UTF-8 bytes (value ≥ 0x80) so a
    /// sub-message wrapping it is recursed, not mistaken for a string.
    fn varint_field(field: u64, value: u64) -> Vec<u8> {
        let mut out = Vec::new();
        varint(field << 3, &mut out); // wire-type 0 (VARINT) = the low 3 bits being zero
        varint(value, &mut out);
        out
    }

    /// Wrap a message body in a single uncompressed gRPC frame.
    fn frame(msg: &[u8]) -> Vec<u8> {
        let mut out = vec![0u8];
        out.extend_from_slice(&(msg.len() as u32).to_be_bytes());
        out.extend_from_slice(msg);
        out
    }

    // ── extraction ────────────────────────────────────────────────────────────────

    #[test]
    fn extracts_string_leaf_from_unary_frame() {
        // {1: "1 UNION SELECT a,b FROM users--"} in one uncompressed frame.
        let sqli = "1 UNION SELECT a,b FROM users--";
        let body = frame(&len_field(1, sqli.as_bytes()));
        let ex = grpc_extract(&body, GrpcLimits::default());
        assert_eq!(ex.messages, 1);
        assert!(!ex.compressed && !ex.malformed);
        assert!(ex.leaves.iter().any(|l| l == sqli), "SQLi leaf must be extracted: {:?}", ex.leaves);
    }

    #[test]
    fn recurses_into_non_utf8_submessage() {
        // Outer {3: <sub>} where sub = {2: <varint 300>}{1: "inner-secret"}. The varint
        // (300 = 0xac 0x02) makes the sub-message bytes non-UTF-8 → recursion fires.
        let mut sub = varint_field(2, 300);
        sub.extend_from_slice(&len_field(1, b"inner-secret"));
        let body = frame(&len_field(3, &sub));
        let ex = grpc_extract(&body, GrpcLimits::default());
        assert!(ex.max_depth >= 2, "must recurse into the sub-message (depth {})", ex.max_depth);
        assert!(ex.leaves.iter().any(|l| l == "inner-secret"), "nested leaf: {:?}", ex.leaves);
        assert!(!ex.depth_exceeded);
    }

    // ── paletto A: the trap (benign deep nesting) vs a depth-bomb ────────────────

    /// Build `depth` nested NON-UTF-8 sub-messages (each wraps a varint to force recursion)
    /// with a benign string at the bottom.
    fn nested_messages(depth: u32) -> Vec<u8> {
        let mut inner = varint_field(2, 300); // non-UTF-8 marker
        inner.extend_from_slice(&len_field(15, b"benign-leaf"));
        for _ in 0..depth {
            inner = {
                let mut wrap = varint_field(2, 300);
                wrap.extend_from_slice(&len_field(1, &inner));
                wrap
            };
        }
        frame(&inner)
    }

    #[test]
    fn benign_deep_but_within_cap_is_not_a_false_reject() {
        // The negative reference (paletto A): legitimately nested, but under the cap →
        // fully extracted, depth_exceeded = FALSE. Proves the cap distinguishes nesting
        // from a depth-bomb.
        let limits = GrpcLimits { max_depth: 16, ..GrpcLimits::default() };
        let ex = grpc_extract(&nested_messages(8), limits);
        assert!(!ex.depth_exceeded, "legitimate nesting must not trip the depth cap");
        assert!(!ex.malformed);
        assert!(ex.leaves.iter().any(|l| l == "benign-leaf"));
    }

    #[test]
    fn depth_bomb_beyond_cap_is_flagged() {
        let limits = GrpcLimits { max_depth: 8, ..GrpcLimits::default() };
        let ex = grpc_extract(&nested_messages(40), limits);
        assert!(ex.depth_exceeded, "a depth-bomb past the cap must be flagged");
        assert!(ex.max_depth <= 8, "recursion must stop at the cap (got {})", ex.max_depth);
    }

    // ── structural signals ───────────────────────────────────────────────────────

    #[test]
    fn compressed_frame_is_flagged_not_parsed() {
        // flag = 1 (compressed); the payload is opaque → no leaves, compressed = true.
        let mut body = vec![1u8];
        let payload = len_field(1, b"would-be-secret");
        body.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        body.extend_from_slice(&payload);
        let ex = grpc_extract(&body, GrpcLimits::default());
        assert!(ex.compressed);
        assert!(ex.leaves.is_empty(), "a compressed frame must not be parsed here");
    }

    #[test]
    fn field_cap_is_flagged() {
        let mut msg = Vec::new();
        for n in 1..=10u64 {
            msg.extend_from_slice(&varint_field(n, 1));
        }
        let ex = grpc_extract(&frame(&msg), GrpcLimits { max_fields: 5, ..GrpcLimits::default() });
        assert!(ex.fields_exceeded);
    }

    #[test]
    fn multi_frame_body_counts_all() {
        let mut body = frame(&len_field(1, b"first"));
        body.extend_from_slice(&frame(&len_field(1, b"second")));
        let ex = grpc_extract(&body, GrpcLimits::default());
        assert_eq!(ex.messages, 2);
        assert!(ex.leaves.iter().any(|l| l == "first"));
        assert!(ex.leaves.iter().any(|l| l == "second"));
    }

    // ── robustness (never panic) ─────────────────────────────────────────────────

    #[test]
    fn truncated_and_malformed_inputs_do_not_panic() {
        let limits = GrpcLimits::default();
        let _ = grpc_extract(&[], limits);
        let _ = grpc_extract(&[0], limits); // partial header
        let _ = grpc_extract(&[0, 0, 0, 0, 100], limits); // length 100, no payload
        let _ = grpc_extract(&[0, 0, 0, 0, 3, 0xff, 0xff, 0xff], limits); // garbage payload
        let _ = grpc_extract(&[0, 0, 0, 0, 2, 0x08], limits); // tag varint then truncated value
        // a LEN field claiming more bytes than present
        let _ = grpc_extract(&frame(&[0x0a, 0x7f]), limits);
    }

    #[test]
    fn empty_string_field_yields_no_leaf() {
        let ex = grpc_extract(&frame(&len_field(1, b"")), GrpcLimits::default());
        assert!(ex.leaves.is_empty());
        assert_eq!(ex.messages, 1);
        assert!(!ex.malformed);
    }
}
