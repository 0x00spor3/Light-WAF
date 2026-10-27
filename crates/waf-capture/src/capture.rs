// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

//! The captured-request DTO and how it is built from a live [`RequestContext`].
//!
//! [`CapturedRequest`] is the wire + storage shape: it is what the ring holds (C1), what the shipper
//! POSTs to the control-plane (C2), and what the CP stores/serves (C3+). The body is carried as
//! base64 (JSON cannot hold raw bytes; the CP column is `BYTEA`). Two node-side guards are applied
//! here so nothing sensitive/oversized ever leaves the node:
//!   - **redaction** — header/cookie/body-field values whose name matches [`RedactionConfig`] are
//!     replaced with [`REDACTED`]. Body redaction is structured (JSON keys / form params);
//!   - **truncation** — the stored body is capped at `max_body_bytes`, with the original size and a
//!     `body_truncated` flag preserved.

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use waf_core::RequestContext;

use crate::RedactionConfig;

/// The placeholder a redacted value is replaced with.
pub const REDACTED: &str = "***REDACTED***";

/// A captured HTTP request — the full request the WAF denied, as forwarded to the control-plane
/// drill-down. Built by [`CapturedRequest::from_ctx`] with redaction + truncation already applied.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapturedRequest {
    /// Correlation id — the same `request_id` the decision-log carries, so the CP joins this
    /// capture onto the stored `DecisionEvent`.
    pub request_id: String,
    pub method: String,
    pub path: String,
    pub query: Option<String>,
    pub http_version: String,
    /// Raw request headers as received (names as-sent), redacted values swapped for [`REDACTED`].
    pub headers: Vec<(String, String)>,
    /// Parsed cookies, redacted values swapped for [`REDACTED`].
    pub cookies: Vec<(String, String)>,
    /// Base64 of the (possibly redacted, possibly truncated) body bytes.
    pub body_b64: String,
    /// Original body size in bytes, before any truncation.
    pub body_size: usize,
    /// True when the stored body was capped at `max_body_bytes` (the original was larger).
    pub body_truncated: bool,
    /// Names (headers / cookies / body fields) that were redacted node-side — drives the UI banner.
    pub redacted: Vec<String>,
}

impl CapturedRequest {
    /// Build a capture from a live request context, applying `redaction` (node-side) and capping the
    /// stored body at `max_body_bytes`. Reads the RAW request fields (`ctx.headers`/`ctx.cookies`/
    /// `ctx.body`) — the request *as received*, not the normalized canonical forms.
    pub fn from_ctx(ctx: &RequestContext, max_body_bytes: usize, redaction: &RedactionConfig) -> Self {
        let mut redacted: Vec<String> = Vec::new();

        // Headers: redact by header name.
        let headers = ctx
            .headers
            .iter()
            .map(|(name, value)| {
                if redaction.header_redacted(name) {
                    push_unique(&mut redacted, name);
                    (name.clone(), REDACTED.to_string())
                } else {
                    (name.clone(), value.clone())
                }
            })
            .collect();

        // Cookies: a blanket redaction when `cookie`/`set-cookie` is in the header list (the raw
        // Cookie header carries the same data), else per-cookie by name against the body-field list.
        let blanket_cookies =
            redaction.header_redacted("cookie") || redaction.header_redacted("set-cookie");
        let cookies = ctx
            .cookies
            .iter()
            .map(|(name, value)| {
                if blanket_cookies || redaction.field_redacted(name) {
                    push_unique(&mut redacted, name);
                    (name.clone(), REDACTED.to_string())
                } else {
                    (name.clone(), value.clone())
                }
            })
            .collect();

        // Body: structured field redaction (only when it fits the cap — a truncated body cannot be
        // parsed), then truncate to `max_body_bytes`.
        let body_size = ctx.body.len();
        let raw: &[u8] = ctx.body.as_ref();
        let redacted_body: Vec<u8> = if !redaction.body_fields.is_empty() && body_size <= max_body_bytes {
            redact_body(raw, content_type(&ctx.headers), redaction, &mut redacted)
        } else {
            raw.to_vec()
        };
        let body_truncated = redacted_body.len() > max_body_bytes;
        let stored = &redacted_body[..redacted_body.len().min(max_body_bytes)];
        let body_b64 = base64::engine::general_purpose::STANDARD.encode(stored);

        Self {
            request_id: ctx.request_id.clone(),
            method: ctx.method.clone(),
            path: ctx.path.clone(),
            query: ctx.query.clone(),
            http_version: ctx.http_version.clone(),
            headers,
            cookies,
            body_b64,
            body_size,
            body_truncated,
            redacted,
        }
    }

    /// Rough in-memory footprint, used by the ring to enforce its byte budget. Dominated by the
    /// base64 body; header/cookie/line sizes are added so a header-heavy request is accounted for.
    pub fn estimated_bytes(&self) -> usize {
        let hdr: usize = self.headers.iter().map(|(k, v)| k.len() + v.len()).sum();
        let cke: usize = self.cookies.iter().map(|(k, v)| k.len() + v.len()).sum();
        self.body_b64.len()
            + hdr
            + cke
            + self.request_id.len()
            + self.method.len()
            + self.path.len()
            + self.query.as_ref().map_or(0, |q| q.len())
    }
}

/// The `content-type` header value (lowercased), if present. Case-insensitive on the header name.
fn content_type(headers: &[(String, String)]) -> Option<String> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
        .map(|(_, v)| v.to_ascii_lowercase())
}

/// Redact body fields by content-type: JSON (keys, recursively) or form-urlencoded (params). An
/// unrecognized / unparseable body is returned unchanged (structured redaction cannot locate fields).
fn redact_body(
    body: &[u8],
    content_type: Option<String>,
    redaction: &RedactionConfig,
    redacted: &mut Vec<String>,
) -> Vec<u8> {
    let ct = content_type.unwrap_or_default();
    if ct.contains("application/json") || ct.contains("+json") {
        if let Ok(mut v) = serde_json::from_slice::<serde_json::Value>(body) {
            redact_json(&mut v, redaction, redacted);
            if let Ok(s) = serde_json::to_vec(&v) {
                return s;
            }
        }
        body.to_vec()
    } else if ct.contains("application/x-www-form-urlencoded") {
        redact_form(body, redaction, redacted)
    } else {
        body.to_vec()
    }
}

/// Recursively replace, in a JSON value, every object member whose key matches the redaction list.
fn redact_json(v: &mut serde_json::Value, redaction: &RedactionConfig, redacted: &mut Vec<String>) {
    match v {
        serde_json::Value::Object(map) => {
            for (k, val) in map.iter_mut() {
                if redaction.field_redacted(k) {
                    push_unique(redacted, k);
                    *val = serde_json::Value::String(REDACTED.to_string());
                } else {
                    redact_json(val, redaction, redacted);
                }
            }
        }
        serde_json::Value::Array(items) => {
            for item in items.iter_mut() {
                redact_json(item, redaction, redacted);
            }
        }
        _ => {}
    }
}

/// Replace the value of any `key=value` pair whose key matches the redaction list. Keys are compared
/// as sent (case-insensitively); values are replaced verbatim with the placeholder.
fn redact_form(body: &[u8], redaction: &RedactionConfig, redacted: &mut Vec<String>) -> Vec<u8> {
    let text = String::from_utf8_lossy(body);
    let out = text
        .split('&')
        .map(|pair| match pair.split_once('=') {
            Some((key, _)) if redaction.field_redacted(key) => {
                push_unique(redacted, key);
                format!("{key}={REDACTED}")
            }
            _ => pair.to_string(),
        })
        .collect::<Vec<_>>()
        .join("&");
    out.into_bytes()
}

/// Push `name` into `redacted` unless already present (case-insensitively) — keeps the UI banner list
/// free of duplicates when the same field appears more than once.
fn push_unique(redacted: &mut Vec<String>, name: &str) {
    if !redacted.iter().any(|n| n.eq_ignore_ascii_case(name)) {
        redacted.push(name.to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use waf_core::testkit::Request;

    fn decode(b64: &str) -> String {
        String::from_utf8(base64::engine::general_purpose::STANDARD.decode(b64).unwrap()).unwrap()
    }

    #[test]
    fn raw_capture_keeps_everything() {
        let ctx = Request::new()
            .method("POST")
            .path("/login")
            .header("authorization", "Bearer secret")
            .json_body(r#"{"user":"a","password":"p"}"#)
            .build();
        let cap = CapturedRequest::from_ctx(&ctx, 64 * 1024, &RedactionConfig::default());
        assert_eq!(cap.method, "POST");
        assert_eq!(cap.path, "/login");
        assert!(cap.redacted.is_empty(), "no redaction configured");
        assert!(cap.headers.iter().any(|(k, v)| k == "authorization" && v == "Bearer secret"));
        assert_eq!(decode(&cap.body_b64), r#"{"user":"a","password":"p"}"#);
        assert!(!cap.body_truncated);
    }

    #[test]
    fn redacts_headers_and_json_body_fields() {
        let ctx = Request::new()
            .method("POST")
            .path("/login")
            .header("Authorization", "Bearer secret")
            .header("user-agent", "curl/8")
            .json_body(r#"{"user":"alice","password":"hunter2","nested":{"token":"t"}}"#)
            .build();
        let red = RedactionConfig {
            headers: vec!["authorization".to_string()],
            body_fields: vec!["password".to_string(), "token".to_string()],
        };
        let cap = CapturedRequest::from_ctx(&ctx, 64 * 1024, &red);

        // Header redacted, unrelated header intact.
        assert!(cap.headers.iter().any(|(k, v)| k == "Authorization" && v == REDACTED));
        assert!(cap.headers.iter().any(|(k, v)| k == "user-agent" && v == "curl/8"));

        // JSON body fields redacted (top-level + nested), other fields intact.
        let body = decode(&cap.body_b64);
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["password"], REDACTED);
        assert_eq!(v["nested"]["token"], REDACTED);
        assert_eq!(v["user"], "alice");

        // Names are recorded as-encountered (header `Authorization` as sent, body keys as in JSON).
        assert!(cap.redacted.contains(&"Authorization".to_string()));
        assert!(cap.redacted.contains(&"password".to_string()));
        assert!(cap.redacted.contains(&"token".to_string()));
    }

    #[test]
    fn redacts_form_body_fields() {
        let ctx = Request::new()
            .method("POST")
            .path("/login")
            .form_body("user=alice&password=hunter2&remember=1")
            .build();
        let red = RedactionConfig { headers: vec![], body_fields: vec!["password".to_string()] };
        let cap = CapturedRequest::from_ctx(&ctx, 64 * 1024, &red);
        let body = decode(&cap.body_b64);
        assert!(body.contains("password=***REDACTED***"));
        assert!(body.contains("user=alice"));
        assert!(body.contains("remember=1"));
    }

    #[test]
    fn blanket_cookie_redaction_when_cookie_header_listed() {
        let mut ctx = Request::new().path("/").build();
        ctx.cookies = vec![("sid".to_string(), "abc".to_string())];
        let red = RedactionConfig { headers: vec!["cookie".to_string()], body_fields: vec![] };
        let cap = CapturedRequest::from_ctx(&ctx, 64 * 1024, &red);
        assert_eq!(cap.cookies, vec![("sid".to_string(), REDACTED.to_string())]);
    }

    #[test]
    fn truncates_oversized_body_and_flags_it() {
        let big = "A".repeat(1000);
        let ctx = Request::new().method("POST").path("/upload").body(big.into_bytes(), "text/plain").build();
        let cap = CapturedRequest::from_ctx(&ctx, 100, &RedactionConfig::default());
        assert_eq!(cap.body_size, 1000, "original size preserved");
        assert!(cap.body_truncated);
        assert_eq!(decode(&cap.body_b64).len(), 100, "stored body capped at max_body_bytes");
    }
}
