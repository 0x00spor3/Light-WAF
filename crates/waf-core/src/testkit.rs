//! Test-only builders for [`RequestContext`], gated behind the `testkit` feature.
//!
//! These builders populate **raw** request fields (pre-normalization) plus stable
//! defaults for the 14 context fields. They deliberately do **not** write into
//! `ctx.normalized.*` — unlike the per-test shortcut helpers in the detection
//! crate's integration tests (`with_query`, `with_cookies`, …) which bypass the
//! normalizer. A consumer (e.g. the `waf-corpus` validation suite) builds the raw
//! context here and then runs the real `Normalizer::normalize`, so the corpus
//! exercises the production pipeline rather than bypassing it.
//!
//! Defaults are deterministic (`timestamp = UNIX_EPOCH`, `request_id = "corpus"`,
//! `client_ip = 127.0.0.1`, …) so reports/assertions stay reproducible. Override
//! per-field via the builder methods where a case needs it.

use std::net::{IpAddr, Ipv4Addr};
use std::time::SystemTime;

use crate::{Bytes, Normalized, RequestContext};

const FORM_CONTENT_TYPE: &str = "application/x-www-form-urlencoded";
const JSON_CONTENT_TYPE: &str = "application/json";

/// A context with all stable defaults and no payload — convenience for
/// `Request::new().build()`.
pub fn base_ctx() -> RequestContext {
    Request::new().build()
}

/// Fluent builder for a raw (pre-normalization) [`RequestContext`].
pub struct Request {
    ctx: RequestContext,
}

impl Default for Request {
    fn default() -> Self {
        Self::new()
    }
}

impl Request {
    /// A request with deterministic defaults: GET `/`, HTTP/1.1, loopback client,
    /// epoch timestamp, no query/headers/cookies/body, zero score.
    pub fn new() -> Self {
        Self {
            ctx: RequestContext {
                client_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                request_id: "corpus".to_string(),
                timestamp: SystemTime::UNIX_EPOCH,
                method: "GET".to_string(),
                path: "/".to_string(),
                raw_path: "/".to_string(),
                query: None,
                http_version: "HTTP/1.1".to_string(),
                headers: Vec::new(),
                cookies: Vec::new(),
                body: Bytes::new(),
                normalized: Normalized::default(),
                score: 0,
                score_contributions: Vec::new(),
            },
        }
    }

    /// Override the (otherwise stable) request id.
    pub fn request_id(mut self, id: &str) -> Self {
        self.ctx.request_id = id.to_string();
        self
    }

    /// Override the (otherwise epoch) timestamp — kept injectable for determinism.
    pub fn timestamp(mut self, t: SystemTime) -> Self {
        self.ctx.timestamp = t;
        self
    }

    /// Set the HTTP method.
    pub fn method(mut self, method: &str) -> Self {
        self.ctx.method = method.to_string();
        self
    }

    /// Set both `path` and `raw_path` (the normalizer derives `normalized.path`
    /// from `raw_path`).
    pub fn path(mut self, path: &str) -> Self {
        self.ctx.path = path.to_string();
        self.ctx.raw_path = path.to_string();
        self
    }

    /// Set the verbatim raw query string (the part after `?`), e.g.
    /// `q=%2527+OR+1%253D1--`. Use this for payloads that craft their own
    /// encoding (double-encoding, literal `+`).
    pub fn raw_query(mut self, query_string: &str) -> Self {
        self.ctx.query = Some(query_string.to_string());
        self
    }

    /// Append a `name=value` pair to the raw query string, percent-encoding only
    /// the characters that would otherwise change query parsing (`%`, `&`, `+`)
    /// so the normalizer decodes `value` back exactly. For self-encoded payloads
    /// use [`Request::raw_query`].
    pub fn query(mut self, name: &str, value: &str) -> Self {
        let pair = format!("{}={}", enc_query_component(name), enc_query_component(value));
        match &mut self.ctx.query {
            Some(existing) => {
                existing.push('&');
                existing.push_str(&pair);
            }
            None => self.ctx.query = Some(pair),
        }
        self
    }

    /// Add a raw header. Names are kept as given; the normalizer lowercases them.
    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.ctx.headers.push((name.to_string(), value.to_string()));
        self
    }

    /// Add a raw `Cookie` header value, e.g. `sid=%27%20OR%201%3D1--`.
    pub fn cookie_header(self, raw: &str) -> Self {
        self.header("cookie", raw)
    }

    /// Set an `application/x-www-form-urlencoded` body from a raw `a=b&c=d` string.
    pub fn form_body(self, raw: &str) -> Self {
        self.body(raw.as_bytes().to_vec(), FORM_CONTENT_TYPE)
    }

    /// Set an `application/json` body from raw JSON text.
    pub fn json_body(self, raw: &str) -> Self {
        self.body(raw.as_bytes().to_vec(), JSON_CONTENT_TYPE)
    }

    /// Set the raw body bytes and the `Content-Type` header.
    pub fn body(mut self, bytes: impl Into<Bytes>, content_type: &str) -> Self {
        self.ctx.body = bytes.into();
        self.ctx.headers.push(("content-type".to_string(), content_type.to_string()));
        self
    }

    /// Finalize the raw context.
    pub fn build(self) -> RequestContext {
        self.ctx
    }
}

/// Percent-encode the three characters that alter query parsing (`%`, `&`, `+`).
/// All other bytes (including multi-byte UTF-8) pass through unchanged, so the
/// result is still valid UTF-8 and the normalizer round-trips `value` exactly.
fn enc_query_component(s: &str) -> String {
    let mut out: Vec<u8> = Vec::with_capacity(s.len());
    for &b in s.as_bytes() {
        match b {
            b'%' => out.extend_from_slice(b"%25"),
            b'&' => out.extend_from_slice(b"%26"),
            b'+' => out.extend_from_slice(b"%2B"),
            other => out.push(other),
        }
    }
    String::from_utf8(out).expect("only ASCII bytes were substituted; UTF-8 stays valid")
}
