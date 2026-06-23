// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

pub mod body;
pub mod graphql;
pub mod grpc;
pub mod url;

use waf_core::{LimitsConfig, RequestContext};

use crate::body::parse_body;
use crate::url::{canonicalize_value, normalize_path, parse_cookies_limited, parse_query};

// ── NormalizationError ────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NormalizationError {
    BodyTooLarge { limit: usize, actual: usize },
    TooManyHeaders { limit: usize },
    HeaderTooLarge { limit: usize, actual: usize },
    TooManyParams { limit: usize },
    TooManyCookies { limit: usize },
    JsonDepthExceeded { limit: usize },
    JsonParseError(String),
    MultipartError(String),
}

impl std::fmt::Display for NormalizationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BodyTooLarge { limit, actual } =>
                write!(f, "body too large: {actual} bytes (limit {limit})"),
            Self::TooManyHeaders { limit } =>
                write!(f, "too many headers (limit {limit})"),
            Self::HeaderTooLarge { limit, actual } =>
                write!(f, "header value too large: {actual} bytes (limit {limit})"),
            Self::TooManyParams { limit } =>
                write!(f, "too many parameters (limit {limit})"),
            Self::TooManyCookies { limit } =>
                write!(f, "too many cookies (limit {limit})"),
            Self::JsonDepthExceeded { limit } =>
                write!(f, "JSON nesting exceeds depth limit {limit}"),
            Self::JsonParseError(msg) =>
                write!(f, "JSON parse error: {msg}"),
            Self::MultipartError(msg) =>
                write!(f, "multipart error: {msg}"),
        }
    }
}

// ── Normalizer ────────────────────────────────────────────────────────────────

pub struct Normalizer {
    limits: LimitsConfig,
}

impl Normalizer {
    pub fn new(limits: &LimitsConfig) -> Self {
        Self { limits: limits.clone() }
    }

    /// Validate limits and populate `ctx.normalized` from the raw request fields.
    ///
    /// Call this before the pipeline runs. Returns an error (→ 400) if any
    /// defensive limit is exceeded; the error is not recoverable.
    pub fn normalize(&self, ctx: &mut RequestContext) -> Result<(), NormalizationError> {
        let limits = &self.limits;

        // ── 1. Body size ──────────────────────────────────────────────────────
        let body_len = ctx.body.len();
        if body_len > limits.max_body_size {
            return Err(NormalizationError::BodyTooLarge {
                limit: limits.max_body_size,
                actual: body_len,
            });
        }

        // ── 2. Header count + per-header value size ───────────────────────────
        if ctx.headers.len() > limits.max_headers {
            return Err(NormalizationError::TooManyHeaders { limit: limits.max_headers });
        }
        for (_name, value) in &ctx.headers {
            if value.len() > limits.max_header_size {
                return Err(NormalizationError::HeaderTooLarge {
                    limit: limits.max_header_size,
                    actual: value.len(),
                });
            }
        }

        // ── 3. Normalize header names (lowercase) and trim values ─────────────
        let norm_headers: Vec<(String, String)> = ctx
            .headers
            .iter()
            .map(|(k, v)| (k.to_lowercase(), v.trim().to_string()))
            .collect();

        // ── 4. Parse + canonicalize cookies (from normalized Cookie headers) ──
        // Limits (max_cookies count, plus max_header_size on the raw header value
        // in step 2) are enforced on the RAW text inside parse_cookies_limited,
        // BEFORE any decoding — so an encoded cookie that expands cannot bypass
        // them. Decoding then uses the SAME pass as query/body (canonicalize_value),
        // except `+` stays literal (RFC 6265 cookies are not form-encoded).
        // `derived_decoded`: base64 (10c) variants of inspected values, collected as
        // we go. Decode-then-match-then-discard. Cookies are EXCLUDED from the base64
        // channel (D3 — session cookies are base64-benign-heavy); they still get the
        // canonical (overlong) decode.
        let mut derived: Vec<String> = Vec::new();

        let mut cookies = Vec::new();
        let mut cookie_double_enc = false;
        for (name, value) in &norm_headers {
            if name == "cookie" {
                for (k, v) in parse_cookies_limited(value, limits.max_cookies)? {
                    let (dk, de_k) = canonicalize_value(&k, false);
                    let (dv, de_v) = canonicalize_value(&v, false);
                    cookie_double_enc |= de_k || de_v;
                    cookies.push((dk, dv)); // NB: no base64_derived — cookie surface excluded
                }
            }
        }

        // ── 5. Normalize path ─────────────────────────────────────────────────
        let (norm_path, path_double_enc) = normalize_path(&ctx.raw_path);

        // base64-derived from the URL PATH segments (10c REOPEN, pcap-confirmed:
        // gotestwaf places Base64Flat blobs AS the path, e.g. `/PGJvZHkg…`). The path
        // rules already scan `norm_path`, but the DECODE channel must reach it too.
        // Use the RAW path (case-PRESERVED — base64 is case-sensitive and normalize_path
        // lowercases), split on the literal `/` separators, percent-decode each segment
        // (path mode → `+` is literal), then derive. Normal path segments fail candidacy
        // (too short / non-alphabet) → no cost, no FP.
        for raw_seg in ctx.raw_path.split('/').filter(|s| !s.is_empty()) {
            let (seg, _) = url::percent_decode(raw_seg, false);
            derived.extend(url::derive_variants(&seg));
        }

        // ── 6. Parse query params (+ base64-derived) ──────────────────────────
        let (query_params, query_double_enc) = match &ctx.query {
            Some(q) => {
                let (p, de, d) = parse_query(q, limits)?;
                derived.extend(d);
                (p, de)
            }
            None => (Vec::new(), false),
        };

        // ── 7. Parse body (+ base64-derived from body values) ─────────────────
        let content_type = norm_headers
            .iter()
            .find(|(k, _)| k == "content-type")
            .map(|(_, v)| v.as_str());

        let parsed_body = parse_body(content_type, &ctx.body, limits)?;
        // Body-derived inspection surface (10c). JSON leaves get the FULL decode
        // (percent + overlong + base64) into the derived channel because
        // `body_str_values` inspects JSON values RAW (serde unescapes `\u` but does NOT
        // percent/overlong-decode; form & multipart already canonicalize their values).
        // EVERY flattened leaf is processed → nested objects/arrays are covered too.
        // Other body types only contribute base64-derived variants (already canonical).
        match &parsed_body {
            waf_core::ParsedBody::JsonFlattened(pairs) => {
                for (_, v) in pairs {
                    derived.extend(url::json_leaf_derived(v));
                }
            }
            // A `Raw` body (e.g. `application/graphql`, or any content-type the parser does
            // not structure) is inspected RAW by `body_str_values` — it never goes through
            // `canonicalize_value`, unlike form/multipart (canonicalized at parse) and JSON
            // leaves (`json_leaf_derived`). So a percent/overlong-encoded payload in a raw
            // body bypasses (Phase-11 Step-0 probe: `application/graphql` `%3Cscript%3E`
            // reached score 0). Push the canonical form into the derived channel — same
            // decode-then-match-then-discard pattern as the JSON leaf — plus the full
            // transform set. The canonical itself is pushed only when it DIFFERS from the raw
            // (when equal, `body_str_values` already inspects it; the guard also skips the
            // clone for un-encoded / binary bodies).
            waf_core::ParsedBody::Raw(b) => {
                // gRPC (`application/grpc*`): the framed protobuf body is BINARY, so the
                // canonical path below (`from_utf8`) extracts nothing. De-frame it and feed
                // the length-delimited protobuf FIELDS (leaf strings) to the derived channel,
                // so the content modules inspect a SQLi/XSS smuggled inside a field. This is
                // the §6 CONTENT surface (always-on, like JSON-leaf decode) — the structural
                // size/field/depth caps are the separate `grpc` module's job (accounting kept
                // apart). A compressed/malformed body yields no leaves (the module's policy
                // decides on those). Caps are generous defaults purely to bound the work.
                let is_grpc = content_type
                    .map(|ct| ct.trim_start().starts_with("application/grpc"))
                    .unwrap_or(false);
                if is_grpc {
                    let ex = crate::grpc::grpc_extract(b, crate::grpc::GrpcLimits::default());
                    for leaf in ex.leaves {
                        let canonical = url::canonicalize_value(&leaf, false).0;
                        derived.extend(url::derive_variants(&canonical));
                        // ALWAYS push the canonical leaf: unlike a UTF-8 raw body (which
                        // `body_str_values` inspects directly), the BINARY gRPC body is
                        // invisible to `body_str_values`, so the leaf only reaches the
                        // modules through this derived channel.
                        derived.push(canonical);
                    }
                } else if let Ok(raw) = std::str::from_utf8(b) {
                    let canonical = url::canonicalize_value(raw, false).0;
                    derived.extend(url::derive_variants(&canonical));
                    if canonical != raw {
                        derived.push(canonical);
                    }
                }
            }
            other => {
                for s in body_canonical_strings(other) {
                    derived.extend(url::derive_variants(&s));
                }
            }
        }

        // base64-derived from header VALUES, minus the structural per-name exclusion
        // (Authorization/Cookie/ETag/conditional-GET/`*-token`). Overlong is NOT
        // excluded here — but header values are kept raw for header_injection; only the
        // base64 channel reads them (the candidate is canonicalized inside base64_derived).
        for (name, value) in &norm_headers {
            if !header_base64_excluded(name) {
                derived.extend(url::derive_variants(value));
            }
        }

        // ── 8. Write results ──────────────────────────────────────────────────
        ctx.normalized.path = norm_path;
        ctx.normalized.query = ctx.query.clone();
        ctx.normalized.query_params = query_params;
        ctx.normalized.cookies = cookies;
        ctx.normalized.headers = norm_headers;
        ctx.normalized.body = parsed_body;
        ctx.normalized.double_encoding_detected =
            path_double_enc || query_double_enc || cookie_double_enc;
        ctx.normalized.derived_decoded = derived;

        Ok(())
    }
}

/// Header names STRUCTURALLY excluded from the base64-derive channel (D3): their
/// values are base64-benign-heavy and high-volume (Basic/Bearer auth, cookies, ETag
/// / conditional-GET validators) so a per-name exclusion beats the statistical
/// decode-then-match bet there. Case-insensitive (names are pre-lowercased). The
/// OVERLONG channel is NOT subject to this — it stays pipeline-wide.
fn header_base64_excluded(name: &str) -> bool {
    const EXCLUDED: &[&str] = &[
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "etag",
        "if-none-match",
        "if-match",
    ];
    EXCLUDED.contains(&name) || name.ends_with("-token")
}

/// Closed ALLOWLIST of header names whose VALUE the content-inspection modules scan
/// (P1-B). Unlike query/body, request headers are mostly NOT attacker payload carriers,
/// so we invert the policy: inspect ONLY the user-controlled forwarding headers
/// (`Referer`, `X-Forwarded-{For,Host,Proto}`) and custom `x-*` headers (gotestwaf
/// injects into `X-<random>`), and EXCLUDE everything else — even an `x-*` that is really
/// infra/secret (`*-token`, `proxy-*`) or negotiation/validators (`accept*`, `content-*`,
/// `etag`, `if-*`) or hop-by-hop. Names are pre-lowercased. The deny-list takes
/// precedence over the `x-*` allowance. (Distinct from [`header_base64_excluded`], which
/// is a deny-list for the separate base64-derive channel.)
pub fn header_content_inspectable(name: &str) -> bool {
    // Deny-list FIRST (overrides the x-* allowance).
    const DENY_EXACT: &[&str] = &[
        "authorization", "proxy-authorization", "cookie", "set-cookie",
        "user-agent", "host", "etag", "if-none-match", "if-match",
        // hop-by-hop (RFC 7230 §6.1) + framing controls
        "connection", "keep-alive", "transfer-encoding", "te", "trailer", "upgrade",
    ];
    if DENY_EXACT.contains(&name)
        || name.ends_with("-token")
        || name.starts_with("accept")
        || name.starts_with("content-")
        || name.starts_with("proxy-")
    {
        return false;
    }
    // Allow-list: forwarding headers + Referer + any custom x-*.
    matches!(name, "referer" | "x-forwarded-for" | "x-forwarded-host" | "x-forwarded-proto")
        || name.starts_with("x-")
}

/// Canonical inspectable strings of a parsed body (form values, JSON leaf values,
/// multipart name/filename/UTF-8 value) — the surface the base64-derive channel scans.
/// Mirrors detection's `body_str_values` but lives here so the normalizer can build
/// `derived_decoded` once (the prefilter + every module then read it).
fn body_canonical_strings(body: &waf_core::ParsedBody) -> Vec<String> {
    use waf_core::ParsedBody;
    match body {
        ParsedBody::FormUrlEncoded(p) => p.iter().map(|(_, v)| v.clone()).collect(),
        ParsedBody::JsonFlattened(p) => {
            p.iter().map(|(_, v)| url::canonicalize_value(v, false).0).collect()
        }
        ParsedBody::Multipart(fields) => {
            let mut out = Vec::with_capacity(fields.len() * 2);
            for f in fields {
                out.push(url::canonicalize_multipart_field(&f.name));
                if let Some(fname) = &f.filename {
                    out.push(url::canonicalize_multipart_field(fname));
                }
                if let Ok(s) = std::str::from_utf8(&f.data) {
                    out.push(url::canonicalize_multipart_field(s));
                }
            }
            out
        }
        ParsedBody::Raw(b) => {
            std::str::from_utf8(b).ok().map(|s| url::canonicalize_value(s, false).0).into_iter().collect()
        }
        ParsedBody::None => Vec::new(),
    }
}
