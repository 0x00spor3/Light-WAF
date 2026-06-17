pub mod body;
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
        let mut cookies = Vec::new();
        let mut cookie_double_enc = false;
        for (name, value) in &norm_headers {
            if name == "cookie" {
                for (k, v) in parse_cookies_limited(value, limits.max_cookies)? {
                    let (dk, de_k) = canonicalize_value(&k, false);
                    let (dv, de_v) = canonicalize_value(&v, false);
                    cookie_double_enc |= de_k || de_v;
                    cookies.push((dk, dv));
                }
            }
        }

        // ── 5. Normalize path ─────────────────────────────────────────────────
        let (norm_path, path_double_enc) = normalize_path(&ctx.raw_path);

        // ── 6. Parse query params ─────────────────────────────────────────────
        let (query_params, query_double_enc) = match &ctx.query {
            Some(q) => parse_query(q, limits)?,
            None => (Vec::new(), false),
        };

        // ── 7. Parse body ─────────────────────────────────────────────────────
        let content_type = norm_headers
            .iter()
            .find(|(k, _)| k == "content-type")
            .map(|(_, v)| v.as_str());

        let parsed_body = parse_body(content_type, &ctx.body, limits)?;

        // ── 8. Write results ──────────────────────────────────────────────────
        ctx.normalized.path = norm_path;
        ctx.normalized.query = ctx.query.clone();
        ctx.normalized.query_params = query_params;
        ctx.normalized.cookies = cookies;
        ctx.normalized.headers = norm_headers;
        ctx.normalized.body = parsed_body;
        ctx.normalized.double_encoding_detected =
            path_double_enc || query_double_enc || cookie_double_enc;

        Ok(())
    }
}
