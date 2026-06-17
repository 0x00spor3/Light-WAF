use unicode_normalization::UnicodeNormalization;

use waf_core::LimitsConfig;

use crate::NormalizationError;

// ── helpers ───────────────────────────────────────────────────────────────────

fn is_hex(b: u8) -> bool {
    b.is_ascii_hexdigit()
}

fn hex_val(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _ => 0,
    }
}

fn still_percent_encoded(s: &str) -> bool {
    let b = s.as_bytes();
    let mut i = 0;
    while i + 2 < b.len() {
        if b[i] == b'%' && is_hex(b[i + 1]) && is_hex(b[i + 2]) {
            return true;
        }
        i += 1;
    }
    false
}

// ── public API ────────────────────────────────────────────────────────────────

/// Percent-decode a string (single pass).
///
/// Returns `(decoded, double_encoding_detected)`.
/// `double_encoding_detected` is true when the decoded output still contains
/// `%XX` sequences, meaning the input was double-encoded.
/// If `plus_as_space` is true, `'+'` is decoded as `' '` (query-string mode).
pub fn percent_decode(input: &str, plus_as_space: bool) -> (String, bool) {
    let b = input.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
    let mut i = 0;

    while i < b.len() {
        if b[i] == b'+' && plus_as_space {
            out.push(b' ');
            i += 1;
        } else if b[i] == b'%' && i + 2 < b.len() && is_hex(b[i + 1]) && is_hex(b[i + 2]) {
            out.push((hex_val(b[i + 1]) << 4) | hex_val(b[i + 2]));
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }

    let decoded = String::from_utf8_lossy(&out).into_owned();
    let double_enc = still_percent_encoded(&decoded);
    (decoded, double_enc)
}

/// Canonicalize a single field value exactly as query/body params are:
/// one percent-decode pass, then a **second pass only when double-encoding is
/// detected** (the Fase 2 anti-double-encoding defense), then NFKC
/// normalization. This is the single source of truth for value canonicalization
/// shared by query, body and cookies.
///
/// `plus_as_space` follows the form-encoding convention: `true` for query/body,
/// `false` for cookies (RFC 6265 treats `+` as a literal, not a space).
///
/// Returns `(canonical, double_encoding_detected)`.
pub fn canonicalize_value(raw: &str, plus_as_space: bool) -> (String, bool) {
    let (decoded, double_enc) = percent_decode(raw, plus_as_space);
    // Second decode resolves double-encoded content to its canonical form.
    let decoded = if double_enc {
        percent_decode(&decoded, false).0
    } else {
        decoded
    };
    // NFKC catches fullwidth / compatibility character evasion.
    let canonical: String = decoded.nfkc().collect();
    (canonical, double_enc)
}

/// Normalize a URL path.
///
/// Steps:
/// 1. Percent-decode (detecting double-encoding).
/// 2. If double-encoded, decode the result a second time.
/// 3. NFKC Unicode normalization (fullwidth → ASCII, ligatures → components).
/// 4. Strip null bytes.
/// 5. Lowercase.
/// 6. Resolve `.` / `..` segments and collapse consecutive slashes.
///
/// Returns `(normalized_path, double_encoding_detected)`.
pub fn normalize_path(raw: &str) -> (String, bool) {
    let (decoded, double_enc) = percent_decode(raw, false);

    let working = if double_enc {
        let (second, _) = percent_decode(&decoded, false);
        second
    } else {
        decoded
    };

    let nfkc: String = working.nfkc().collect();
    let no_nulls: String = nfkc.chars().filter(|&c| c != '\0').collect();
    let lower = no_nulls.to_lowercase();
    let resolved = resolve_path(&lower);

    (resolved, double_enc)
}

fn resolve_path(path: &str) -> String {
    let mut segments: Vec<&str> = Vec::new();

    for seg in path.split('/') {
        match seg {
            "" | "." => {}
            ".." => { segments.pop(); }
            other => segments.push(other),
        }
    }

    let mut out = String::with_capacity(path.len().max(1));
    for seg in &segments {
        out.push('/');
        out.push_str(seg);
    }
    if out.is_empty() {
        out.push('/');
    }
    out
}

/// Parse a query string into decoded key-value pairs (`+` treated as space).
///
/// Values are fully canonicalized: percent-decoded (with double-encoding
/// resolved), then NFKC-normalized so detection modules see canonical form.
/// Returns `(params, double_encoding_detected)`.
pub fn parse_query(
    query: &str,
    limits: &LimitsConfig,
) -> Result<(Vec<(String, String)>, bool), NormalizationError> {
    let mut params = Vec::new();
    let mut double_enc = false;

    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        if params.len() >= limits.max_params {
            return Err(NormalizationError::TooManyParams { limit: limits.max_params });
        }
        let (k, v) = match pair.find('=') {
            Some(pos) => (&pair[..pos], &pair[pos + 1..]),
            None => (pair, ""),
        };
        let (dk, de_k) = canonicalize_value(k, true);
        let (dv, de_v) = canonicalize_value(v, true);
        if de_k || de_v {
            double_enc = true;
        }
        params.push((dk, dv));
    }

    Ok((params, double_enc))
}

/// Parse a Cookie header value into name-value pairs, enforcing `max_cookies`.
pub fn parse_cookies_limited(
    cookie_header: &str,
    max_cookies: usize,
) -> Result<Vec<(String, String)>, NormalizationError> {
    let mut cookies = Vec::new();

    for pair in cookie_header.split(';') {
        let pair = pair.trim();
        if pair.is_empty() {
            continue;
        }
        if cookies.len() >= max_cookies {
            return Err(NormalizationError::TooManyCookies { limit: max_cookies });
        }
        let (k, v) = match pair.find('=') {
            Some(pos) => (pair[..pos].trim(), pair[pos + 1..].trim()),
            None => (pair, ""),
        };
        cookies.push((k.to_string(), v.to_string()));
    }

    Ok(cookies)
}
