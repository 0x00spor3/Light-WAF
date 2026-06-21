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

// ── multipart deep normalization (B1-cont follow-up) ──────────────────────────

/// Byte-level percent-decode (single pass). Unlike [`percent_decode`] this keeps
/// the result as raw bytes — it does NOT run `from_utf8_lossy` — so invalid /
/// overlong sequences survive for [`collapse_overlong`] to handle. `+` is treated
/// literally (multipart values are not form-encoded).
fn percent_decode_bytes(input: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        if input[i] == b'%' && i + 2 < input.len() && is_hex(input[i + 1]) && is_hex(input[i + 2]) {
            out.push((hex_val(input[i + 1]) << 4) | hex_val(input[i + 2]));
            i += 3;
        } else {
            out.push(input[i]);
            i += 1;
        }
    }
    out
}

/// Collapse **overlong** 2-byte UTF-8 sequences that encode a 7-bit ASCII byte
/// back to that byte: `0xC0 0xAE` → `.`, `0xC0 0xAF` → `/`, `0xC1 …` → the
/// corresponding char. These are illegal UTF-8 (a `.`/`/` must be a single byte),
/// so a normal decode maps them to U+FFFD and the `../` / `/etc/passwd` signature
/// is lost — the classic overlong path-traversal evasion. Lead bytes `0xC0`/`0xC1`
/// can ONLY introduce an overlong (codepoint < 0x80), so mapping them is sound.
fn collapse_overlong(bytes: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if (b == 0xC0 || b == 0xC1) && i + 1 < bytes.len() && (0x80..=0xBF).contains(&bytes[i + 1]) {
            // cp = ((b & 0x1F) << 6) | (b2 & 0x3F); always < 0x80 for 0xC0/0xC1.
            out.push(((b & 0x1F) << 6) | (bytes[i + 1] & 0x3F));
            i += 2;
        } else {
            out.push(b);
            i += 1;
        }
    }
    out
}

/// Deep canonicalization for a multipart field (name / filename / value).
///
/// The multipart surface is a known traversal-smuggling vector (gotestwaf
/// `community-lfi-multipart`) that hides `../` in the part `name`, `filename` or
/// value, often **double-/overlong-encoded**. This applies a stronger decode than
/// the shared single+conditional pass before the traversal/LFI rules see it:
///   1. **recursive** percent-decode + overlong collapse until the byte stream is
///      stable (capped at `MAX_PASSES` to bound work and avoid loops): peels
///      `%25C0%25AE` → `%C0%AE` → `0xC0 0xAE` → `.`;
///   2. UTF-8 (lossy on anything still invalid) then **NFKC**, as elsewhere.
/// Separator normalization (`%2f`→`/`, `%5c`→`\`) falls out of step 1.
pub fn canonicalize_multipart_field(raw: &str) -> String {
    const MAX_PASSES: usize = 5;
    let mut bytes = raw.as_bytes().to_vec();
    for _ in 0..MAX_PASSES {
        let next = collapse_overlong(&percent_decode_bytes(&bytes));
        if next == bytes {
            break;
        }
        bytes = next;
    }
    String::from_utf8_lossy(&bytes).nfkc().collect()
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
