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

/// Canonicalize a single field value: recursive percent-decode + **overlong-UTF8
/// collapse** to a fixed point (Fase 10c — overlong is now folded into the canonical
/// surface PIPELINE-WIDE, not scoped to multipart), then NFKC normalization. The
/// single source of truth for value canonicalization shared by query, body, cookies
/// and multipart. Overlong collapse is a *canonical* transform (the same value, a
/// legal re-encoding decoded) — distinct from the *derived* base64 channel below.
///
/// `plus_as_space` follows the form-encoding convention: `true` for query/body,
/// `false` for cookies (RFC 6265 treats `+` as a literal, not a space).
///
/// Returns `(canonical, double_encoding_detected)`.
pub fn canonicalize_value(raw: &str, plus_as_space: bool) -> (String, bool) {
    let mut budget = PIPELINE_CAP;
    let (bytes, passes) = percent_overlong_fixpoint(raw.as_bytes(), plus_as_space, &mut budget);
    let canonical: String = String::from_utf8_lossy(&bytes).nfkc().collect();
    (canonical, passes >= 2)
}

// ── §6 decode pipeline (Fase 10c) ─────────────────────────────────────────────
//
// TWO stages with ONE shared budget (`PIPELINE_CAP`):
//   - **overlong** (this is a CANONICAL transform): folded into the value above and
//     into `normalize_path` — applies pipeline-wide, no per-name exclusion;
//   - **base64** (a DERIVED channel): `derived_decoded` variants, decode-then-match-
//     then-discard, gated by `is_base64_candidate` + a per-NAME structural exclusion
//     on the header surface (Authorization/Cookie/ETag/…). See `expand_base64`.

/// Shared fixed-point decode budget across overlong + base64 (10c). One constant,
/// not two: an attacker chaining encodings cannot exceed it.
pub const PIPELINE_CAP: usize = 5;

/// Minimum base64 length to even attempt a decode. A COST gate, not a security gate
/// (the security gate is decode-then-match): probe-measured floor = 12, the length
/// of the shortest tracked attack (`base64("\r\nQUIT\r\n")`). Below 12 only adds work.
pub const BASE64_MIN_LEN: usize = 12;

/// Byte-level percent-decode (single pass). Unlike [`percent_decode`] this keeps the
/// result as raw bytes — no `from_utf8_lossy` — so overlong sequences survive for
/// [`collapse_overlong`]. `+`→space only when `plus_as_space` (form-encoding).
fn percent_decode_bytes(input: &[u8], plus_as_space: bool) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        if input[i] == b'+' && plus_as_space {
            out.push(b' ');
            i += 1;
        } else if input[i] == b'%' && i + 2 < input.len() && is_hex(input[i + 1]) && is_hex(input[i + 2]) {
            out.push((hex_val(input[i + 1]) << 4) | hex_val(input[i + 2]));
            i += 3;
        } else {
            out.push(input[i]);
            i += 1;
        }
    }
    out
}

/// Recursive percent-decode + overlong-collapse to a fixed point, consuming the
/// shared `budget`. `+`→space only on the FIRST pass (form-encoding; a literal `+`
/// in decoded content must not keep collapsing). Returns `(bytes, passes_applied)`.
fn percent_overlong_fixpoint(raw: &[u8], plus_as_space: bool, budget: &mut usize) -> (Vec<u8>, usize) {
    let mut bytes = raw.to_vec();
    let mut passes = 0;
    while *budget > 0 {
        let next = collapse_overlong(&percent_decode_bytes(&bytes, plus_as_space && passes == 0));
        if next == bytes {
            break;
        }
        bytes = next;
        passes += 1;
        *budget -= 1;
    }
    (bytes, passes)
}

/// Collapse overlong UTF-8 to ASCII and return a lossy string. Pub for §6 docs /
/// tests; the pipeline uses the byte-level [`collapse_overlong`] inside the fixpoint.
pub fn decode_overlong_utf8(input: &str) -> String {
    String::from_utf8_lossy(&collapse_overlong(input.as_bytes())).into_owned()
}

/// Base64 CANDIDACY (cost gate): strict alphabet `[A-Za-z0-9+/]` + `=` padding,
/// length a multiple of 4, and `>= len_min`. NOT a security gate — a benign token
/// that passes still cannot cause an FP because the decoded value only contributes
/// if it matches a module rule (decode-then-match-then-discard). Probe-verified
/// `benign_FP=[]` at every threshold.
pub fn is_base64_candidate(s: &str, len_min: usize) -> bool {
    if s.len() < len_min || s.len() % 4 != 0 {
        return false;
    }
    let core = s.trim_end_matches('=');
    !core.is_empty() && core.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'+' || c == b'/')
}

/// Hand-rolled standard base64 decode (alphabet `+/`, `=` padding). Returns `None`
/// on any non-alphabet byte. No new dependency (mirrors the hand-rolled percent /
/// overlong decoders); property-tested in the differential suite.
pub fn base64_decode(s: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let core = s.trim_end_matches('=');
    let mut out: Vec<u8> = Vec::with_capacity(core.len() * 3 / 4);
    let (mut buf, mut bits) = (0u32, 0u32);
    for &c in core.as_bytes() {
        buf = (buf << 6) | val(c)? as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    Some(out)
}

/// A decoded blob is worth inspecting only if it is mostly text — a random
/// token/hash decodes to high-entropy bytes (no module signature), so we discard it
/// before it even reaches the rules. ≥90% printable ASCII (CR/LF/TAB allowed).
fn mostly_printable(b: &[u8]) -> bool {
    if b.is_empty() {
        return false;
    }
    let p = b
        .iter()
        .filter(|&&c| matches!(c, b'\r' | b'\n' | b'\t') || (0x20..=0x7e).contains(&c))
        .count();
    p * 100 / b.len() >= 90
}

/// Base64-DERIVED variants of `value`, sharing `budget` with the overlong stage.
/// If `value` is a confident base64 candidate that decodes to mostly-printable text,
/// canonicalize the decode (so a base64 wrapping a percent/overlong payload still
/// resolves) and push it; recurse for nested base64. Each derived string is
/// inspection-only ("discard if it matches nothing"). Caller pre-applies the header
/// per-name exclusion (this fn is alphabet-only and surface-agnostic).
pub fn expand_base64(value: &str, budget: &mut usize, out: &mut Vec<String>) {
    if *budget == 0 || !is_base64_candidate(value, BASE64_MIN_LEN) {
        return;
    }
    let Some(decoded) = base64_decode(value) else { return };
    if !mostly_printable(&decoded) {
        return;
    }
    *budget -= 1;
    // The decode may itself carry percent/overlong encodings → canonicalize (shared
    // budget), then recurse for base64-of-base64.
    let (bytes, _) = percent_overlong_fixpoint(&decoded, false, budget);
    let canon: String = String::from_utf8_lossy(&bytes).nfkc().collect();
    expand_base64(&canon, budget, out);
    out.push(canon);
}

/// Collect base64-derived variants from `value` with a FRESH shared budget. The
/// single entry the normalizer calls per inspected field value.
pub fn base64_derived(value: &str) -> Vec<String> {
    let mut out = Vec::new();
    expand_base64(value, &mut PIPELINE_CAP.clone(), &mut out);
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

/// Canonicalize a multipart field (name / filename / value). Since 10c folded the
/// recursive percent + overlong decode into [`canonicalize_value`] PIPELINE-WIDE,
/// this is just that canonical transform (multipart `+` is literal). Kept as a named
/// entry for the multipart call sites (10b-cont). Base64-derived variants from
/// multipart values are collected separately by the normalizer (`base64_derived`).
pub fn canonicalize_multipart_field(raw: &str) -> String {
    canonicalize_value(raw, false).0
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
    // 10c: recursive percent + overlong fixpoint (shared cap), then NFKC / strip
    // NUL / lowercase / resolve. Overlong now collapses on the path too (`%C0%AE`→`.`).
    let mut budget = PIPELINE_CAP;
    let (bytes, passes) = percent_overlong_fixpoint(raw.as_bytes(), false, &mut budget);
    let nfkc: String = String::from_utf8_lossy(&bytes).nfkc().collect();
    let no_nulls: String = nfkc.chars().filter(|&c| c != '\0').collect();
    let lower = no_nulls.to_lowercase();
    let resolved = resolve_path(&lower);

    (resolved, passes >= 2)
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
/// Values are fully canonicalized (percent + overlong fixpoint + NFKC). Also returns
/// the **base64-derived** variants of the values (10c, decode-then-match-then-discard).
/// Returns `(params, double_encoding_detected, derived_decoded)`.
pub fn parse_query(
    query: &str,
    limits: &LimitsConfig,
) -> Result<(Vec<(String, String)>, bool, Vec<String>), NormalizationError> {
    let mut params = Vec::new();
    let mut double_enc = false;
    let mut derived = Vec::new();

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
        // Base64-derived from the canonical VALUE only (param names aren't attacker
        // payload carriers; keys stay out, like multipart field names).
        derived.extend(base64_derived(&dv));
        params.push((dk, dv));
    }

    Ok((params, double_enc, derived))
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
