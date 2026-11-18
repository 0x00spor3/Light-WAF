// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

use std::borrow::Cow;
use std::ops::Range;

use waf_core::{Bytes, LimitsConfig, MultipartField, ParsedBody};

use crate::url::canonicalize_value;
use crate::NormalizationError;

// ── public entry point ────────────────────────────────────────────────────────

pub fn parse_body(
    content_type: Option<&str>,
    body: &Bytes,
    limits: &LimitsConfig,
) -> Result<ParsedBody, NormalizationError> {
    let ct = content_type.unwrap_or("");
    let ct_lower = ct.trim().to_lowercase();

    if ct_lower == "application/x-www-form-urlencoded"
        || ct_lower.starts_with("application/x-www-form-urlencoded;")
    {
        parse_form_urlencoded(body, limits)
    } else if ct_lower.starts_with("multipart/") {
        // Boundary value is case-sensitive; extract from original ct.
        match extract_boundary(ct) {
            Some((boundary, ambiguous)) => parse_multipart(body, &boundary, ambiguous, limits),
            None => Ok(ParsedBody::Raw(body.clone())),
        }
    } else if ct_lower == "application/json" || ct_lower.starts_with("application/json;") {
        parse_json(body, limits)
    } else if body.is_empty() {
        Ok(ParsedBody::None)
    } else {
        // The Content-Type does NOT declare a structured format (absent, text/plain,
        // application/graphql, …). An attacker controls the Content-Type, so dropping
        // or forging it would keep a JSON envelope out of the per-leaf canonicalization
        // channel (§6 / Fase 10c): with a `Raw` body the derived channel only sees the
        // WHOLE-string canonicalize (no per-leaf base64 / JSON-`\u` decode) and
        // `body_str_values` inspects the raw string, so an injection encoded inside a
        // JSON leaf (`{"q":"<base64>"}`) bypasses every content module by simply omitting
        // `Content-Type: application/json`. So when the body actually LOOKS like JSON,
        // parse it like a declared JSON body. On a genuine parse failure (it only looked
        // like JSON — e.g. an `application/graphql` selection set `{__typename}`) fall
        // back to `Raw`; a structural/limit error (depth) is propagated, same fail-closed
        // policy as a declared JSON body.
        match sniff_json(body, limits)? {
            Some(parsed) => Ok(parsed),
            None => Ok(ParsedBody::Raw(body.clone())),
        }
    }
}

/// `from_utf8_lossy` with each run of invalid bytes as a single U+FFFD. One byte grows to
/// three as a replacement char and every module scans the result, so without this a body of
/// invalid bytes costs three times what its size suggests. No rule looks at how many there are.
pub fn lossy_text(bytes: &[u8]) -> Cow<'_, str> {
    let text = String::from_utf8_lossy(bytes);
    if !text.contains("\u{FFFD}\u{FFFD}") {
        return text;
    }
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if c != '\u{FFFD}' || !out.ends_with('\u{FFFD}') {
            out.push(c);
        }
    }
    Cow::Owned(out)
}

// ── raw bodies ────────────────────────────────────────────────────────────────

/// Above this share of non-text bytes, a body that does not declare a text type is binary.
/// Deliberately low: containers full of HTML or JS (`.pak`, resource files) sit at 6-30% and
/// would fire rules on content nobody sent as a request. Measured on 690 real binaries, 5%
/// keeps all of them passing at the default profile.
const BINARY_BYTE_SHARE: f64 = 0.05;

/// A short payload behind one invalid byte is a high share of very little, so this many
/// non-text bytes are always tolerated.
const BINARY_BYTE_FLOOR: usize = 8;

fn declares_text(content_type: Option<&str>) -> bool {
    let ct = content_type.unwrap_or("").trim().to_lowercase();
    ct.starts_with("text/") || ["json", "xml", "yaml", "graphql", "javascript"].iter().any(|t| ct.contains(t))
}

fn looks_binary(bytes: &[u8]) -> bool {
    let non_text = bytes
        .iter()
        .filter(|&&b| !matches!(b, b'\t' | b'\n' | b'\r' | 0x20..=0x7e))
        .count();
    non_text > BINARY_BYTE_FLOOR && non_text as f64 > bytes.len() as f64 * BINARY_BYTE_SHARE
}

/// The text of a `Raw` body that is not clean UTF-8, or `None` when it is clean (it is
/// scanned as it is) or really binary.
///
/// A stray invalid byte or NUL does not stop a body being text to the backend, so neither
/// may take it out of the scan. NUL is dropped rather than replaced, which is also what
/// turns ASCII in UTF-16 or UTF-32, a charset XML parsers honour, back into readable text.
///
/// The Content-Type decides in one direction only. A body declaring text is always read as
/// text, or padding it with invalid bytes would pass for binary. A body declaring anything
/// else is judged on its bytes, since the header is the client's word and a backend reading
/// the raw body ignores it: nearly all text is treated like the UTF-8 text it almost is. The
/// gap left: enough padding, under a non-text type, sent to a backend that reads raw bytes
/// regardless. Closing it means scanning real binary, and blocking real uploads.
pub fn raw_body_text(content_type: Option<&str>, body: &[u8]) -> Option<String> {
    if !body.contains(&0) && std::str::from_utf8(body).is_ok() {
        return None;
    }
    if !declares_text(content_type) && looks_binary(body) {
        return None;
    }
    let bytes: Vec<u8> = body.iter().copied().filter(|&b| b != 0).collect();
    Some(lossy_text(&bytes).into_owned())
}

// ── form-urlencoded ───────────────────────────────────────────────────────────

fn parse_form_urlencoded(body: &Bytes, limits: &LimitsConfig) -> Result<ParsedBody, NormalizationError> {
    // Lossy, never all-or-nothing: backends split on `&` and `=` whatever the bytes are, so
    // one invalid byte must not cost every other parameter its inspection.
    let text = lossy_text(body.as_ref());
    let mut params: Vec<(String, String)> = Vec::new();

    for pair in text.split('&') {
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
        let (dk, _) = canonicalize_value(k, true);
        let (dv, _) = canonicalize_value(v, true);
        params.push((dk, dv));
    }

    Ok(ParsedBody::FormUrlEncoded(params))
}

// ── multipart/form-data ───────────────────────────────────────────────────────

/// The text of a part value to inspect, or `None` when it is an opaque file upload.
///
/// Only a real file (a non-empty `filename`) may be skipped for being binary. Everything
/// else reaches the application as a form value, and backends accept invalid UTF-8 there,
/// so a single bad byte must not take the value out of the scan. Go hands a part with
/// `filename=""` to the app as a form value too, hence the non-empty check.
///
/// NUL is replaced on this path only: it is ordinary content in binary data, and
/// `pt-null-byte` would otherwise fire on the bytes of the blob. A valid UTF-8 value keeps
/// its NUL, that one is a `%00`-style injection.
pub fn multipart_field_text(field: &MultipartField) -> Option<Cow<'_, str>> {
    if let Ok(text) = std::str::from_utf8(&field.data) {
        return Some(Cow::Borrowed(text));
    }
    if field.filename.as_deref().is_some_and(|name| !name.is_empty()) {
        return None;
    }
    let bytes: Vec<u8> = field.data.iter().map(|&b| if b == 0 { 0xFF } else { b }).collect();
    Some(Cow::Owned(lossy_text(&bytes).into_owned()))
}

/// Split a `value; key=value; key="value"` header into its lowercased parameters. The
/// first segment (the media type or disposition) is not a parameter and is skipped.
/// A `;` inside quotes does not separate parameters. Anything parsers are known to read
/// differently (`\"`, an unbalanced quote, a segment without `=`, spaces around `=`) raises
/// `anomaly`.
fn split_params(header: &str, anomaly: &mut bool) -> Vec<(String, String)> {
    let mut segments = Vec::new();
    let (mut start, mut quoted, mut prev) = (0, false, 0u8);
    for (i, b) in header.bytes().enumerate() {
        match b {
            b'"' if quoted && prev == b'\\' => *anomaly = true,
            b'"' => quoted = !quoted,
            b';' if !quoted => {
                segments.push(&header[start..i]);
                start = i + 1;
            }
            _ => {}
        }
        prev = b;
    }
    segments.push(&header[start..]);
    if quoted {
        *anomaly = true;
    }

    let mut params = Vec::new();
    for segment in segments.into_iter().skip(1) {
        let segment = segment.trim();
        if segment.is_empty() {
            continue;
        }
        // Split on the first `=` so a value that itself contains `=` is preserved.
        match segment.split_once('=') {
            Some((key, value)) => {
                if key.ends_with(char::is_whitespace) || value.starts_with(char::is_whitespace) {
                    *anomaly = true;
                }
                params.push((key.trim().to_lowercase(), value.trim().trim_matches('"').to_string()));
            }
            None => *anomaly = true,
        }
    }
    params
}

/// The boundary of a multipart Content-Type, plus whether it is ambiguous. Backends differ
/// on which of several `boundary` parameters wins, so more than one is an anomaly.
fn extract_boundary(ct: &str) -> Option<(String, bool)> {
    let mut anomaly = false;
    let mut boundary = None;
    for (key, value) in split_params(ct, &mut anomaly) {
        if key == "boundary" {
            if boundary.is_some() {
                anomaly = true;
            } else {
                boundary = Some(value);
            }
        }
    }
    boundary.map(|b| (b, anomaly))
}

/// Parse a multipart body, keeping every part a backend could plausibly read.
///
/// There is no single multipart grammar in the wild: backends disagree on line endings,
/// padding, truncated bodies, quoting and more, and each disagreement is a way to show the
/// application a value the WAF never saw. So two layers, neither enough alone:
///
/// 1. The parser is tolerant and extracts what it can from malformed framing, and never
///    gives up silently.
/// 2. Any deviation from what browsers and mainstream HTTP clients emit raises `anomaly`,
///    and the whole body is appended as one more field (empty name, no filename), which
///    `multipart_field_text` then scans as text, see `fallback_text`. No parser can match
///    every backend, this is what covers the shapes nobody anticipated.
///
/// A well-formed body raises nothing, so it is parsed exactly as before. The extra field
/// costs one more pass over at most `max_body_size` bytes, the same as a `Raw` body.
fn parse_multipart(
    body: &Bytes,
    boundary: &str,
    mut anomaly: bool,
    limits: &LimitsConfig,
) -> Result<ParsedBody, NormalizationError> {
    let data = body.as_ref();
    let delimiter = format!("--{boundary}").into_bytes();

    let mut fields = Vec::new();
    let mut opaque = Vec::new();
    let mut nameless = 0;

    let mut current = find_delimiter(data, &delimiter, 0, &mut anomaly);
    if !matches!(current, Some(Delimiter { start: 0, .. })) {
        anomaly = true; // a preamble, or no delimiter at all
    }

    while let Some(delim) = current {
        if delim.closing {
            // Anything but trailing whitespace here is a part some parser may still read.
            if !data[delim.after..].iter().all(u8::is_ascii_whitespace) {
                anomaly = true;
            }
            break;
        }

        let Some((headers, body_start)) = parse_part_headers(data, delim.after, &mut anomaly) else {
            anomaly = true;
            break;
        };

        // No delimiter left: the part runs to the end of the body, as PHP reads it.
        let next = find_delimiter(data, &delimiter, body_start, &mut anomaly);
        let body_end = match &next {
            Some(next) => part_end(data, body_start, next.start, &mut anomaly),
            None => {
                anomaly = true;
                data.len()
            }
        };
        current = next;

        let content = &data[body_start..body_end];
        let field = build_field(&headers, content, &mut anomaly);
        // A binary upload stays out of the fallback too, unless the boundary shows up inside
        // it: that is how a part ends earlier for a backend than it does here, so what looks
        // like file bytes may be a field to that backend.
        if multipart_field_text(&field).is_none() && find_bytes(content, &delimiter, 0).is_none() {
            opaque.push(body_start..body_end);
        }
        // Nameless parts used to be dropped, and take the least bytes to forge. Past the
        // cap they are left to the whole-body field (being nameless raised `anomaly`).
        if field.name.is_empty() {
            nameless += 1;
            if nameless > limits.max_params {
                continue;
            }
        }
        fields.push(field);
    }

    if anomaly && !body.is_empty() {
        fields.push(MultipartField {
            name: String::new(),
            filename: None,
            content_type: None,
            data: fallback_text(data, &opaque),
        });
    }

    Ok(ParsedBody::Multipart(fields))
}

/// Stands in for what the fallback text must not read. Not whitespace, or rules written
/// with `\s*` would match across it (`name="f"` then a line starting with `--`), and not
/// valid UTF-8, so it ends up as U+FFFD like any other invalid byte.
const FALLBACK_SEPARATOR: u8 = 0xFF;

/// The body as the fallback scan reads it. Line breaks are the multipart framing itself
/// here, and a line break followed by `Content-Disposition:` is exactly what
/// `hdr-crlf-header-injection` looks for, so kept they would block every anomalous body.
/// NUL goes for the same reason, it is file content and not `pt-null-byte`. `opaque` are
/// binary uploads, which are not text in this path either. Values the parser did extract
/// keep these bytes and are still matched on them.
fn fallback_text(data: &[u8], opaque: &[Range<usize>]) -> Bytes {
    // A separator grows to three bytes as U+FFFD and every module scans this, so runs
    // collapse to one and opaque ranges are cut rather than overwritten.
    fn append(text: &mut Vec<u8>, bytes: &[u8]) {
        for &byte in bytes {
            let byte = if matches!(byte, b'\r' | b'\n' | 0) { FALLBACK_SEPARATOR } else { byte };
            if byte != FALLBACK_SEPARATOR || text.last() != Some(&FALLBACK_SEPARATOR) {
                text.push(byte);
            }
        }
    }

    let mut text = Vec::with_capacity(data.len());
    let mut pos = 0;
    for range in opaque {
        append(&mut text, &data[pos..range.start]);
        append(&mut text, &[FALLBACK_SEPARATOR]);
        pos = range.end;
    }
    append(&mut text, &data[pos..]);
    text.into()
}

/// One delimiter line: where it starts, where its content ends, and whether it closes.
struct Delimiter {
    start: usize,
    after: usize,
    closing: bool,
}

/// The next delimiter at or after `from`. It must start a line. Bare LF is accepted and
/// so is transport padding, both as anomalies. An occurrence that does not qualify is
/// data, but nothing legitimate looks like that (the boundary is chosen to be absent from
/// the content) and backends do not agree on it either, so it raises `anomaly`.
fn find_delimiter(data: &[u8], delimiter: &[u8], from: usize, anomaly: &mut bool) -> Option<Delimiter> {
    let mut search = from;
    while let Some(start) = find_bytes(data, delimiter, search) {
        search = start + 1;
        let end = start + delimiter.len();
        if start != 0 && data[start - 1] != b'\n' {
            *anomaly = true;
            continue;
        }
        if data[end..].starts_with(b"--") {
            return Some(Delimiter { start, after: end + 2, closing: true });
        }
        let padding = data[end..].iter().take_while(|b| matches!(b, b' ' | b'\t')).count();
        let line = &data[end + padding..];
        let newline = if line.starts_with(b"\r\n") {
            2
        } else if line.starts_with(b"\n") {
            1
        } else {
            *anomaly = true;
            continue;
        };
        if padding > 0 || newline == 1 {
            *anomaly = true;
        }
        return Some(Delimiter { start, after: end + padding + newline, closing: false });
    }
    None
}

/// Where a part's content ends, given the start of the delimiter after it.
fn part_end(data: &[u8], body_start: usize, delimiter: usize, anomaly: &mut bool) -> usize {
    if delimiter >= body_start + 2 && data[delimiter - 2] == b'\r' {
        return delimiter - 2;
    }
    *anomaly = true;
    delimiter.saturating_sub(1).max(body_start)
}

/// Build a field from a part's headers and raw content.
fn build_field(headers: &[(String, String)], content: &[u8], anomaly: &mut bool) -> MultipartField {
    let mut name = String::new();
    let mut filename: Option<String> = None;
    let mut content_type: Option<String> = None;
    let mut quoted_printable = false;
    let mut dispositions = 0;

    for (hname, hval) in headers {
        match hname.to_lowercase().as_str() {
            "content-disposition" => {
                dispositions += 1;
                let kind = hval.split(';').next().unwrap_or("");
                if !kind.trim().eq_ignore_ascii_case("form-data") {
                    *anomaly = true;
                }
                // Attribute keys are case-insensitive (`name`/`Name`/`FILENAME`);
                // gotestwaf sends `Content-disposition` + lowercase `name=`, but
                // be robust to any casing.
                let (mut names, mut filenames) = (0, 0);
                for (key, value) in split_params(hval, anomaly) {
                    match key.as_str() {
                        "name" => {
                            names += 1;
                            name = value;
                        }
                        "filename" => {
                            filenames += 1;
                            filename = Some(value);
                        }
                        // RFC 5987 `charset'lang'value`. The percent-encoding left in the
                        // value is resolved by the multipart canonicalization.
                        "filename*" => {
                            filenames += 1;
                            filename = Some(extended_param_value(&value).to_string());
                        }
                        _ => *anomaly = true,
                    }
                }
                if names != 1 || filenames > 1 {
                    *anomaly = true;
                }
            }
            "content-type" => {
                content_type = Some(hval.clone());
            }
            "content-transfer-encoding" => match hval.to_lowercase().as_str() {
                "7bit" | "8bit" | "binary" => {}
                "quoted-printable" => {
                    quoted_printable = true;
                    *anomaly = true;
                }
                _ => *anomaly = true,
            },
            _ => {}
        }
    }
    if dispositions != 1 || name.is_empty() {
        *anomaly = true;
    }

    let data = if quoted_printable {
        Bytes::from(decode_quoted_printable(content))
    } else {
        Bytes::copy_from_slice(content)
    };
    MultipartField { name, filename, content_type, data }
}

/// The value of an RFC 5987 extended parameter, without its `charset'lang'` prefix.
fn extended_param_value(value: &str) -> &str {
    value.splitn(3, '\'').nth(2).unwrap_or(value)
}

/// Decode quoted-printable: `=XX` escapes and `=` soft line breaks. Anything else is kept
/// as it is. Go decodes this for the application.
fn decode_quoted_printable(data: &[u8]) -> Vec<u8> {
    let hex = |b: u8| (b as char).to_digit(16).map(|d| d as u8);
    let mut out = Vec::with_capacity(data.len());
    let mut i = 0;
    while i < data.len() {
        if data[i] == b'=' {
            let rest = &data[i + 1..];
            if rest.starts_with(b"\r\n") {
                i += 3;
                continue;
            }
            if rest.starts_with(b"\n") {
                i += 2;
                continue;
            }
            if let [hi, lo, ..] = rest {
                if let (Some(hi), Some(lo)) = (hex(*hi), hex(*lo)) {
                    out.push((hi << 4) | lo);
                    i += 3;
                    continue;
                }
            }
        }
        out.push(data[i]);
        i += 1;
    }
    out
}

/// Read a part's header block. Returns the headers and the offset of the content, or
/// `None` when the block never ends. Bare LF, invalid UTF-8, folding and lines without a
/// colon are all read, and all raise `anomaly`.
fn parse_part_headers(
    data: &[u8],
    start: usize,
    anomaly: &mut bool,
) -> Option<(Vec<(String, String)>, usize)> {
    let mut headers: Vec<(String, String)> = Vec::new();
    let mut pos = start;

    loop {
        let (line_end, next) = find_line_end(data, pos)?;
        if next - line_end == 1 {
            *anomaly = true;
        }
        let line = &data[pos..line_end];
        pos = next;

        if line.is_empty() {
            return Some((headers, pos));
        }
        if std::str::from_utf8(line).is_err() {
            *anomaly = true;
        }
        let text = String::from_utf8_lossy(line);

        if line[0] == b' ' || line[0] == b'\t' {
            *anomaly = true;
            if let Some((_, value)) = headers.last_mut() {
                value.push(' ');
                value.push_str(text.trim());
            }
            continue;
        }
        match text.split_once(':') {
            Some((name, value)) => headers.push((name.trim().to_string(), value.trim().to_string())),
            None => *anomaly = true,
        }
    }
}

/// The next line ending at or after `from`: `(end of line content, start of next line)`.
fn find_line_end(data: &[u8], from: usize) -> Option<(usize, usize)> {
    let newline = from + data[from..].iter().position(|&b| b == b'\n')?;
    if newline > from && data[newline - 1] == b'\r' {
        Some((newline - 1, newline + 1))
    } else {
        Some((newline, newline + 1))
    }
}

fn find_bytes(haystack: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    let limit = haystack.len() - needle.len() + 1;
    for i in from..limit {
        if &haystack[i..i + needle.len()] == needle {
            return Some(i);
        }
    }
    None
}

// ── JSON ──────────────────────────────────────────────────────────────────────

/// Flatten an already-parsed JSON value to `(dot-path, string)` pairs, depth-limited.
///
/// Public test/fuzz seam (Fase 8, DEC 2 #5): lets the depth-limited RECURSION be
/// exercised directly on a `serde_json::Value`, bypassing serde's own parse-depth
/// cap (~128). The JSON *parsing* is serde_json's job and already robust; this is
/// our recursion. In production the value always comes from `serde_json::from_str`,
/// so the input depth is bounded before this even runs.
pub fn flatten_value(
    value: &serde_json::Value,
    limits: &LimitsConfig,
) -> Result<Vec<(String, String)>, NormalizationError> {
    let mut out = Vec::new();
    flatten_json(value, "", &mut out, 1, limits.max_json_depth)?;
    Ok(out)
}

/// Best-effort JSON parse for a body whose Content-Type does NOT declare JSON. Returns
/// `Ok(Some(JsonFlattened))` when the body is a JSON object/array envelope, `Ok(None)`
/// when it is not JSON (caller inspects it `Raw`), and propagates a depth/limit error
/// (fail-closed, like a declared JSON body). Only object/array shapes (`{`/`[`) are
/// treated as JSON — a bare scalar (`123`, `"x"`, `true`) stays `Raw` — so this never
/// reinterprets a non-envelope body. See the `parse_body` final-else rationale (§6).
fn sniff_json(body: &Bytes, limits: &LimitsConfig) -> Result<Option<ParsedBody>, NormalizationError> {
    let Ok(text) = std::str::from_utf8(body.as_ref()) else { return Ok(None) };
    let trimmed = text.trim_start();
    if !(trimmed.starts_with('{') || trimmed.starts_with('[')) {
        return Ok(None);
    }
    let Ok(value) = serde_json::from_str::<serde_json::Value>(trimmed) else {
        return Ok(None); // looked like JSON but isn't → inspect raw
    };
    let mut pairs = Vec::new();
    flatten_json(&value, "", &mut pairs, 1, limits.max_json_depth)?;
    Ok(Some(ParsedBody::JsonFlattened(pairs)))
}

fn parse_json(body: &Bytes, limits: &LimitsConfig) -> Result<ParsedBody, NormalizationError> {
    let text = std::str::from_utf8(body.as_ref())
        .map_err(|e| NormalizationError::JsonParseError(e.to_string()))?;

    let value: serde_json::Value = serde_json::from_str(text)
        .map_err(|e| NormalizationError::JsonParseError(e.to_string()))?;

    let mut pairs = Vec::new();
    flatten_json(&value, "", &mut pairs, 1, limits.max_json_depth)?;

    Ok(ParsedBody::JsonFlattened(pairs))
}

/// Depth-limited recursive JSON flattening to (dot-path, string-value) pairs.
///
/// Depth is counted for Object/Array nodes only; leaf primitives don't add depth.
/// The check fires when an Object or Array is entered at depth > max_depth.
fn flatten_json(
    value: &serde_json::Value,
    prefix: &str,
    out: &mut Vec<(String, String)>,
    depth: usize,
    max_depth: usize,
) -> Result<(), NormalizationError> {
    match value {
        serde_json::Value::Object(map) => {
            if depth > max_depth {
                return Err(NormalizationError::JsonDepthExceeded { limit: max_depth });
            }
            for (k, v) in map {
                let key = if prefix.is_empty() { k.clone() } else { format!("{prefix}.{k}") };
                flatten_json(v, &key, out, depth + 1, max_depth)?;
            }
        }
        serde_json::Value::Array(arr) => {
            if depth > max_depth {
                return Err(NormalizationError::JsonDepthExceeded { limit: max_depth });
            }
            for (i, v) in arr.iter().enumerate() {
                let key = if prefix.is_empty() { format!("{i}") } else { format!("{prefix}.{i}") };
                flatten_json(v, &key, out, depth + 1, max_depth)?;
            }
        }
        serde_json::Value::String(s) => out.push((prefix.to_string(), s.clone())),
        serde_json::Value::Null => out.push((prefix.to_string(), "null".to_string())),
        other => out.push((prefix.to_string(), other.to_string())),
    }
    Ok(())
}
