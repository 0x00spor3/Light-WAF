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
            Some(boundary) => parse_multipart(body, &boundary),
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

// ── form-urlencoded ───────────────────────────────────────────────────────────

fn parse_form_urlencoded(body: &Bytes, limits: &LimitsConfig) -> Result<ParsedBody, NormalizationError> {
    let text = std::str::from_utf8(body.as_ref()).unwrap_or("");
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

fn extract_boundary(ct: &str) -> Option<String> {
    for part in ct.split(';') {
        let part = part.trim();
        if part.to_lowercase().starts_with("boundary=") {
            return Some(part["boundary=".len()..].trim_matches('"').to_string());
        }
    }
    None
}

fn parse_multipart(body: &Bytes, boundary: &str) -> Result<ParsedBody, NormalizationError> {
    let data = body.as_ref();
    let delimiter = format!("--{boundary}");
    let inter_boundary = format!("\r\n--{boundary}");

    let mut fields = Vec::new();

    // Locate the opening boundary.
    let mut pos = match find_bytes(data, delimiter.as_bytes(), 0) {
        Some(p) => p + delimiter.len(),
        None => return Ok(ParsedBody::Multipart(fields)),
    };

    loop {
        // After boundary: '--' means end delimiter, '\r\n' means part follows.
        if pos + 1 < data.len() && data[pos] == b'-' && data[pos + 1] == b'-' {
            break;
        }
        if pos + 1 < data.len() && data[pos] == b'\r' && data[pos + 1] == b'\n' {
            pos += 2;
        } else {
            break;
        }

        let (headers, body_start) = match parse_part_headers(data, pos) {
            Some(x) => x,
            None => break,
        };
        pos = body_start;

        let body_end = match find_bytes(data, inter_boundary.as_bytes(), pos) {
            Some(p) => p,
            None => break,
        };

        let part_data = Bytes::copy_from_slice(&data[pos..body_end]);
        pos = body_end + inter_boundary.len();

        let mut name = String::new();
        let mut filename: Option<String> = None;
        let mut content_type: Option<String> = None;

        for (hname, hval) in &headers {
            match hname.to_lowercase().as_str() {
                "content-disposition" => {
                    // Attribute keys are case-insensitive (`name`/`Name`/`FILENAME`);
                    // gotestwaf sends `Content-disposition` + lowercase `name=`, but
                    // be robust to any casing. Split on the first `=` so a value that
                    // itself contains `=` is preserved.
                    for param in hval.split(';') {
                        let param = param.trim();
                        let Some(eq) = param.find('=') else { continue };
                        let key = param[..eq].trim().to_lowercase();
                        let value = param[eq + 1..].trim().trim_matches('"').to_string();
                        match key.as_str() {
                            "name" => name = value,
                            "filename" => filename = Some(value),
                            _ => {}
                        }
                    }
                }
                "content-type" => {
                    content_type = Some(hval.clone());
                }
                _ => {}
            }
        }

        if !name.is_empty() {
            fields.push(MultipartField { name, filename, content_type, data: part_data });
        }
    }

    Ok(ParsedBody::Multipart(fields))
}

fn parse_part_headers(data: &[u8], start: usize) -> Option<(Vec<(String, String)>, usize)> {
    let mut headers = Vec::new();
    let mut pos = start;

    loop {
        let line_end = find_crlf(data, pos)?;
        let line = &data[pos..line_end];

        if line.is_empty() {
            return Some((headers, line_end + 2));
        }

        if let Some(colon) = line.iter().position(|&b| b == b':') {
            let name = std::str::from_utf8(&line[..colon]).ok()?.trim().to_string();
            let value = std::str::from_utf8(&line[colon + 1..]).ok()?.trim().to_string();
            headers.push((name, value));
        }

        pos = line_end + 2;
    }
}

fn find_crlf(data: &[u8], from: usize) -> Option<usize> {
    let mut i = from;
    while i + 1 < data.len() {
        if data[i] == b'\r' && data[i + 1] == b'\n' {
            return Some(i);
        }
        i += 1;
    }
    None
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
