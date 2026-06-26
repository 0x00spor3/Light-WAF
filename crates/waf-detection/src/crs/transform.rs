// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

//! ModSecurity `t:` transformation pipeline (v1 subset). Each transform takes the output
//! of the previous one and runs on the **raw** target value (paletto #1) — NOT on the §6
//! canonical surface — so an imported CRS rule sees exactly what its author intended.
//!
//! Where a faithful primitive already exists in `waf-normalizer` we reuse it
//! (`percent_decode`, `base64_decode`); the rest are small, self-contained passes.

use waf_normalizer::url::{base64_decode, percent_decode};

use super::ast::Transform;

/// Apply the resolved transform pipeline, in order, to `input`.
pub fn apply(input: &str, pipeline: &[Transform]) -> String {
    let mut s = input.to_string();
    for t in pipeline {
        s = apply_one(&s, t);
    }
    s
}

fn apply_one(s: &str, t: &Transform) -> String {
    match t {
        // `None` is a reset marker consumed at parse time; if it ever reaches here it is
        // a no-op. `Unsupported` rules are skipped before compilation, so it is unreachable.
        Transform::None | Transform::Unsupported(_) => s.to_string(),
        // ModSecurity `t:lowercase` is a byte-wise ASCII tolower.
        Transform::Lowercase => s.to_ascii_lowercase(),
        // `t:urlDecode` / `urlDecodeUni`: single percent-decode (`+`→space, like ModSec).
        // `urlDecodeUni` additionally resolves `%uHHHH` unicode escapes.
        Transform::UrlDecode => percent_decode(s, true).0,
        Transform::UrlDecodeUni => percent_decode(&decode_u_escapes(s), true).0,
        Transform::HtmlEntityDecode => html_entity_decode(s),
        Transform::CompressWhitespace => compress_whitespace(s),
        Transform::RemoveWhitespace => s.chars().filter(|c| !c.is_whitespace()).collect(),
        Transform::RemoveNulls => s.replace('\0', ""),
        Transform::NormalizePath => normalize_path(s),
        Transform::Base64Decode => match base64_decode(s.trim()) {
            Some(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
            None => s.to_string(),
        },
    }
}

/// Collapse every run of whitespace into a single ASCII space (ModSec `compressWhitespace`).
fn compress_whitespace(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut in_ws = false;
    for c in s.chars() {
        if c.is_whitespace() {
            if !in_ws {
                out.push(' ');
                in_ws = true;
            }
        } else {
            out.push(c);
            in_ws = false;
        }
    }
    out
}

/// Resolve `%uHHHH` unicode escapes (used by `t:urlDecodeUni`). Non-escape text is kept;
/// a malformed `%u` is left verbatim.
fn decode_u_escapes(s: &str) -> String {
    let b = s.as_bytes();
    let n = b.len();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < n {
        if b[i] == b'%' && i + 6 <= n && (b[i + 1] == b'u' || b[i + 1] == b'U') {
            let hex = &s[i + 2..i + 6];
            if let Ok(cp) = u32::from_str_radix(hex, 16) {
                if let Some(ch) = char::from_u32(cp) {
                    out.push(ch);
                    i += 6;
                    continue;
                }
            }
        }
        // Copy one UTF-8 char.
        let ch = s[i..].chars().next().unwrap_or('\u{FFFD}');
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

/// Decode HTML entities (ModSec `htmlEntityDecode`). Covers all numeric (`&#NN;`, `&#xHH;`,
/// with or without the trailing `;`) plus the security-relevant named entities. The full
/// named-entity table is intentionally partial (documented v1 limit); numeric coverage —
/// the form attackers actually use to smuggle `<`/`>`/`'`/`"` — is complete.
fn html_entity_decode(s: &str) -> String {
    let b = s.as_bytes();
    let n = b.len();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < n {
        if b[i] == b'&' {
            if let Some((decoded, consumed)) = decode_entity(&s[i..]) {
                out.push(decoded);
                i += consumed;
                continue;
            }
        }
        let ch = s[i..].chars().next().unwrap_or('\u{FFFD}');
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

/// Try to decode a single entity at the start of `rest` (which begins with `&`).
/// Returns `(char, bytes_consumed)` or `None` if it is not a recognized entity.
fn decode_entity(rest: &str) -> Option<(char, usize)> {
    let bytes = rest.as_bytes();
    if bytes.len() < 3 {
        return None;
    }
    if bytes[1] == b'#' {
        // Numeric: &#NN; or &#xHH;
        let (radix, start) = if bytes.len() > 2 && (bytes[2] == b'x' || bytes[2] == b'X') {
            (16, 3)
        } else {
            (10, 2)
        };
        let mut j = start;
        while j < bytes.len() && j < start + 8 && is_radix_digit(bytes[j], radix) {
            j += 1;
        }
        if j == start {
            return None;
        }
        let cp = u32::from_str_radix(&rest[start..j], radix).ok()?;
        let ch = char::from_u32(cp)?;
        // Optional trailing `;` is consumed if present.
        let consumed = if j < bytes.len() && bytes[j] == b';' { j + 1 } else { j };
        return Some((ch, consumed));
    }
    // Named: scan letters up to `;` (or up to 10 chars).
    let mut j = 1;
    while j < bytes.len() && j < 11 && bytes[j].is_ascii_alphabetic() {
        j += 1;
    }
    let name = &rest[1..j];
    let ch = named_entity(name)?;
    let consumed = if j < bytes.len() && bytes[j] == b';' { j + 1 } else { j };
    Some((ch, consumed))
}

fn named_entity(name: &str) -> Option<char> {
    Some(match name {
        "lt" => '<',
        "gt" => '>',
        "amp" => '&',
        "quot" => '"',
        "apos" => '\'',
        "nbsp" => '\u{00A0}',
        "tab" => '\t',
        "newline" => '\n',
        "sol" => '/',
        "bsol" => '\\',
        "colon" => ':',
        "semi" => ';',
        "lpar" => '(',
        "rpar" => ')',
        "equals" => '=',
        _ => return None,
    })
}

fn is_radix_digit(b: u8, radix: u32) -> bool {
    if radix == 16 {
        b.is_ascii_hexdigit()
    } else {
        b.is_ascii_digit()
    }
}

/// Resolve `.` / `..` path segments and collapse repeated slashes (ModSec `normalizePath`).
/// Does NOT lowercase (unlike our §6 path normalization) — ModSecurity keeps case.
fn normalize_path(s: &str) -> String {
    let leading_slash = s.starts_with('/');
    let mut stack: Vec<&str> = Vec::new();
    for seg in s.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                stack.pop();
            }
            other => stack.push(other),
        }
    }
    let joined = stack.join("/");
    let trailing_slash = s.ends_with('/') && !joined.is_empty();
    let mut out = String::new();
    if leading_slash {
        out.push('/');
    }
    out.push_str(&joined);
    if trailing_slash {
        out.push('/');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(input: &str, pipeline: &[Transform]) -> String {
        apply(input, pipeline)
    }

    #[test]
    fn lowercase() {
        assert_eq!(t("UnIoN", &[Transform::Lowercase]), "union");
    }

    #[test]
    fn url_decode_single_pass() {
        // %75nion → union ; a DOUBLE-encoded %2575 must decode ONLY ONE level (paletto #1).
        assert_eq!(t("%75nion", &[Transform::UrlDecode]), "union");
        assert_eq!(t("%2575nion", &[Transform::UrlDecode]), "%75nion");
    }

    #[test]
    fn url_decode_plus_is_space() {
        assert_eq!(t("a+b", &[Transform::UrlDecode]), "a b");
    }

    #[test]
    fn url_decode_uni() {
        assert_eq!(t("%u0041BC", &[Transform::UrlDecodeUni]), "ABC");
    }

    #[test]
    fn html_entity_numeric_and_named() {
        assert_eq!(t("&#60;script&#62;", &[Transform::HtmlEntityDecode]), "<script>");
        assert_eq!(t("&#x3c;a&#x3e;", &[Transform::HtmlEntityDecode]), "<a>");
        assert_eq!(t("&lt;b&gt;", &[Transform::HtmlEntityDecode]), "<b>");
        // No trailing semicolon (browsers tolerate it; ModSec decodes it).
        assert_eq!(t("&#60script", &[Transform::HtmlEntityDecode]), "<script");
    }

    #[test]
    fn compress_and_remove_whitespace() {
        assert_eq!(t("a  \t b", &[Transform::CompressWhitespace]), "a b");
        assert_eq!(t("a  \t b", &[Transform::RemoveWhitespace]), "ab");
    }

    #[test]
    fn remove_nulls() {
        assert_eq!(t("a\0b", &[Transform::RemoveNulls]), "ab");
    }

    #[test]
    fn normalize_path_resolves_dotdot() {
        assert_eq!(t("/a/b/../c", &[Transform::NormalizePath]), "/a/c");
        assert_eq!(t("/a//./b/", &[Transform::NormalizePath]), "/a/b/");
        // Case preserved (unlike §6).
        assert_eq!(t("/Etc/Passwd", &[Transform::NormalizePath]), "/Etc/Passwd");
    }

    #[test]
    fn base64_decode() {
        // base64("union select") with our decoder.
        assert_eq!(t("dW5pb24gc2VsZWN0", &[Transform::Base64Decode]), "union select");
    }

    #[test]
    fn pipeline_order_matters() {
        // urlDecode THEN lowercase: %55nion → Union → union.
        let p = [Transform::UrlDecode, Transform::Lowercase];
        assert_eq!(t("%55nion", &p), "union");
    }
}
