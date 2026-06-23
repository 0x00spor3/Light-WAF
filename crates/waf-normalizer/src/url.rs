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
    if s.len() < len_min {
        return false;
    }
    let core = s.trim_end_matches('=');
    // base64 quanta encode to 2/3/4 chars per group → a core length of `%4 == 1` is
    // IMPOSSIBLE; everything else (0/2/3) is valid. We must NOT require `%4 == 0`: that
    // only holds for PADDED base64, but gotestwaf (and many real encoders) emit UNPADDED
    // base64 — `%4 ∈ {2,3}` — which the old gate silently rejected, so the decode-then-
    // match channel never saw the payload (10c REOPEN, pcap-confirmed: 72/106 wire values).
    !core.is_empty()
        && core.len() % 4 != 1
        && core.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'+' || c == b'/')
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

/// Named HTML entities decoded by the EVASION decoder (§6-D1). DELIBERATELY excludes the
/// structural/escaping entities `lt`/`gt`/`amp`/`quot`/`apos` — decoding those would
/// reconstruct `<script>` / `"` from benign HTML-escaped content (forums, code samples,
/// JSON-carrying-HTML) and FALSE-POSITIVE. The ones here resolve obfuscation that benign
/// callers never use (`confirm&lpar;1&rpar;`, `&equals;`).
const ENTITY_NAMED: &[(&str, char)] = &[
    ("lpar", '('), ("rpar", ')'), ("equals", '='), ("colon", ':'), ("sol", '/'),
    ("bsol", '\\'), ("period", '.'), ("comma", ','), ("excl", '!'), ("semi", ';'),
    ("quest", '?'), ("commat", '@'), ("dollar", '$'), ("percnt", '%'), ("plus", '+'),
    ("ast", '*'), ("midast", '*'), ("lbrace", '{'), ("rbrace", '}'), ("lcub", '{'),
    ("rcub", '}'), ("lsqb", '['), ("rsqb", ']'), ("grave", '`'), ("lowbar", '_'),
    ("verbar", '|'), ("vert", '|'), ("num", '#'), ("Tab", '\t'), ("NewLine", '\n'),
];

/// HTML-entity decode for EVASION only (§6-D1): named (table above) + numeric
/// (`&#NN;` / `&#xHH;`), but NEVER the 5 structural chars `< > & " '`. Returns `Some`
/// only when at least one entity was decoded (else the value is unchanged → no point
/// adding it to the derived channel). decode-then-match-then-discard: this output is an
/// inspection-only variant, the stored value is untouched. Linear single pass.
pub fn html_entity_decode_evasion(s: &str) -> Option<String> {
    if !s.contains('&') {
        return None;
    }
    let mut out = String::with_capacity(s.len());
    let mut changed = false;
    let mut rest = s;
    while let Some(amp) = rest.find('&') {
        out.push_str(&rest[..amp]);
        let after = &rest[amp + 1..];
        // entity body is up to the next ';' within a small window (cap 31 chars)
        let decoded = after.find(';').filter(|&p| p <= 31).and_then(|semi| {
            let ent = &after[..semi];
            let c = if let Some(num) = ent.strip_prefix('#') {
                let cp = match num.strip_prefix(['x', 'X']) {
                    Some(hex) => u32::from_str_radix(hex, 16).ok(),
                    None => num.parse::<u32>().ok(),
                };
                cp.and_then(char::from_u32)
            } else {
                ENTITY_NAMED.iter().find(|(n, _)| *n == ent).map(|(_, c)| *c)
            };
            c.filter(|c| !matches!(c, '<' | '>' | '&' | '"' | '\''))
                .map(|c| (c, semi))
        });
        match decoded {
            Some((c, semi)) => {
                out.push(c);
                changed = true;
                rest = &after[semi + 1..];
            }
            None => {
                out.push('&');
                rest = after;
            }
        }
    }
    out.push_str(rest);
    changed.then_some(out)
}

/// MID-TOKEN tag-strip (§6-D2): drop a `<…>` tag ONLY when immediately surrounded by word
/// chars on BOTH sides (`\w<…>\w`) — i.e. injected INSIDE an identifier to break a token
/// (`o<x>nfocus` → `onfocus`, `autof<x>ocus` → `autofocus`), the gotestwaf mutation-XSS
/// evasion. WRAPPING tags (`<code>onerror</code>`, HTML tables/`<b>`/`<a href>`) are left
/// INTACT, so benign HTML-bearing content gains NO spurious `onerror=` adjacency
/// (probe-measured: zero new FP). Returns `Some` only when a tag was dropped. The tag span
/// is capped at 24 chars (a real mutation tag is tiny — `<x>`, `<y>`).
pub fn strip_midtoken_tags(s: &str) -> Option<String> {
    if !s.contains('<') {
        return None;
    }
    let b = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut changed = false;
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'<' {
            if let Some(close) = s[i..].find('>').map(|p| i + p) {
                let before = out.chars().last().is_some_and(|c| c.is_alphanumeric() || c == '_');
                let after = b.get(close + 1).is_some_and(|&c| (c as char).is_alphanumeric() || c == b'_');
                if before && after && (close - i) <= 24 {
                    i = close + 1; // drop the mid-token tag, keep the surrounding word chars
                    changed = true;
                    continue;
                }
            }
        }
        let ch = s[i..].chars().next().unwrap();
        out.push(ch);
        i += ch.len_utf8();
    }
    changed.then_some(out)
}

/// MID-TOKEN control-character strip (§6-D2b): drop a run of C0 control bytes injected
/// INSIDE an identifier to break a keyword (`<<scr\0ipt>` → `<<script>`, the gotestwaf
/// NUL-split mutation). Like [`strip_midtoken_tags`], it fires ONLY when the control run
/// sits between word chars on BOTH sides — benign content never carries a NUL mid-word.
/// `\t`/`\n`/`\r` are EXCLUDED: those are structural whitespace handled elsewhere, and
/// collapsing intra-token WHITESPACE (`scr ipt`) is the high-FP D2b-2 variant, still
/// deferred. Returns `Some` only when a control run was dropped. Linear single pass.
pub fn strip_midtoken_controls(s: &str) -> Option<String> {
    let is_ctrl = |c: u8| c < 0x20 && c != b'\t' && c != b'\n' && c != b'\r';
    let b = s.as_bytes();
    if !b.iter().any(|&c| is_ctrl(c)) {
        return None;
    }
    let mut out = String::with_capacity(s.len());
    let mut changed = false;
    let mut i = 0;
    while i < b.len() {
        if is_ctrl(b[i]) {
            let mut j = i;
            while j < b.len() && is_ctrl(b[j]) {
                j += 1;
            }
            let before = out.chars().last().is_some_and(|c| c.is_alphanumeric() || c == '_');
            let after = b.get(j).is_some_and(|&c| (c as char).is_alphanumeric() || c == b'_');
            if before && after {
                i = j; // drop the mid-token control run, keep the surrounding word chars
                changed = true;
                continue;
            }
        }
        let ch = s[i..].chars().next().unwrap();
        out.push(ch);
        i += ch.len_utf8();
    }
    changed.then_some(out)
}

/// VBScript string-concat de-obfuscation (§6-D3): collapse the `"…&…"` joints VBScript
/// uses to split keywords across string literals — `"Ex"&"e"&"cute` → `"Execute`,
/// `M"&"i"&"d` → `Mid`, `c"&"h"&"r` → `chr` (gotestwaf rce-urlparam webshell). Matches a
/// close-quote, optional ws, `&`, optional ws, open-quote and drops all of it, joining the
/// adjacent literals. `&` is VBScript's concat operator (JS uses `+`), so `"x"&"y"` in a
/// request value is itself a strong VBScript tell → low FP, and decode-then-match-then-
/// discard means it only counts if it reconstructs an RCE keyword. Returns `Some` only when
/// a joint was removed. Linear single pass.
pub fn strip_vbscript_concat(s: &str) -> Option<String> {
    if !s.contains('&') {
        return None;
    }
    let b = s.as_bytes();
    let ws = |c: u8| c == b' ' || c == b'\t';
    let mut out = String::with_capacity(s.len());
    let mut changed = false;
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'"' {
            let mut j = i + 1;
            while j < b.len() && ws(b[j]) {
                j += 1;
            }
            if j < b.len() && b[j] == b'&' {
                let mut k = j + 1;
                while k < b.len() && ws(b[k]) {
                    k += 1;
                }
                if k < b.len() && b[k] == b'"' {
                    i = k + 1; // drop the `"…&…"` joint, fusing the two string literals
                    changed = true;
                    continue;
                }
            }
        }
        let ch = s[i..].chars().next().unwrap();
        out.push(ch);
        i += ch.len_utf8();
    }
    changed.then_some(out)
}

/// All derived inspection variants of one inspected value (§6): base64-decoded (10c) +
/// HTML-entity-decoded (evasion, §6-D1) + mid-token-tag-stripped (mutation, §6-D2) +
/// mid-token-control-stripped (§6-D2b). All are decode-then-match-then-discard. Single
/// entry the normalizer calls per inspected value.
///
/// COMPOSITION (10c reopen): the evasion may live INSIDE a base64 blob (Base64Flat —
/// gotestwaf wraps the whole mutation/entity payload in base64). The raw `value` is then
/// the opaque base64 alphabet (no `&`/`<`/control byte), so the entity/tag/control
/// transforms would no-op on it. Apply them over each base64-DECODED variant too, not
/// just the raw input — otherwise `<<scr\0ipt>` / `o<x>nfocus` / `confirm&lpar;` survive
/// the base64 unwrap un-reconstructed (pcap bypass-new.txt: D2a/D2b Base64Flat).
pub fn derive_variants(value: &str) -> Vec<String> {
    let mut out = base64_derived(value);
    // Compose the structural transforms over the base64-decoded variants.
    let mut composed = Vec::new();
    for d in &out {
        if let Some(ent) = html_entity_decode_evasion(d) {
            composed.push(ent);
        }
        if let Some(stripped) = strip_midtoken_tags(d) {
            composed.push(stripped);
        }
        if let Some(stripped) = strip_midtoken_controls(d) {
            composed.push(stripped);
        }
        if let Some(joined) = strip_vbscript_concat(d) {
            composed.push(joined);
        }
    }
    out.extend(composed);
    // Raw-surface transforms (URL/percent-decoded value, no base64 wrapper).
    if let Some(ent) = html_entity_decode_evasion(value) {
        out.extend(base64_derived(&ent));
        out.push(ent);
    }
    if let Some(stripped) = strip_midtoken_tags(value) {
        out.push(stripped);
    }
    if let Some(stripped) = strip_midtoken_controls(value) {
        out.push(stripped);
    }
    if let Some(joined) = strip_vbscript_concat(value) {
        out.push(joined);
    }
    out
}

/// Derived inspection variants of a single JSON STRING leaf (Fase 10c).
///
/// `serde_json::from_str` already unescapes JSON `\uXXXX`/`\n`/… so `raw` is the
/// unescaped leaf — but it is stored AND inspected raw: unlike form-urlencoded (decoded
/// at parse) and multipart (decoded in `body_str_values`), the JSON leaf never sees
/// `canonicalize_value`. So an encoded leaf (`%25C0%25AE…`, `%3CsvG…`) reaches the
/// modules still encoded → bypass (pcap 10c). This feeds the DECODED form to the derived
/// channel instead of mutating the stored leaf (decode-then-match-then-discard):
///   - percent + overlong fixed-point → the `canonical`, pushed ONLY when it differs
///     from `raw` (when unchanged, `body_str_values` already inspects the raw leaf, so
///     pushing would be redundant — `all_matches` dedups by rule anyway);
///   - base64 expansion of the canonical.
///
/// Both stages share the ONE [`PIPELINE_CAP`] budget — no new cap (same invariant as
/// the overlong/base64 channels). Recursion across nesting levels is automatic: the
/// caller iterates EVERY flattened leaf (`flatten_json` descends objects + arrays).
pub fn json_leaf_derived(raw: &str) -> Vec<String> {
    let mut budget = PIPELINE_CAP;
    let mut out = Vec::new();
    let (bytes, _) = percent_overlong_fixpoint(raw.as_bytes(), false, &mut budget);
    let canonical: String = String::from_utf8_lossy(&bytes).nfkc().collect();
    expand_base64(&canonical, &mut budget, &mut out);
    // §6-D1: a JSON leaf may carry HTML entities too (`{"q":"confirm&lpar;1&rpar;"}`).
    if let Some(ent) = html_entity_decode_evasion(&canonical) {
        out.push(ent);
    }
    if canonical != raw {
        out.push(canonical);
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

/// Parsed query result: `(params, double_encoding_detected, derived_decoded)`.
pub type ParsedQuery = (Vec<(String, String)>, bool, Vec<String>);

/// Parse a query string into decoded key-value pairs (`+` treated as space).
///
/// Values are fully canonicalized (percent + overlong fixpoint + NFKC). Also returns
/// the **base64-derived** variants of the values (10c, decode-then-match-then-discard).
/// Returns `(params, double_encoding_detected, derived_decoded)`.
pub fn parse_query(
    query: &str,
    limits: &LimitsConfig,
) -> Result<ParsedQuery, NormalizationError> {
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
        derived.extend(derive_variants(&dv));
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
