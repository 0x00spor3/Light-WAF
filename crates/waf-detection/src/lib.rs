pub mod header_injection;
pub mod lfi_rfi;
pub mod path_traversal;
pub mod rate_limit;
pub mod rce;
pub mod sqli;
pub mod ssrf;
pub mod xss;

use waf_core::{ParsedBody, Severity};

/// Highest paranoia level any shipped rule currently declares. The config
/// contract allows up to `waf_core::MAX_PARANOIA_LEVEL` (4), but no rule uses 4
/// yet — so a higher `paranoia_level` activates no additional rules. The proxy
/// logs this at startup so PL4 is "empty but legal", never silently == PL3.
/// Bump this when the first higher-paranoia rule is added.
pub const HIGHEST_RULE_PARANOIA: u8 = 3;

// ── Rule ──────────────────────────────────────────────────────────────────────

/// A single detection rule: an id (used as `rule_id` in the emitted decision),
/// a regex pattern compiled into a `RegexSet` at module init time, a severity
/// class (mapped to points by the pipeline), and the minimum paranoia level at
/// which the rule becomes active.
pub struct Rule {
    pub id: &'static str,
    pub pattern: &'static str,
    pub severity: Severity,
    /// Minimum configured paranoia level (1..=4) for this rule to be compiled.
    pub paranoia: u8,
}

// ── shared helpers ────────────────────────────────────────────────────────────

/// Return the indices of every pattern in `rule_set` that matches at least one
/// of the given values, deduplicated and sorted. A rule that matches in several
/// values (query + body + cookie) is counted once, mirroring CRS semantics.
pub(crate) fn all_matches(
    rule_set: &regex::RegexSet,
    values: impl Iterator<Item = impl AsRef<str>>,
) -> Vec<usize> {
    let mut matched = vec![false; rule_set.len()];
    for v in values {
        for idx in rule_set.matches(v.as_ref()).into_iter() {
            matched[idx] = true;
        }
    }
    matched
        .iter()
        .enumerate()
        .filter_map(|(i, &hit)| if hit { Some(i) } else { None })
        .collect()
}

/// Collect all inspectable string values from a parsed body.
/// Binary multipart parts that are not valid UTF-8 are silently skipped.
pub(crate) fn body_str_values(body: &ParsedBody) -> Vec<String> {
    match body {
        ParsedBody::FormUrlEncoded(params) => {
            params.iter().map(|(_, v)| v.clone()).collect()
        }
        ParsedBody::JsonFlattened(pairs) => {
            pairs.iter().map(|(_, v)| v.clone()).collect()
        }
        ParsedBody::Multipart(fields) => {
            fields
                .iter()
                .filter_map(|f| std::str::from_utf8(&f.data).ok().map(str::to_owned))
                .collect()
        }
        ParsedBody::Raw(bytes) => {
            std::str::from_utf8(bytes).ok().map(str::to_owned).into_iter().collect()
        }
        ParsedBody::None => vec![],
    }
}
