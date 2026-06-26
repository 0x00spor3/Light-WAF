// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

//! AST produced by [`super::parse`] from the lexed directive lines. A [`CrsRule`] is the
//! owned, runtime-loaded analogue of the static [`crate::Rule`] tables — but richer,
//! because it carries the ModSecurity variable/operator/transform structure. Anything the
//! v1 subset does not model becomes an [`Unsupported`](Operator::Unsupported) /
//! [`TargetKind::Unsupported`] / [`Transform::Unsupported`] leaf, so the parser can SKIP the
//! whole rule with a precise reason instead of silently mis-evaluating it (policy D3=A).

use waf_core::Severity;

/// One ModSecurity transformation (`t:` action). Applied, in order, to the **raw** target
/// value before the operator runs (faithful to ModSecurity — see the module docs, paletto #1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Transform {
    None,
    Lowercase,
    UrlDecode,
    UrlDecodeUni,
    HtmlEntityDecode,
    CompressWhitespace,
    RemoveWhitespace,
    RemoveNulls,
    NormalizePath,
    Base64Decode,
    /// A transform outside the v1 subset (e.g. `cssDecode`, `jsDecode`, `sqlHexDecode`):
    /// its presence makes the rule Unsupported, because skipping a declared decode would
    /// change what the pattern sees.
    Unsupported(String),
}

/// One ModSecurity operator. The string argument is kept raw at parse time; `@rx` is
/// compiled to a [`regex::Regex`] later (in the loader/`init`), never in `inspect`.
#[derive(Debug, Clone)]
pub enum Operator {
    /// `@rx <pattern>` — the pattern is compiled later.
    Rx(String),
    /// `@pm <phrase1> <phrase2> …` — case-insensitive multi-phrase match (any phrase).
    Pm(Vec<String>),
    /// `@pmf <path>` / `@pmFromFile <path>` — phrases from a file, resolved by the loader
    /// (file I/O is not done at parse time). Becomes [`Operator::Pm`] once read.
    PmFromFile(String),
    /// `@contains <s>` — target contains `s`.
    Contains(String),
    /// `@beginsWith <s>`.
    BeginsWith(String),
    /// `@endsWith <s>`.
    EndsWith(String),
    /// `@within <set>` — target value is a substring of `set`.
    Within(String),
    /// `@streq <s>` — exact string equality.
    StrEq(String),
    /// An operator outside the v1 subset (`@detectSQLi`, `@ipMatch`, `@eq`, …) → rule Skipped.
    Unsupported(String),
}

/// The collection a [`Variable`] points at, mapped to a slice of the request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetKind {
    Args,
    ArgsNames,
    ArgsGet,
    ArgsPost,
    RequestHeaders,
    RequestHeadersNames,
    RequestCookies,
    RequestCookiesNames,
    RequestUri,
    RequestUriRaw,
    RequestFilename,
    QueryString,
    RequestMethod,
    RequestProtocol,
    RequestLine,
    RequestBody,
    /// A target outside the v1 subset (`XML`, `JSON`, `FILES`, `TX:*`, `RESPONSE_*`, …)
    /// → rule Skipped.
    Unsupported(String),
}

/// One parsed variable token (`ARGS`, `REQUEST_HEADERS:User-Agent`, `!ARGS:csrf`, `&ARGS`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Variable {
    pub kind: TargetKind,
    /// `:Name` selector — exact, case-insensitive name match within the collection.
    pub selector: Option<String>,
    /// Leading `!` → this is an EXCLUSION (remove the named member from the set).
    pub negated: bool,
    /// Leading `&` → count operator. Not modelled in v1 → makes the rule Unsupported.
    pub count: bool,
    /// A regex selector (`:/re/`) — not modelled in v1 → makes the rule Unsupported.
    pub regex_selector: bool,
}

/// One link of a rule: its variables, the (possibly negated) operator and the transform
/// pipeline that runs before it. A bare rule has one link (the head); a `chain` rule has
/// the head plus one link per chained child — ALL must match.
#[derive(Debug, Clone)]
pub struct MatchUnit {
    pub variables: Vec<Variable>,
    pub operator: Operator,
    /// Leading `!` on the operator string (`"!@rx ^$"`).
    pub negated: bool,
    /// Resolved transform pipeline (SecDefaultAction defaults + the link's own `t:`,
    /// with `t:none` resetting — see paletto #3).
    pub transforms: Vec<Transform>,
}

/// A fully parsed, supported rule ready to be compiled and evaluated.
#[derive(Debug, Clone)]
pub struct CrsRule {
    /// ModSecurity numeric `id`. Emitted as `rule_id = "crs-<id>"`.
    pub id: u64,
    /// Resolved severity (rule → SecDefaultAction → `Warning` fallback).
    pub severity: Severity,
    /// Head match unit.
    pub head: MatchUnit,
    /// Chain children (all must match for the rule to fire). Empty for a non-chained rule.
    pub chain: Vec<MatchUnit>,
    /// `msg:` text, for logging.
    pub msg: Option<String>,
    /// 1-based source line where the rule started.
    pub line_no: usize,
}

/// A rule that could not be loaded into the v1 subset. Counted and surfaced at boot
/// (policy D3=A) so the operator sees the exact coverage gap — never a silent drop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkippedRule {
    pub id: Option<u64>,
    pub line_no: usize,
    pub reason: String,
}

/// Outcome of parsing one `seclang` source: the supported rules plus the skipped ones.
#[derive(Debug, Default)]
pub struct ParsedRuleset {
    pub rules: Vec<CrsRule>,
    pub skipped: Vec<SkippedRule>,
}

/// Map a CRS/syslog severity word to our [`Severity`] classes. CRS uses
/// CRITICAL/ERROR/WARNING/NOTICE; the rarer syslog words collapse to the nearest class.
pub fn map_severity(word: &str) -> Option<Severity> {
    match word.trim().to_ascii_uppercase().as_str() {
        "EMERGENCY" | "ALERT" | "CRITICAL" | "0" | "1" | "2" => Some(Severity::Critical),
        "ERROR" | "3" => Some(Severity::Error),
        "WARNING" | "4" => Some(Severity::Warning),
        "NOTICE" | "INFO" | "DEBUG" | "5" | "6" | "7" => Some(Severity::Notice),
        _ => None,
    }
}
