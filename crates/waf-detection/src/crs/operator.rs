// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

//! Compiled ModSecurity operators (v1 subset). `@rx` compiles to a [`regex::Regex`] at
//! load time (never in `inspect`); the string operators keep their argument.

use regex::Regex;

use super::ast::Operator;

/// A compiled operator ready to test a (already transformed) value.
#[derive(Debug)]
pub enum Matcher {
    Rx(Regex),
    /// `@pm` — lowercased phrases; matches if the value contains ANY (case-insensitive).
    Pm(Vec<String>),
    Contains(String),
    BeginsWith(String),
    EndsWith(String),
    /// `@within` — the value must be a substring of the operator's parameter set.
    Within(String),
    StrEq(String),
}

impl Matcher {
    /// Does this operator match `value`? (`value` has already had the rule's `t:` applied.)
    pub fn matches(&self, value: &str) -> bool {
        match self {
            Matcher::Rx(re) => re.is_match(value),
            Matcher::Pm(phrases) => {
                let lower = value.to_ascii_lowercase();
                phrases.iter().any(|p| lower.contains(p.as_str()))
            }
            Matcher::Contains(s) => value.contains(s.as_str()),
            Matcher::BeginsWith(s) => value.starts_with(s.as_str()),
            Matcher::EndsWith(s) => value.ends_with(s.as_str()),
            Matcher::Within(set) => set.contains(value),
            Matcher::StrEq(s) => value == s,
        }
    }
}

/// Compile a parsed [`Operator`] into a [`Matcher`]. `Err` (invalid regex / an operator
/// that should have been resolved/skipped earlier) makes the loader skip the rule.
pub fn compile(op: &Operator) -> Result<Matcher, String> {
    match op {
        Operator::Rx(pattern) => Regex::new(pattern)
            .map(Matcher::Rx)
            .map_err(|e| format!("invalid @rx regex: {e}")),
        Operator::Pm(phrases) => {
            Ok(Matcher::Pm(phrases.iter().map(|p| p.to_ascii_lowercase()).collect()))
        }
        // `@pmf`/`@pmFromFile` would need per-file base-dir resolution of the phrase file;
        // not modelled in v1 → the rule is skipped (use inline `@pm` instead).
        Operator::PmFromFile(_) => {
            Err("@pmFromFile not supported in v1 (use inline @pm)".to_string())
        }
        Operator::Contains(s) => Ok(Matcher::Contains(s.clone())),
        Operator::BeginsWith(s) => Ok(Matcher::BeginsWith(s.clone())),
        Operator::EndsWith(s) => Ok(Matcher::EndsWith(s.clone())),
        Operator::Within(s) => Ok(Matcher::Within(s.clone())),
        Operator::StrEq(s) => Ok(Matcher::StrEq(s.clone())),
        Operator::Unsupported(name) => Err(format!("unsupported operator @{name}")),
    }
}

/// The raw `@rx` pattern, if this operator is a regex (used for fast-bucket RegexSets).
pub fn rx_pattern(op: &Operator) -> Option<&str> {
    match op {
        Operator::Rx(p) => Some(p.as_str()),
        _ => None,
    }
}
