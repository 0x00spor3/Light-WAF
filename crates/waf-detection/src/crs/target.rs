// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

//! Extract the inspectable values a rule's variables point at, **from the raw request**
//! (paletto #1), applying ModSecurity's per-target *implicit* decoding — the single
//! url-decode ModSec does when populating `ARGS`, the cookie url-decode, etc. The rule's
//! own `t:` pipeline (see [`super::transform`]) then runs ON TOP of these baseline values.
//!
//! Crucially this NEVER reads `ctx.normalized.*` (the §6 canonical surface), which is
//! already recursively decoded — doing so would double-decode under a `t:urlDecode`.

use waf_core::RequestContext;
use waf_normalizer::url::percent_decode;

use super::ast::{TargetKind, Variable};

/// Collect the values to test for one match unit's variable list. Selectors (`:Name`)
/// filter to a named member; negated variables (`!VAR:name`) exclude that member.
pub fn collect_values(vars: &[Variable], ctx: &RequestContext) -> Vec<String> {
    // Exclusion keys: (collection, lowercased name) to drop from the positive set.
    let mut exclusions: Vec<(TargetKind, String)> = Vec::new();
    for v in vars.iter().filter(|v| v.negated) {
        if let Some(sel) = &v.selector {
            exclusions.push((v.kind.clone(), sel.to_ascii_lowercase()));
        }
    }
    let mut out = Vec::new();
    for v in vars.iter().filter(|v| !v.negated) {
        for (name, value) in entries(&v.kind, ctx) {
            if let Some(sel) = &v.selector {
                if !name.eq_ignore_ascii_case(sel) {
                    continue;
                }
            }
            if exclusions.iter().any(|(k, n)| *k == v.kind && name.eq_ignore_ascii_case(n)) {
                continue;
            }
            out.push(value);
        }
    }
    out
}

/// `(name, value)` entries for one target collection, with ModSec's implicit per-target
/// decoding baked into the value (NOT the rule's `t:` — those run afterwards).
fn entries(kind: &TargetKind, ctx: &RequestContext) -> Vec<(String, String)> {
    match kind {
        TargetKind::Args => {
            let mut e = query_args(ctx);
            e.extend(post_args(ctx));
            e
        }
        TargetKind::ArgsGet => query_args(ctx),
        TargetKind::ArgsPost => post_args(ctx),
        TargetKind::ArgsNames => {
            let mut e = query_args(ctx);
            e.extend(post_args(ctx));
            e.into_iter().map(|(n, _)| (n.clone(), n)).collect()
        }
        TargetKind::RequestHeaders => {
            // Header values are NOT url-decoded by ModSecurity (not url-encoded surface).
            ctx.headers.iter().map(|(n, v)| (n.clone(), v.clone())).collect()
        }
        TargetKind::RequestHeadersNames => {
            ctx.headers.iter().map(|(n, _)| (n.clone(), n.clone())).collect()
        }
        TargetKind::RequestCookies => ctx
            .cookies
            .iter()
            .map(|(n, v)| (n.clone(), percent_decode(v, false).0))
            .collect(),
        TargetKind::RequestCookiesNames => {
            ctx.cookies.iter().map(|(n, _)| (n.clone(), n.clone())).collect()
        }
        // REQUEST_URI / _RAW: the raw request URI (path + ?query), undecoded.
        TargetKind::RequestUri | TargetKind::RequestUriRaw => {
            vec![("REQUEST_URI".to_string(), raw_uri(ctx))]
        }
        // REQUEST_FILENAME: the path, url-decoded once, without the query.
        TargetKind::RequestFilename => {
            vec![("REQUEST_FILENAME".to_string(), percent_decode(&ctx.path, false).0)]
        }
        TargetKind::QueryString => {
            vec![("QUERY_STRING".to_string(), ctx.query.clone().unwrap_or_default())]
        }
        TargetKind::RequestMethod => vec![("REQUEST_METHOD".to_string(), ctx.method.clone())],
        TargetKind::RequestProtocol => {
            vec![("REQUEST_PROTOCOL".to_string(), ctx.http_version.clone())]
        }
        TargetKind::RequestLine => {
            let line = format!("{} {} {}", ctx.method, raw_uri(ctx), ctx.http_version);
            vec![("REQUEST_LINE".to_string(), line)]
        }
        TargetKind::RequestBody => {
            vec![("REQUEST_BODY".to_string(), String::from_utf8_lossy(&ctx.body).into_owned())]
        }
        // Unreachable: a rule with an Unsupported target is skipped before evaluation.
        TargetKind::Unsupported(_) => Vec::new(),
    }
}

/// Split a raw query string into url-decoded `(name, value)` args — ModSec's implicit
/// single decode (`+`→space, one `%XX` pass). Separator is `&` (v1; `;` not supported).
fn query_args(ctx: &RequestContext) -> Vec<(String, String)> {
    match &ctx.query {
        Some(q) => split_args(q),
        None => Vec::new(),
    }
}

/// Form-urlencoded POST args, parsed from the RAW body — only when the body IS a urlencoded
/// form. Multipart / JSON bodies are not surfaced as ARGS in v1 (documented limit); rules
/// that need them can target `REQUEST_BODY`.
fn post_args(ctx: &RequestContext) -> Vec<(String, String)> {
    if !is_form_urlencoded(ctx) {
        return Vec::new();
    }
    match std::str::from_utf8(&ctx.body) {
        Ok(s) => split_args(s),
        Err(_) => Vec::new(),
    }
}

fn split_args(s: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for pair in s.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k, v) = match pair.split_once('=') {
            Some((k, v)) => (k, v),
            None => (pair, ""),
        };
        out.push((percent_decode(k, true).0, percent_decode(v, true).0));
    }
    out
}

fn is_form_urlencoded(ctx: &RequestContext) -> bool {
    header(ctx, "content-type")
        .map(|ct| ct.to_ascii_lowercase().contains("application/x-www-form-urlencoded"))
        .unwrap_or(false)
}

fn raw_uri(ctx: &RequestContext) -> String {
    match &ctx.query {
        Some(q) => format!("{}?{}", ctx.path, q),
        None => ctx.path.clone(),
    }
}

fn header<'a>(ctx: &'a RequestContext, name: &str) -> Option<&'a str> {
    ctx.headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}
