// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

//! Parse lexed [`DirectiveLine`](super::lexer::DirectiveLine)s into a [`ParsedRuleset`].
//!
//! Scope (v1 subset — see the B2 plan table). Supported directives: `SecRule`,
//! `SecDefaultAction`, `SecRuleRemoveById`. `SecAction` is configuration/setup (it sets
//! `TX` variables we do not model) and is ignored. `SecMarker`, `SecComponentSignature`,
//! `SecRuleUpdate*` and unknown directives are ignored (they cannot make us *miss* an
//! attack — at worst we run a rule the operator meant to skip, which is fail-closed).
//!
//! Anything a `SecRule` needs that the v1 subset cannot model (unsupported operator /
//! variable / transform, a response-phase rule, a stateful action like `setvar`/`ctl`,
//! a missing `id`) makes the WHOLE rule (and its whole chain) a [`SkippedRule`] with a
//! precise reason — never a silent partial evaluation (policy D3=A).

use waf_core::Severity;

use super::ast::{
    map_severity, CrsRule, MatchUnit, Operator, ParsedRuleset, SkippedRule, TargetKind,
    Transform, Variable,
};
use super::lexer::{lex, DirectiveLine};

/// Parse a whole `seclang` source into supported + skipped rules.
pub fn parse(input: &str) -> ParsedRuleset {
    let dirs = lex(input);
    let mut out = ParsedRuleset::default();
    let mut defaults = Defaults::default();
    let mut removed_ids: Vec<u64> = Vec::new();

    let mut i = 0usize;
    while i < dirs.len() {
        let name = dirs[i].tokens[0].to_ascii_lowercase();
        match name.as_str() {
            "secrule" => {
                // Collect the head plus any chained children (each a following `SecRule`).
                let mut links: Vec<(usize, Result<RuleParts, String>)> =
                    vec![(dirs[i].line_no, parse_secrule(&dirs[i]))];
                let mut chained = links[0].1.as_ref().map(|p| p.actions.chain).unwrap_or(false);
                while chained {
                    if i + 1 < dirs.len() && dirs[i + 1].tokens[0].eq_ignore_ascii_case("secrule") {
                        i += 1;
                        let child = parse_secrule(&dirs[i]);
                        chained = child.as_ref().map(|p| p.actions.chain).unwrap_or(false);
                        links.push((dirs[i].line_no, child));
                    } else {
                        // Dangling `chain` with no following SecRule — stop consuming.
                        break;
                    }
                }
                assemble(links, &defaults, &mut out);
            }
            "secdefaultaction" => defaults.update(&dirs[i]),
            "secruleremovebyid" => collect_removed_ids(&dirs[i], &mut removed_ids),
            // SecAction (config), SecMarker, SecComponentSignature, SecRuleUpdate*, unknown:
            // ignored. They are not detection rules in the v1 model.
            _ => {}
        }
        i += 1;
    }

    if !removed_ids.is_empty() {
        out.rules.retain(|r| !removed_ids.contains(&r.id));
    }
    out
}

// ── SecDefaultAction state ─────────────────────────────────────────────────────

#[derive(Default, Clone)]
struct Defaults {
    transforms: Vec<Transform>, // resolved (no `None` markers)
    severity: Option<Severity>,
    phase: Option<u8>,
}

impl Defaults {
    fn update(&mut self, d: &DirectiveLine) {
        // `SecDefaultAction "phase:2,t:none,t:lowercase,..."`
        let Some(action_str) = d.tokens.get(1) else { return };
        let a = parse_actions(action_str);
        // Defaults' transform pipeline is whatever the directive resolves to (its own
        // `t:none` resets from empty).
        self.transforms = resolve_transforms(&[], &a.transforms);
        if a.severity.is_some() {
            self.severity = a.severity;
        }
        if a.phase.is_some() {
            self.phase = a.phase;
        }
    }
}

// ── one SecRule's raw parts ─────────────────────────────────────────────────────

struct RuleParts {
    variables: Vec<Variable>,
    operator: Operator,
    negated: bool,
    actions: ActionParse,
}

struct ActionParse {
    id: Option<u64>,
    phase: Option<u8>,
    severity: Option<Severity>,
    transforms: Vec<Transform>, // raw order, may contain `Transform::None` reset markers
    chain: bool,
    msg: Option<String>,
    /// First stateful/unsupported action whose presence forces the rule to be skipped.
    blocking_unsupported: Option<String>,
}

/// Parse a `SecRule VARS OP [ACTIONS]` directive line into its raw parts.
fn parse_secrule(d: &DirectiveLine) -> Result<RuleParts, String> {
    if d.tokens.len() < 3 {
        return Err("malformed SecRule (expected VARIABLES OPERATOR [ACTIONS])".to_string());
    }
    let variables = parse_variables(&d.tokens[1]);
    let (negated, operator) = parse_operator(&d.tokens[2]);
    let actions = match d.tokens.get(3) {
        Some(s) => parse_actions(s),
        None => ActionParse {
            id: None,
            phase: None,
            severity: None,
            transforms: Vec::new(),
            chain: false,
            msg: None,
            blocking_unsupported: None,
        },
    };
    Ok(RuleParts { variables, operator, negated, actions })
}

/// Build a [`CrsRule`] (or a [`SkippedRule`]) from a head + chain children.
fn assemble(links: Vec<(usize, Result<RuleParts, String>)>, defaults: &Defaults, out: &mut ParsedRuleset) {
    let (head_line, head_res) = &links[0];
    let head_line = *head_line;

    // Head must parse and carry an id (ModSecurity requires it on the chain starter).
    let head = match head_res {
        Ok(p) => p,
        Err(reason) => {
            out.skipped.push(SkippedRule { id: None, line_no: head_line, reason: reason.clone() });
            return;
        }
    };
    let Some(id) = head.actions.id else {
        out.skipped.push(SkippedRule {
            id: None,
            line_no: head_line,
            reason: "SecRule has no id (cannot form a stable rule_id)".to_string(),
        });
        return;
    };

    // Response phases (3/4/5) inspect the response/log — out of the request-time v1 model.
    let phase = head.actions.phase.or(defaults.phase).unwrap_or(2);
    if phase >= 3 {
        out.skipped.push(SkippedRule {
            id: Some(id),
            line_no: head_line,
            reason: format!("response/logging phase {phase} not supported (request-time only)"),
        });
        return;
    }

    // Build each match unit (head uses the SecDefaultAction transform defaults; chain
    // children use only their own `t:` — SecDefaultAction does not apply to chained rules).
    let mut units: Vec<MatchUnit> = Vec::with_capacity(links.len());
    for (idx, (line_no, res)) in links.iter().enumerate() {
        let parts = match res {
            Ok(p) => p,
            Err(reason) => {
                out.skipped.push(SkippedRule { id: Some(id), line_no: *line_no, reason: reason.clone() });
                return;
            }
        };
        if let Some(act) = &parts.actions.blocking_unsupported {
            out.skipped.push(SkippedRule {
                id: Some(id),
                line_no: *line_no,
                reason: format!("unsupported action {act}"),
            });
            return;
        }
        let base = if idx == 0 { defaults.transforms.as_slice() } else { &[] };
        let transforms = resolve_transforms(base, &parts.actions.transforms);
        let unit = MatchUnit {
            variables: parts.variables.clone(),
            operator: parts.operator.clone(),
            negated: parts.negated,
            transforms,
        };
        if let Some(reason) = unit_unsupported(&unit) {
            out.skipped.push(SkippedRule { id: Some(id), line_no: *line_no, reason });
            return;
        }
        units.push(unit);
    }

    let severity = head.actions.severity.or(defaults.severity).unwrap_or(Severity::Warning);
    let head_unit = units.remove(0);
    out.rules.push(CrsRule {
        id,
        severity,
        head: head_unit,
        chain: units,
        msg: head.actions.msg.clone(),
        line_no: head_line,
    });
}

/// Why a built [`MatchUnit`] cannot be evaluated by the v1 subset (or `None` if it can).
fn unit_unsupported(u: &MatchUnit) -> Option<String> {
    if let Operator::Unsupported(name) = &u.operator {
        return Some(format!("unsupported operator @{name}"));
    }
    if u.variables.is_empty() {
        return Some("no variables".to_string());
    }
    for v in &u.variables {
        if let TargetKind::Unsupported(name) = &v.kind {
            return Some(format!("unsupported variable {name}"));
        }
        if v.count {
            return Some("count operator (&VAR) not supported".to_string());
        }
        if v.regex_selector {
            return Some("regex variable selector (:/…/) not supported".to_string());
        }
    }
    for t in &u.transforms {
        if let Transform::Unsupported(name) = t {
            return Some(format!("unsupported transform t:{name}"));
        }
    }
    None
}

// ── transforms ──────────────────────────────────────────────────────────────────

/// Resolve a final transform pipeline: start from `base` (the SecDefaultAction defaults),
/// then apply the rule's `t:` list in order, where `t:none` clears everything accumulated
/// so far (defaults included) and subsequent `t:` re-add. Faithful to ModSecurity (#3).
fn resolve_transforms(base: &[Transform], rule: &[Transform]) -> Vec<Transform> {
    let mut list = base.to_vec();
    for t in rule {
        if *t == Transform::None {
            list.clear();
        } else {
            list.push(t.clone());
        }
    }
    list
}

fn map_transform(name: &str) -> Transform {
    match name.trim().to_ascii_lowercase().as_str() {
        "none" => Transform::None,
        "lowercase" => Transform::Lowercase,
        "urldecode" => Transform::UrlDecode,
        "urldecodeuni" => Transform::UrlDecodeUni,
        "htmlentitydecode" => Transform::HtmlEntityDecode,
        "compresswhitespace" => Transform::CompressWhitespace,
        "removewhitespace" => Transform::RemoveWhitespace,
        "removenulls" => Transform::RemoveNulls,
        "normalizepath" | "normalisepath" => Transform::NormalizePath,
        "base64decode" | "base64decodeext" => Transform::Base64Decode,
        other => Transform::Unsupported(other.to_string()),
    }
}

// ── variables ───────────────────────────────────────────────────────────────────

fn parse_variables(tok: &str) -> Vec<Variable> {
    tok.split('|').filter(|s| !s.is_empty()).map(parse_variable).collect()
}

fn parse_variable(piece: &str) -> Variable {
    let mut s = piece.trim();
    let mut negated = false;
    let mut count = false;
    loop {
        if let Some(r) = s.strip_prefix('!') {
            negated = true;
            s = r;
        } else if let Some(r) = s.strip_prefix('&') {
            count = true;
            s = r;
        } else {
            break;
        }
    }
    let (name, selector, regex_selector) = match s.split_once(':') {
        Some((n, sel)) => {
            let rx = sel.starts_with('/');
            let selector = if rx || sel.is_empty() { None } else { Some(sel.to_string()) };
            (n, selector, rx)
        }
        None => (s, None, false),
    };
    Variable { kind: map_target(name), selector, negated, count, regex_selector }
}

fn map_target(name: &str) -> TargetKind {
    match name.trim().to_ascii_uppercase().as_str() {
        "ARGS" => TargetKind::Args,
        "ARGS_NAMES" => TargetKind::ArgsNames,
        "ARGS_GET" => TargetKind::ArgsGet,
        "ARGS_POST" => TargetKind::ArgsPost,
        "REQUEST_HEADERS" => TargetKind::RequestHeaders,
        "REQUEST_HEADERS_NAMES" => TargetKind::RequestHeadersNames,
        "REQUEST_COOKIES" => TargetKind::RequestCookies,
        "REQUEST_COOKIES_NAMES" => TargetKind::RequestCookiesNames,
        "REQUEST_URI" => TargetKind::RequestUri,
        "REQUEST_URI_RAW" => TargetKind::RequestUriRaw,
        "REQUEST_FILENAME" => TargetKind::RequestFilename,
        "QUERY_STRING" => TargetKind::QueryString,
        "REQUEST_METHOD" => TargetKind::RequestMethod,
        "REQUEST_PROTOCOL" => TargetKind::RequestProtocol,
        "REQUEST_LINE" => TargetKind::RequestLine,
        "REQUEST_BODY" => TargetKind::RequestBody,
        other => TargetKind::Unsupported(other.to_string()),
    }
}

// ── operator ────────────────────────────────────────────────────────────────────

fn parse_operator(tok: &str) -> (bool, Operator) {
    let mut s = tok.trim_start();
    let mut negated = false;
    if let Some(r) = s.strip_prefix('!') {
        negated = true;
        s = r.trim_start();
    }
    let Some(rest) = s.strip_prefix('@') else {
        // No explicit operator → ModSecurity defaults to `@rx` over the whole token.
        return (negated, Operator::Rx(s.to_string()));
    };
    // Split the operator name from its (verbatim, NOT trimmed) argument at the first space.
    let (op, arg) = match rest.find(char::is_whitespace) {
        Some(pos) => (&rest[..pos], &rest[pos + 1..]),
        None => (rest, ""),
    };
    let operator = match op.to_ascii_lowercase().as_str() {
        "rx" => Operator::Rx(arg.to_string()),
        "pm" => Operator::Pm(split_phrases(arg)),
        "pmf" | "pmfromfile" => Operator::PmFromFile(arg.trim().to_string()),
        "contains" => Operator::Contains(arg.to_string()),
        "beginswith" => Operator::BeginsWith(arg.to_string()),
        "endswith" => Operator::EndsWith(arg.to_string()),
        "within" => Operator::Within(arg.to_string()),
        "streq" => Operator::StrEq(arg.to_string()),
        other => Operator::Unsupported(other.to_string()),
    };
    (negated, operator)
}

fn split_phrases(arg: &str) -> Vec<String> {
    arg.split_whitespace().map(|s| s.to_string()).collect()
}

// ── actions ─────────────────────────────────────────────────────────────────────

fn parse_actions(s: &str) -> ActionParse {
    let mut out = ActionParse {
        id: None,
        phase: None,
        severity: None,
        transforms: Vec::new(),
        chain: false,
        msg: None,
        blocking_unsupported: None,
    };
    for item in split_actions(s) {
        let (name, value) = match item.split_once(':') {
            Some((n, v)) => (n.trim(), Some(unquote(v.trim()))),
            None => (item.trim(), None),
        };
        match name.to_ascii_lowercase().as_str() {
            "id" => out.id = value.as_deref().and_then(|v| v.parse().ok()),
            "phase" => out.phase = value.as_deref().and_then(parse_phase),
            "severity" => out.severity = value.as_deref().and_then(map_severity),
            "t" => {
                if let Some(v) = value {
                    out.transforms.push(map_transform(&v));
                }
            }
            "chain" => out.chain = true,
            "msg" => out.msg = value,
            // Disposition + metadata that do NOT change whether the rule matches → ignored.
            // (Per-rule immediate block/deny is folded into the cumulative anomaly score in
            // v1 — see the B2 plan, paletto #4.)
            "block" | "deny" | "drop" | "pass" | "allow" | "status" | "tag" | "rev" | "ver"
            | "accuracy" | "maturity" | "capture" | "log" | "nolog" | "auditlog"
            | "noauditlog" | "logdata" | "multimatch" => {}
            // Stateful / control actions we do not model: their presence changes behaviour,
            // so the rule is skipped rather than silently mis-evaluated.
            "setvar" | "ctl" | "skip" | "skipafter" | "expirevar" | "initcol" | "setsid"
            | "setuid" | "exec" | "deprecatevar" | "sanitisearg" | "sanitisematched"
            | "sanitisematchedbytes" => {
                if out.blocking_unsupported.is_none() {
                    out.blocking_unsupported = Some(name.to_string());
                }
            }
            // Unknown action → conservatively skip the rule (it might be state-changing).
            other if !other.is_empty() && out.blocking_unsupported.is_none() => {
                out.blocking_unsupported = Some(other.to_string());
            }
            _ => {}
        }
    }
    out
}

fn parse_phase(v: &str) -> Option<u8> {
    match v.trim().to_ascii_lowercase().as_str() {
        "request" => Some(2),
        "response" => Some(4),
        "logging" => Some(5),
        n => n.parse().ok(),
    }
}

/// Split an action string on commas that are NOT inside a single-quoted value
/// (`msg:'SQLi, attempt'` stays one item).
fn split_actions(s: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut cur = String::new();
    let mut in_q = false;
    for c in s.chars() {
        match c {
            '\'' => {
                in_q = !in_q;
                cur.push(c);
            }
            ',' if !in_q => {
                if !cur.trim().is_empty() {
                    parts.push(cur.trim().to_string());
                }
                cur.clear();
            }
            _ => cur.push(c),
        }
    }
    if !cur.trim().is_empty() {
        parts.push(cur.trim().to_string());
    }
    parts
}

/// Strip surrounding single quotes from an action value, if present.
fn unquote(v: &str) -> String {
    let v = v.trim();
    if v.len() >= 2 && v.starts_with('\'') && v.ends_with('\'') {
        v[1..v.len() - 1].to_string()
    } else {
        v.to_string()
    }
}

fn collect_removed_ids(d: &DirectiveLine, out: &mut Vec<u64>) {
    for tok in &d.tokens[1..] {
        if let Some((a, b)) = tok.split_once('-') {
            // Range `N-M`.
            if let (Ok(a), Ok(b)) = (a.trim().parse::<u64>(), b.trim().parse::<u64>()) {
                for id in a..=b {
                    out.push(id);
                }
            }
        } else if let Ok(id) = tok.trim().parse::<u64>() {
            out.push(id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_rx_rule() {
        let r = parse(r#"SecRule ARGS "@rx (?i)union\s+select" "id:1,phase:2,severity:CRITICAL,block,t:lowercase,t:urlDecode""#);
        assert_eq!(r.skipped.len(), 0);
        assert_eq!(r.rules.len(), 1);
        let rule = &r.rules[0];
        assert_eq!(rule.id, 1);
        assert_eq!(rule.severity, Severity::Critical);
        assert!(matches!(rule.head.operator, Operator::Rx(_)));
        assert_eq!(rule.head.transforms, vec![Transform::Lowercase, Transform::UrlDecode]);
        assert_eq!(rule.head.variables[0].kind, TargetKind::Args);
    }

    #[test]
    fn default_action_severity_and_transforms_inherited() {
        let src = r#"
SecDefaultAction "phase:2,t:none,t:lowercase,severity:WARNING"
SecRule ARGS "@rx foo" "id:2"
"#;
        let r = parse(src);
        assert_eq!(r.rules.len(), 1);
        assert_eq!(r.rules[0].severity, Severity::Warning);
        assert_eq!(r.rules[0].head.transforms, vec![Transform::Lowercase]);
    }

    #[test]
    fn t_none_resets_defaults() {
        let src = r#"
SecDefaultAction "phase:2,t:lowercase"
SecRule ARGS "@rx foo" "id:3,t:none,t:urlDecode"
"#;
        let r = parse(src);
        // t:none clears the inherited t:lowercase, leaving only t:urlDecode.
        assert_eq!(r.rules[0].head.transforms, vec![Transform::UrlDecode]);
    }

    #[test]
    fn unsupported_operator_skips_rule_with_reason() {
        let r = parse(r#"SecRule ARGS "@detectSQLi" "id:4,phase:2""#);
        assert_eq!(r.rules.len(), 0);
        assert_eq!(r.skipped.len(), 1);
        assert_eq!(r.skipped[0].id, Some(4));
        assert!(r.skipped[0].reason.contains("@detectsqli"));
    }

    #[test]
    fn unsupported_transform_skips_rule() {
        let r = parse(r#"SecRule ARGS "@rx x" "id:5,t:cssDecode""#);
        assert_eq!(r.rules.len(), 0);
        assert!(r.skipped[0].reason.contains("cssdecode"));
    }

    #[test]
    fn setvar_action_skips_rule() {
        let r = parse(r#"SecRule ARGS "@rx x" "id:6,phase:2,pass,setvar:tx.score=5""#);
        assert_eq!(r.rules.len(), 0);
        assert!(r.skipped[0].reason.contains("setvar"));
    }

    #[test]
    fn missing_id_skips() {
        let r = parse(r#"SecRule ARGS "@rx x" "phase:2,pass""#);
        assert_eq!(r.rules.len(), 0);
        assert!(r.skipped[0].reason.contains("no id"));
    }

    #[test]
    fn response_phase_skipped() {
        let r = parse(r#"SecRule RESPONSE_BODY "@rx x" "id:7,phase:4""#);
        assert_eq!(r.rules.len(), 0);
        // Either the phase or the RESPONSE_BODY target trips first; both are correct skips.
        assert!(r.skipped[0].reason.contains("phase") || r.skipped[0].reason.contains("RESPONSE_BODY"));
    }

    #[test]
    fn chain_all_links_supported() {
        let src = r#"
SecRule REQUEST_METHOD "@streq POST" "id:8,phase:2,chain,severity:ERROR"
    SecRule ARGS "@rx (?i)evil" "t:lowercase"
"#;
        let r = parse(src);
        assert_eq!(r.rules.len(), 1, "skipped: {:?}", r.skipped);
        assert_eq!(r.rules[0].chain.len(), 1);
        assert_eq!(r.rules[0].severity, Severity::Error);
    }

    #[test]
    fn chain_with_unsupported_child_skips_whole() {
        let src = r#"
SecRule REQUEST_METHOD "@streq POST" "id:9,phase:2,chain"
    SecRule XML "@detectXSS" "t:none"
"#;
        let r = parse(src);
        assert_eq!(r.rules.len(), 0);
        assert_eq!(r.skipped[0].id, Some(9));
    }

    #[test]
    fn remove_by_id_drops_rule() {
        let src = r#"
SecRule ARGS "@rx a" "id:100,phase:2"
SecRule ARGS "@rx b" "id:101,phase:2"
SecRuleRemoveById 100
"#;
        let r = parse(src);
        assert_eq!(r.rules.len(), 1);
        assert_eq!(r.rules[0].id, 101);
    }

    #[test]
    fn remove_by_id_range() {
        let src = r#"
SecRule ARGS "@rx a" "id:200,phase:2"
SecRule ARGS "@rx b" "id:205,phase:2"
SecRuleRemoveById 200-210
"#;
        let r = parse(src);
        assert_eq!(r.rules.len(), 0);
    }

    #[test]
    fn variable_selector_and_exclusion_parsed() {
        let r = parse(r#"SecRule REQUEST_HEADERS:User-Agent|!ARGS:csrf_token "@rx x" "id:11,phase:2""#);
        let v = &r.rules[0].head.variables;
        assert_eq!(v[0].kind, TargetKind::RequestHeaders);
        assert_eq!(v[0].selector.as_deref(), Some("User-Agent"));
        assert_eq!(v[1].kind, TargetKind::Args);
        assert!(v[1].negated);
        assert_eq!(v[1].selector.as_deref(), Some("csrf_token"));
    }

    #[test]
    fn count_variable_skips_rule() {
        let r = parse(r#"SecRule &ARGS "@rx x" "id:12,phase:2""#);
        assert_eq!(r.rules.len(), 0);
        assert!(r.skipped[0].reason.contains("count"));
    }

    #[test]
    fn default_operator_is_rx() {
        let r = parse(r#"SecRule ARGS "evil" "id:13,phase:2""#);
        assert!(matches!(r.rules[0].head.operator, Operator::Rx(ref p) if p == "evil"));
    }

    #[test]
    fn secaction_is_ignored_not_skipped() {
        let r = parse(r#"SecAction "id:900000,phase:1,nolog,pass,t:none,setvar:tx.crs_setup=1""#);
        assert_eq!(r.rules.len(), 0);
        assert_eq!(r.skipped.len(), 0);
    }
}
