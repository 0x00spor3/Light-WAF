// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

//! SSTI module — F-2 ERB/EJS/JSP arithmetic rule + its FP guards (2026-07-16).

use waf_core::{Bytes, Config, Decision, Normalized, RequestContext, Severity, WafModule};
use waf_detection::ssti::SstiModule;

fn base_ctx() -> RequestContext {
    RequestContext {
        client_ip: "127.0.0.1".parse().unwrap(),
        request_id: "t".to_string(),
        timestamp: std::time::SystemTime::now(),
        method: "GET".to_string(),
        path: "/".to_string(),
        raw_path: "/".to_string(),
        query: None,
        http_version: "HTTP/1.1".to_string(),
        headers: vec![],
        cookies: vec![],
        body: Bytes::new(),
        normalized: Normalized::default(),
        score: 0,
        score_contributions: vec![],
    }
}

fn with_query(name: &str, value: &str) -> RequestContext {
    let mut c = base_ctx();
    c.normalized.query_params = vec![(name.to_string(), value.to_string())];
    c
}

fn module() -> SstiModule {
    let mut m = SstiModule::new();
    m.init(&Config::default()); // PL defaults; ERB rule is paranoia 1
    m
}

fn severity_of(d: &Decision, rule_id: &str) -> Option<Severity> {
    match d {
        Decision::Scores(items) => items.iter().find(|i| i.rule_id == rule_id).map(|i| i.severity),
        _ => None,
    }
}

fn fires(d: &Decision, rule_id: &str) -> bool {
    severity_of(d, rule_id).is_some()
}

// ── positives ────────────────────────────────────────────────────────────────

#[test]
fn erb_expression_arithmetic_fires_critical() {
    let d = module().inspect(&with_query("q", "<%=7*7%>"));
    assert_eq!(severity_of(&d, "ssti-erb-jsp-arithmetic"), Some(Severity::Critical), "got: {d:?}");
}

#[test]
fn erb_scriptlet_with_spaces_fires() {
    let d = module().inspect(&with_query("q", "aaa<% 16 * 8787 %>bbb"));
    assert!(fires(&d, "ssti-erb-jsp-arithmetic"), "got: {d:?}");
}

#[test]
fn erb_trim_form_fires() {
    let d = module().inspect(&with_query("q", "<%- 2*2 -%>"));
    assert!(fires(&d, "ssti-erb-jsp-arithmetic"), "got: {d:?}");
}

// ── FP guards (must stay clean) ──────────────────────────────────────────────

#[test]
fn erb_comment_does_not_fire() {
    // `<%--` — a `-` follows `<%`, no adjacent digit-op-digit.
    let d = module().inspect(&with_query("tpl", "<%-- build 2024 rev 7 --%>"));
    assert!(!fires(&d, "ssti-erb-jsp-arithmetic"), "false positive on ERB comment: {d:?}");
}

#[test]
fn erb_template_var_does_not_fire() {
    let d = module().inspect(&with_query("tpl", "<%= user.name %>"));
    assert!(!fires(&d, "ssti-erb-jsp-arithmetic"), "false positive on ERB output tag: {d:?}");
}

#[test]
fn html_percent_prose_does_not_fire() {
    // A technical snippet that mentions percentages but is not a template delimiter.
    let d = module().inspect(&with_query("note", "discount was 7% then 7 off"));
    assert!(!fires(&d, "ssti-erb-jsp-arithmetic"), "false positive on prose: {d:?}");
}

// ── G-2: Jinja/Python object-access SSTI ─────────────────────────────────────────

#[test]
fn jinja_config_object_fires() {
    // Secret disclosure vector — was 200 (missed) before G-2.
    let d = module().inspect(&with_query("q", "{{config.items()}}"));
    assert_eq!(severity_of(&d, "ssti-jinja-object"), Some(Severity::Critical), "got: {d:?}");
}

#[test]
fn jinja_self_and_request_fire() {
    assert!(fires(&module().inspect(&with_query("q", "{{self}}")), "ssti-jinja-object"));
    assert!(fires(&module().inspect(&with_query("q", "{{request.application}}")), "ssti-jinja-object"));
}

#[test]
fn python_dunder_rce_chain_fires() {
    // The classic Jinja RCE gadget → must be Critical.
    assert!(fires(&module().inspect(&with_query("q", "{{''.__class__.__mro__[1].__subclasses__()}}")), "ssti-python-dunder"));
    assert!(fires(&module().inspect(&with_query("q", "{{cycler.__init__.__globals__.os.popen('id')}}")), "ssti-python-dunder"));
}

#[test]
fn jinja_statement_tag_with_arg_fires() {
    let d = module().inspect(&with_query("q", "{%for x in range(3)%}a{%endfor%}"));
    assert!(fires(&d, "ssti-template-statement"), "got: {d:?}");
}

// ── G-2 FP guards ────────────────────────────────────────────────────────────────

#[test]
fn jinja_benign_mustache_var_is_clean() {
    // A bare `{{ var }}` (Vue/mustache) has no context-object name → clean.
    for v in ["{{ user.name }}", "{{ product.price }}", "{{ items.length }}"] {
        let d = module().inspect(&with_query("tpl", v));
        assert!(matches!(d, Decision::Allow), "false positive on {v:?}: {d:?}");
    }
}

#[test]
fn jinja_statement_prose_is_clean() {
    // Technical prose naming a bare tag must NOT flag (the arg-required tightening).
    let d = module().inspect(&with_query("note", "use {% for %} … {% endfor %} to loop in Jinja"));
    assert!(matches!(d, Decision::Allow), "false positive on templating prose: {d:?}");
}

#[test]
fn dunder_js_proto_is_clean() {
    // `__proto__` (JS prototype) is NOT a Python introspection gadget → not flagged.
    let d = module().inspect(&with_query("q", "obj.__proto__.polluted"));
    assert!(!fires(&d, "ssti-python-dunder"), "false positive on __proto__: {d:?}");
}

// ── E-4: additional template-engine coverage (EXTREME follow-on) ─────────────────

#[test]
fn thymeleaf_selection_arithmetic_fires() {
    // Thymeleaf selection expression `*{7*7}` — new delimiter for the arithmetic rule.
    let d = module().inspect(&with_query("q", "*{7*7}"));
    assert!(fires(&d, "ssti-template-arithmetic"), "got: {d:?}");
}

#[test]
fn razor_arithmetic_fires() {
    // Razor `@(1+2)` explicit expression.
    let d = module().inspect(&with_query("q", "@(1+2)"));
    assert!(fires(&d, "ssti-template-arithmetic"), "got: {d:?}");
}

#[test]
fn jinja_print_paren_statement_fires() {
    // `{%print(7*7)%}` — `(` directly after the keyword (no whitespace) was missed.
    let d = module().inspect(&with_query("q", "{%print(7*7)%}"));
    assert!(fires(&d, "ssti-template-statement"), "got: {d:?}");
}

#[test]
fn smarty_php_tag_fires() {
    for v in ["{php}phpinfo();{/php}", "{php}echo 1;{/php}"] {
        let d = module().inspect(&with_query("q", v));
        assert!(fires(&d, "ssti-smarty-php"), "missed Smarty {v:?}: {d:?}");
    }
}

// ── E-4 FP guards ────────────────────────────────────────────────────────────────

#[test]
fn e4_engine_fp_guards_stay_clean() {
    for v in [
        "@(user)",             // Razor without arithmetic
        "@model.Name",         // Razor member access, no delimiter+digits
        "* { color: red }",    // CSS universal selector (space, no digit-op-digit)
        "*{margin:0}",         // CSS, no digit-op-digit adjacent
        "use {% print %} to output",  // bare statement tag naming (prose)
    ] {
        let d = module().inspect(&with_query("tpl", v));
        assert!(matches!(d, Decision::Allow), "E-4 false positive on {v:?}: {d:?}");
    }
}
