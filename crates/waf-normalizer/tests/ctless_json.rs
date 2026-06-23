//! Regression for the §6 CT-less body-parsing hole (Fase 11-bis, fix "a"):
//! a body whose Content-Type does NOT declare JSON but which IS a JSON envelope must
//! be parsed like `application/json`, so the per-leaf canonicalization channel (§6)
//! and every content module see the leaves. Before the fix, dropping/forging the
//! Content-Type kept a `{"q":"<base64>"}` body as `ParsedBody::Raw` (whole-string
//! inspection only) → an injection encoded inside a JSON leaf bypassed all modules.

use waf_core::{Bytes, LimitsConfig, ParsedBody};
use waf_normalizer::body::parse_body;

fn limits() -> LimitsConfig {
    LimitsConfig::default()
}

fn parse(ct: Option<&str>, body: &str) -> ParsedBody {
    parse_body(ct, &Bytes::from(body.as_bytes().to_vec()), &limits()).unwrap()
}

fn leaves(p: &ParsedBody) -> Vec<(String, String)> {
    match p {
        ParsedBody::JsonFlattened(pairs) => pairs.clone(),
        other => panic!("expected JsonFlattened, got {other:?}"),
    }
}

#[test]
fn ctless_json_object_is_flattened() {
    // No Content-Type at all → still parsed as JSON (the gotestwaf graphql-post shape).
    let p = parse(None, r#"{"q":"' OR 1=1--"}"#);
    assert_eq!(leaves(&p), vec![("q".to_string(), "' OR 1=1--".to_string())]);
}

#[test]
fn ctless_json_array_is_flattened() {
    let p = parse(None, r#"["a","b"]"#);
    assert!(matches!(p, ParsedBody::JsonFlattened(_)));
}

#[test]
fn forged_content_type_json_is_flattened() {
    // An attacker setting text/plain to dodge JSON handling is defeated too.
    let p = parse(Some("text/plain"), r#"{"x":"payload"}"#);
    assert_eq!(leaves(&p), vec![("x".to_string(), "payload".to_string())]);
}

#[test]
fn leading_whitespace_before_envelope_is_tolerated() {
    let p = parse(None, "  \n\t{\"k\":\"v\"}");
    assert!(matches!(p, ParsedBody::JsonFlattened(_)));
}

#[test]
fn graphql_selection_set_is_not_json_stays_raw() {
    // An `application/graphql` document starts with `{` but is NOT valid JSON
    // (unquoted field names) → must remain Raw so the graphql raw-body transport and
    // the raw derived channel keep working.
    let p = parse(Some("application/graphql"), "{__typename}");
    assert!(matches!(p, ParsedBody::Raw(_)), "got {p:?}");
}

#[test]
fn ctless_invalid_jsonish_stays_raw() {
    // Looks like JSON (`{`) but isn't → inspected Raw, not silently dropped.
    let p = parse(None, "{not: valid, json}");
    assert!(matches!(p, ParsedBody::Raw(_)), "got {p:?}");
}

#[test]
fn ctless_bare_scalar_stays_raw() {
    // A bare JSON scalar is not an envelope → Raw (no behavioural change for it).
    assert!(matches!(parse(None, "12345"), ParsedBody::Raw(_)));
    assert!(matches!(parse(None, "plain text body"), ParsedBody::Raw(_)));
}

#[test]
fn empty_body_is_none() {
    assert!(matches!(parse(None, ""), ParsedBody::None));
}

#[test]
fn declared_json_still_flattened() {
    // Control: the declared-JSON path is unchanged.
    let p = parse(Some("application/json"), r#"{"a":"b"}"#);
    assert_eq!(leaves(&p), vec![("a".to_string(), "b".to_string())]);
}
