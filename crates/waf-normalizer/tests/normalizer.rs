// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

use waf_core::{Bytes, LimitsConfig, Normalized, ParsedBody, RequestContext};
use waf_normalizer::{url, NormalizationError, Normalizer};

// ── helpers ───────────────────────────────────────────────────────────────────

fn norm() -> Normalizer {
    Normalizer::new(&LimitsConfig::default())
}

fn norm_with(limits: LimitsConfig) -> Normalizer {
    Normalizer::new(&limits)
}

fn ctx(raw_path: &str) -> RequestContext {
    RequestContext {
        client_ip: "127.0.0.1".parse().unwrap(),
        request_id: "t".to_string(),
        timestamp: std::time::SystemTime::now(),
        method: "GET".to_string(),
        path: raw_path.to_string(),
        raw_path: raw_path.to_string(),
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

fn ctx_query(raw_path: &str, query: &str) -> RequestContext {
    let mut c = ctx(raw_path);
    c.query = Some(query.to_string());
    c
}

fn ctx_body(content_type: &str, body: &[u8]) -> RequestContext {
    let mut c = ctx("/");
    c.headers = vec![("content-type".to_string(), content_type.to_string())];
    c.body = Bytes::from(body.to_vec());
    c
}

/// Normalize a context with default limits and return a reference to ctx.normalized.
fn run(c: &mut RequestContext) -> &Normalized {
    norm().normalize(c).expect("normalization failed");
    &c.normalized
}

// ── URL / percent-decode ──────────────────────────────────────────────────────

#[test]
fn single_url_encode_is_decoded() {
    let (decoded, double_enc) = url::percent_decode("%41%42%43", false);
    assert_eq!(decoded, "ABC");
    assert!(!double_enc);
}

#[test]
fn double_url_encode_is_detected() {
    // %2541: %25 → '%', then '4','1' → still %41 in the output → flag raised
    let (decoded, double_enc) = url::percent_decode("%2541", false);
    assert_eq!(decoded, "%41");
    assert!(double_enc);
}

#[test]
fn percent_decode_handles_multibyte_utf8() {
    // é = UTF-8 0xC3 0xA9
    let (decoded, double_enc) = url::percent_decode("%C3%A9", false);
    assert_eq!(decoded, "é");
    assert!(!double_enc);
}

#[test]
fn plus_decoded_as_space_when_requested() {
    let (decoded, _) = url::percent_decode("hello+world", true);
    assert_eq!(decoded, "hello world");
}

#[test]
fn plus_kept_literal_in_path_mode() {
    let (decoded, _) = url::percent_decode("hello+world", false);
    assert_eq!(decoded, "hello+world");
}

// ── path normalization ────────────────────────────────────────────────────────

#[test]
fn null_bytes_are_stripped() {
    let mut c = ctx("/foo/bar");
    c.raw_path = "/foo\x00bar".to_string();
    let n = run(&mut c);
    assert!(!n.path.contains('\0'));
    assert_eq!(n.path, "/foobar");
}

#[test]
fn dotdot_traversal_is_resolved() {
    let mut c = ctx("/foo/../bar");
    c.raw_path = "/foo/../bar".to_string();
    assert_eq!(run(&mut c).path, "/bar");
}

#[test]
fn double_slash_is_normalized() {
    let mut c = ctx("/foo//bar");
    c.raw_path = "/foo//bar".to_string();
    assert_eq!(run(&mut c).path, "/foo/bar");
}

#[test]
fn encoded_dotdot_decoded_and_resolved() {
    // %2e%2e = '..' (single encoding, not double)
    let raw = "/%2e%2e/bar";
    let mut c = ctx(raw);
    c.raw_path = raw.to_string();
    let n = run(&mut c);
    assert_eq!(n.path, "/bar");
    assert!(!n.double_encoding_detected);
}

#[test]
fn double_encoded_dotdot_detected_and_resolved() {
    // %252e%252e → first decode: %2e%2e → double enc flag → second decode: .. → resolved
    let raw = "/%252e%252e/bar";
    let mut c = ctx(raw);
    c.raw_path = raw.to_string();
    let n = run(&mut c);
    assert_eq!(n.path, "/bar");
    assert!(n.double_encoding_detected);
}

#[test]
fn double_encoded_slash_sets_flag() {
    // %252f → first decode: %2f → flag → second decode: /
    let raw = "/foo%252fbar";
    let mut c = ctx(raw);
    c.raw_path = raw.to_string();
    let n = run(&mut c);
    assert!(n.double_encoding_detected);
}

#[test]
fn path_is_lowercased() {
    let raw = "/FOO/Bar/BAZ";
    let mut c = ctx(raw);
    c.raw_path = raw.to_string();
    assert_eq!(run(&mut c).path, "/foo/bar/baz");
}

#[test]
fn traversal_cannot_escape_root() {
    let raw = "/../../etc/passwd";
    let mut c = ctx(raw);
    c.raw_path = raw.to_string();
    assert_eq!(run(&mut c).path, "/etc/passwd");
}

// ── Unicode normalization ─────────────────────────────────────────────────────

#[test]
fn fullwidth_ascii_chars_are_normalized() {
    // Fullwidth Ａ (U+FF21) Ｂ (U+FF22) → 'AB' after NFKC, then lowercase 'ab'
    let (norm_path, _) = url::normalize_path("/\u{FF21}\u{FF42}\u{FF43}");
    assert_eq!(norm_path, "/abc");
}

#[test]
fn unicode_fi_ligature_is_decomposed() {
    // ﬁ (U+FB01) → "fi" after NFKC
    let (norm_path, _) = url::normalize_path("/\u{FB01}le");
    assert_eq!(norm_path, "/file");
}

// ── query string ──────────────────────────────────────────────────────────────

#[test]
fn query_params_are_decoded() {
    let mut c = ctx_query("/", "name=John%20Doe&city=New%20York");
    let n = run(&mut c);
    assert!(n.query_params.contains(&("name".to_string(), "John Doe".to_string())));
    assert!(n.query_params.contains(&("city".to_string(), "New York".to_string())));
}

#[test]
fn repeated_query_params_all_kept() {
    let mut c = ctx_query("/", "tag=rust&tag=waf&tag=security");
    let tags: Vec<String> = run(&mut c)
        .query_params
        .iter()
        .filter(|(k, _)| k == "tag")
        .map(|(_, v)| v.clone())
        .collect();
    assert_eq!(tags, vec!["rust", "waf", "security"]);
}

#[test]
fn query_double_encoding_sets_flag() {
    let mut c = ctx_query("/", "x=%2541");
    assert!(run(&mut c).double_encoding_detected);
}

#[test]
fn query_plus_decoded_as_space() {
    let mut c = ctx_query("/", "msg=hello+world");
    assert!(run(&mut c).query_params.contains(&("msg".to_string(), "hello world".to_string())));
}

// ── body: form-urlencoded ─────────────────────────────────────────────────────

#[test]
fn form_urlencoded_is_parsed() {
    let mut c = ctx_body(
        "application/x-www-form-urlencoded",
        b"username=alice&tag=a&tag=b",
    );
    norm().normalize(&mut c).unwrap();
    let ParsedBody::FormUrlEncoded(params) = &c.normalized.body else {
        panic!("expected FormUrlEncoded, got {:?}", c.normalized.body);
    };
    assert!(params.contains(&("username".to_string(), "alice".to_string())));
    let tags: Vec<&str> = params.iter().filter(|(k, _)| k == "tag").map(|(_, v)| v.as_str()).collect();
    assert_eq!(tags, vec!["a", "b"]);
}

#[test]
fn form_urlencoded_plus_decoded_as_space() {
    let mut c = ctx_body("application/x-www-form-urlencoded", b"msg=hello+world");
    norm().normalize(&mut c).unwrap();
    let ParsedBody::FormUrlEncoded(params) = &c.normalized.body else { panic!() };
    assert!(params.contains(&("msg".to_string(), "hello world".to_string())));
}

// ── body: JSON ────────────────────────────────────────────────────────────────

#[test]
fn json_body_is_flattened() {
    let body = br#"{"user":{"name":"Alice","age":30},"active":true}"#;
    let mut c = ctx_body("application/json", body);
    norm().normalize(&mut c).unwrap();
    let ParsedBody::JsonFlattened(pairs) = &c.normalized.body else {
        panic!("expected JsonFlattened, got {:?}", c.normalized.body);
    };
    assert!(pairs.contains(&("user.name".to_string(), "Alice".to_string())));
    assert!(pairs.contains(&("user.age".to_string(), "30".to_string())));
    assert!(pairs.contains(&("active".to_string(), "true".to_string())));
}

#[test]
fn json_array_indexed_in_flattened_output() {
    let body = br#"{"tags":["rust","waf"]}"#;
    let mut c = ctx_body("application/json", body);
    norm().normalize(&mut c).unwrap();
    let ParsedBody::JsonFlattened(pairs) = &c.normalized.body else { panic!() };
    assert!(pairs.contains(&("tags.0".to_string(), "rust".to_string())));
    assert!(pairs.contains(&("tags.1".to_string(), "waf".to_string())));
}

#[test]
fn json_depth_exceeded_returns_error() {
    // 7 levels of nesting, max_depth = 5
    let body = format!("{}{}{}", "{\"a\":".repeat(7), "\"leaf\"", "}".repeat(7));
    let mut c = ctx_body("application/json", body.as_bytes());
    let err = norm_with(LimitsConfig { max_json_depth: 5, ..LimitsConfig::default() })
        .normalize(&mut c)
        .unwrap_err();
    assert!(matches!(err, NormalizationError::JsonDepthExceeded { limit: 5 }), "got: {:?}", err);
}

#[test]
fn json_depth_at_limit_is_accepted() {
    // 5 levels, max_depth = 5 → should succeed
    let body = format!("{}{}{}", "{\"a\":".repeat(5), "\"leaf\"", "}".repeat(5));
    let mut c = ctx_body("application/json", body.as_bytes());
    norm_with(LimitsConfig { max_json_depth: 5, ..LimitsConfig::default() })
        .normalize(&mut c)
        .unwrap();
}

// ── body: multipart ───────────────────────────────────────────────────────────

#[test]
fn multipart_fields_are_extracted() {
    let body = b"--B\r\n\
Content-Disposition: form-data; name=\"field1\"\r\n\
\r\n\
value1\r\n\
--B\r\n\
Content-Disposition: form-data; name=\"file\"; filename=\"test.txt\"\r\n\
Content-Type: text/plain\r\n\
\r\n\
file content\r\n\
--B--\r\n";

    let mut c = ctx_body("multipart/form-data; boundary=B", body);
    norm().normalize(&mut c).unwrap();
    let ParsedBody::Multipart(fields) = &c.normalized.body else {
        panic!("expected Multipart, got {:?}", c.normalized.body);
    };
    assert_eq!(fields.len(), 2);
    assert_eq!(fields[0].name, "field1");
    assert_eq!(fields[0].filename, None);
    assert_eq!(fields[0].data.as_ref(), b"value1");
    assert_eq!(fields[1].name, "file");
    assert_eq!(fields[1].filename.as_deref(), Some("test.txt"));
    assert_eq!(fields[1].content_type.as_deref(), Some("text/plain"));
}

// ── defensive limits ──────────────────────────────────────────────────────────

#[test]
fn body_too_large_returns_error() {
    let mut c = ctx("/");
    c.body = Bytes::from(vec![b'x'; 101]);
    let err = norm_with(LimitsConfig { max_body_size: 100, ..LimitsConfig::default() })
        .normalize(&mut c)
        .unwrap_err();
    assert!(
        matches!(err, NormalizationError::BodyTooLarge { limit: 100, actual: 101 }),
        "got: {:?}", err
    );
}

#[test]
fn too_many_headers_returns_error() {
    let mut c = ctx("/");
    c.headers = (0..101).map(|i| (format!("x-h-{i}"), "v".to_string())).collect();
    let err = norm_with(LimitsConfig { max_headers: 100, ..LimitsConfig::default() })
        .normalize(&mut c)
        .unwrap_err();
    assert!(matches!(err, NormalizationError::TooManyHeaders { limit: 100 }), "got: {:?}", err);
}

#[test]
fn header_value_too_large_returns_error() {
    let mut c = ctx("/");
    c.headers = vec![("x-big".to_string(), "x".repeat(101))];
    let err = norm_with(LimitsConfig { max_header_size: 100, ..LimitsConfig::default() })
        .normalize(&mut c)
        .unwrap_err();
    assert!(
        matches!(err, NormalizationError::HeaderTooLarge { limit: 100, actual: 101 }),
        "got: {:?}", err
    );
}

#[test]
fn too_many_query_params_returns_error() {
    let query = (0..11).map(|i| format!("k{i}=v{i}")).collect::<Vec<_>>().join("&");
    let mut c = ctx_query("/", &query);
    let err = norm_with(LimitsConfig { max_params: 10, ..LimitsConfig::default() })
        .normalize(&mut c)
        .unwrap_err();
    assert!(matches!(err, NormalizationError::TooManyParams { limit: 10 }), "got: {:?}", err);
}

#[test]
fn too_many_form_params_returns_error() {
    let body = (0..11).map(|i| format!("k{i}=v{i}")).collect::<Vec<_>>().join("&");
    let mut c = ctx_body("application/x-www-form-urlencoded", body.as_bytes());
    let err = norm_with(LimitsConfig { max_params: 10, ..LimitsConfig::default() })
        .normalize(&mut c)
        .unwrap_err();
    assert!(matches!(err, NormalizationError::TooManyParams { limit: 10 }), "got: {:?}", err);
}

#[test]
fn too_many_cookies_returns_error() {
    let cookie_hdr = (0..6).map(|i| format!("c{i}=v{i}")).collect::<Vec<_>>().join("; ");
    let mut c = ctx("/");
    c.headers = vec![("cookie".to_string(), cookie_hdr)];
    let err = norm_with(LimitsConfig { max_cookies: 5, ..LimitsConfig::default() })
        .normalize(&mut c)
        .unwrap_err();
    assert!(matches!(err, NormalizationError::TooManyCookies { limit: 5 }), "got: {:?}", err);
}

// ── cookie parsing ────────────────────────────────────────────────────────────

#[test]
fn cookies_parsed_into_normalized() {
    let mut c = ctx("/");
    c.headers = vec![("cookie".to_string(), "session=abc; user=alice; theme=dark".to_string())];
    let n = run(&mut c);
    assert!(n.cookies.contains(&("session".to_string(), "abc".to_string())));
    assert!(n.cookies.contains(&("user".to_string(), "alice".to_string())));
}

fn cookie_value(header: &str, name: &str) -> String {
    let mut c = ctx("/");
    c.headers = vec![("cookie".to_string(), header.to_string())];
    norm().normalize(&mut c).expect("normalization failed");
    c.normalized
        .cookies
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.clone())
        .unwrap_or_else(|| panic!("cookie {name} not found"))
}

#[test]
fn cookie_value_is_percent_decoded() {
    // Same canonicalization as query/body now reaches cookies: php%3a%2f%2f → php://
    assert_eq!(cookie_value("x=php%3a%2f%2f", "x"), "php://");
}

#[test]
fn cookie_double_encoding_resolved_and_flagged() {
    // Mirror of query behavior: a second decode pass resolves double-encoding
    // (anti-double-encoding defense) and raises the flag.
    let mut c = ctx("/");
    c.headers = vec![("cookie".to_string(), "x=%252e%252e".to_string())];
    let n = run(&mut c);
    assert!(n.cookies.contains(&("x".to_string(), "..".to_string())));
    assert!(n.double_encoding_detected);
}

#[test]
fn cookie_plus_is_literal_not_space() {
    // RFC 6265: cookies are not form-encoded, so '+' stays literal (unlike query).
    assert_eq!(cookie_value("x=a+b", "x"), "a+b");
}

#[test]
fn cookie_matches_query_canonicalization_uniformity() {
    // Uniformity: a cookie and a query param with the same input canonicalize the
    // same way — EXCEPT the '+' convention. %2525 collapses to % in BOTH, which is
    // the existing intentional anti-double-encoding behavior (not a regression).
    let mut c = ctx_query("/", "x=%2525");
    c.headers = vec![("cookie".to_string(), "x=%2525".to_string())];
    let n = run(&mut c);
    let q = &n.query_params.iter().find(|(k, _)| k == "x").unwrap().1;
    let ck = &n.cookies.iter().find(|(k, _)| k == "x").unwrap().1;
    assert_eq!(q, "%");
    assert_eq!(ck, "%");
}

#[test]
fn legit_cookie_with_stray_percent_is_preserved() {
    // No false positive: a literal '%' not forming a valid %XX stays as-is.
    assert_eq!(cookie_value("discount=50%off", "discount"), "50%off");
}

// ── header normalization ──────────────────────────────────────────────────────

#[test]
fn header_names_lowercased_in_normalized() {
    let mut c = ctx("/");
    c.headers = vec![
        ("X-Custom-Header".to_string(), "Value".to_string()),
        ("Content-Type".to_string(), "text/plain".to_string()),
    ];
    let n = run(&mut c);
    assert!(n.headers.iter().all(|(k, _)| k == &k.to_lowercase()));
}
