pub mod header_injection;
pub mod ldap;
pub mod lfi_rfi;
pub mod mail;
pub mod nosql;
pub mod path_traversal;
pub mod rate_limit;
pub mod rce;
pub mod request_smuggling;
pub mod scanner;
pub mod sqli;
pub mod ssi;
pub mod ssrf;
pub mod ssti;
pub mod xss;
pub mod xxe;

use regex::RegexSet;
use waf_core::{ParsedBody, RequestContext, Severity};
use waf_normalizer::url::canonicalize_multipart_field;

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

// ── content prefilter (Fase 7 / Pilastro 3: sound fast-path skip) ─────────────

/// A list of `(rule_id, pattern)` for one scope bucket of the content prefilter.
pub type RuleList = Vec<(&'static str, &'static str)>;

/// `(rule_id, pattern)` for every CONTENT-inspection rule active at `paranoia`,
/// split into two **scope buckets** (request_smuggling is excluded — it is
/// structural framing validation, not regex content inspection, and always runs in
/// the connection phase). Single source for the prefilter, so it cannot drift from
/// the per-module rules.
///
/// - `main`: every rule whose pattern is safe to scan over a **superset** of the
///   fields it inspects ({path, query, cookies, headers, body}) — the 6 content
///   modules plus the non-host header-injection rules. Over-scanning is sound
///   (it can only over-flag → run the full path), and these patterns are specific
///   enough not to match benign paths/headers.
/// - `host`: the host-only header-injection rule(s) (`Scope::HostHeaders`), whose
///   broad `[/@]` pattern MUST be scanned **only** against host header values —
///   scanning it over the path (always `/`) is what made a global union useless.
pub fn content_rules_split(paranoia: u8) -> (RuleList, RuleList) {
    let mut main: RuleList = Vec::new();
    let mut host: RuleList = Vec::new();
    for table in [
        sqli::SQLI_RULES,
        xss::XSS_RULES,
        path_traversal::PATH_TRAVERSAL_RULES,
        rce::RCE_RULES,
        lfi_rfi::LFI_RFI_RULES,
        ssrf::SSRF_RULES,
        ldap::LDAP_RULES,
        nosql::NOSQL_RULES,
        mail::MAIL_RULES,
        ssti::SSTI_RULES,
        scanner::SCANNER_RULES,
        ssi::SSI_RULES,
        xxe::XXE_RULES,
    ] {
        for r in table.iter().filter(|r| r.paranoia <= paranoia) {
            main.push((r.id, r.pattern));
        }
    }
    for (id, pattern, par, host_only) in header_injection::rule_meta() {
        if par <= paranoia {
            if host_only {
                host.push((id, pattern));
            } else {
                main.push((id, pattern));
            }
        }
    }
    (main, host)
}

/// A sound, **scope-aware** skip-prefilter: per-scope unions (`RegexSet`) of the
/// active content patterns, evaluated over the **canonical** surface (§6).
///
/// Soundness is by construction *per scope*: each rule's pattern is scanned over a
/// **superset** of the fields it actually inspects, so a clean result on every
/// scanned surface proves no content rule matches → the full inspection would
/// return Allow → the caller may safely skip it. The check can only err toward
/// "candidate" (run the full path), never toward a wrong skip.
///
/// NB: a character-class pre-check (looking for `<`/`'`/`%`/…) would be UNSOUND —
/// keyword rules match plain alphanumerics (`union select`, `sleep(`, `/etc/passwd`)
/// and normalization turns `%3C`/fullwidth into `<` — so this MUST stay a regex
/// union over the same patterns and the same canonical surface as the modules.
pub struct ContentPrefilter {
    /// Scanned over path + query + cookies + headers + body.
    main: RegexSet,
    /// Scanned over host header values only.
    host: RegexSet,
    main_ids: Vec<&'static str>,
    host_ids: Vec<&'static str>,
}

impl ContentPrefilter {
    /// Build the scope-aware prefilter for all content rules active at `paranoia`.
    pub fn new(paranoia: u8) -> Self {
        let (main_rules, host_rules) = content_rules_split(paranoia);
        let main = RegexSet::new(main_rules.iter().map(|(_, p)| *p))
            .expect("content prefilter MAIN union compilation failed");
        let host = RegexSet::new(host_rules.iter().map(|(_, p)| *p))
            .expect("content prefilter HOST union compilation failed");
        Self {
            main,
            host,
            main_ids: main_rules.iter().map(|(id, _)| *id).collect(),
            host_ids: host_rules.iter().map(|(id, _)| *id).collect(),
        }
    }

    /// All rule_ids covered (main + host) — total-completeness assertions.
    pub fn rule_ids(&self) -> Vec<&'static str> {
        self.main_ids.iter().chain(&self.host_ids).copied().collect()
    }

    /// rule_ids in the host-only bucket — scope-correspondence assertions (must be
    /// exactly the `Scope::HostHeaders` rules, never a content rule).
    pub fn host_rule_ids(&self) -> &[&'static str] {
        &self.host_ids
    }

    /// `true` = at least one pattern *might* match the canonical surface → the full
    /// inspection MUST run. `false` = **provably** no content rule can match → the
    /// caller may skip inspection and treat the request as Allow.
    pub fn is_candidate(&self, ctx: &RequestContext) -> bool {
        let n = &ctx.normalized;
        // MAIN bucket over the superset surface.
        if self.main.is_match(&n.path) {
            return true;
        }
        for (_, v) in n.query_params.iter().chain(&n.cookies).chain(&n.headers) {
            if self.main.is_match(v) {
                return true;
            }
        }
        if body_str_values(&n.body).iter().any(|v| self.main.is_match(v)) {
            return true;
        }
        // HOST bucket over host header values only.
        n.headers
            .iter()
            .filter(|(name, _)| name == "host" || name == "x-forwarded-host")
            .any(|(_, v)| self.host.is_match(v))
    }
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
            // Field-coverage (10b-cont fix): inspect EVERY part field — the form
            // `name`, the `filename`, AND the value — because gotestwaf's
            // `community-lfi-multipart` smuggles the traversal in the part `name`
            // (no filename) or in the value, often double-/overlong-encoded. Each is
            // run through `canonicalize_multipart_field` (recursive decode + overlong
            // UTF-8 collapse + NFKC) so `%25C0%25AE…` / `..%2f` resolve to `../`
            // BEFORE the rules see them. Binary values that are not valid UTF-8
            // contribute name+filename only.
            let mut out = Vec::with_capacity(fields.len() * 2);
            for f in fields {
                out.push(canonicalize_multipart_field(&f.name));
                if let Some(filename) = &f.filename {
                    out.push(canonicalize_multipart_field(filename));
                }
                if let Ok(s) = std::str::from_utf8(&f.data) {
                    out.push(canonicalize_multipart_field(s));
                }
            }
            out
        }
        ParsedBody::Raw(bytes) => {
            std::str::from_utf8(bytes).ok().map(str::to_owned).into_iter().collect()
        }
        ParsedBody::None => vec![],
    }
}
