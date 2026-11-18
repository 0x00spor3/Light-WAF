// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

//! False-positive gate for the curated CVE signatures (Tier 3, Aug–Nov 2026 wave).
//!
//! Two sources of benign traffic, both of which must leave every Tier-3 rule silent:
//! 1. every `Clean` trap of the core corpus (`waf-corpus`), built through the real connection
//!    phase + normalizer so the raw fields the CRS channel reads are exactly the wire shape;
//! 2. a hand-written table of realistic requests aimed at the EDGE of each rule — the legitimate
//!    traffic of the very product the signature protects (WordPress permalinks, Next.js assets,
//!    Kestra API calls, Plex clients, Java form logins, signed JWTs, …).

use waf_core::{Bytes, Decision, Normalized, RequestContext, SeverityScores, WafModule};
use waf_corpus::{cases, prepared_ctx, Expect};
use waf_crs_curated::curated_source;
use waf_detection::crs::CrsModule;

/// The rules under test: the Aug–Nov 2026 wave plus the generic pearcmd pivot.
const TIER3: &[&str] = &[
    "crs-9000033", "crs-9100040", "crs-9100041", "crs-9100042", "crs-9100043", "crs-9100044",
    "crs-9100045", "crs-9100046", "crs-9100047", "crs-9100048", "crs-9100049", "crs-9100050",
    "crs-9100051",
];

fn tier3_hits(m: &CrsModule, c: &RequestContext) -> Vec<String> {
    match m.inspect(c) {
        Decision::Scores(items) => items
            .into_iter()
            .map(|i| i.rule_id.to_string())
            .filter(|id| TIER3.contains(&id.as_str()))
            .collect(),
        _ => Vec::new(),
    }
}

#[test]
fn core_corpus_clean_traps_stay_clean() {
    let m = CrsModule::from_source(&curated_source());
    let mut checked = 0;
    let mut fps = Vec::new();
    for case in cases::all().into_iter().filter(|c| c.expect == Expect::Clean) {
        let Some(ctx) = prepared_ctx(&case.field, 3, SeverityScores::default()) else { continue };
        checked += 1;
        let hits = tier3_hits(&m, &ctx);
        if !hits.is_empty() {
            fps.push(format!("{} -> {hits:?}", case.id));
        }
    }
    assert!(checked > 100, "expected the core corpus to provide >100 clean traps, got {checked}");
    assert!(fps.is_empty(), "Tier-3 false positives on core corpus clean traps:\n{}", fps.join("\n"));
}

// ── realistic benign traffic at each rule's edge ───────────────────────────────

struct Req {
    method: &'static str,
    path: &'static str,
    query: Option<&'static str>,
    headers: &'static [(&'static str, &'static str)],
    body: &'static str,
}

const fn get(path: &'static str, query: Option<&'static str>) -> Req {
    Req { method: "GET", path, query, headers: &[], body: "" }
}

const JSON: &[(&str, &str)] = &[("Content-Type", "application/json")];
const XML: &[(&str, &str)] = &[("Content-Type", "text/xml")];
const FORM: &[(&str, &str)] = &[("Content-Type", "application/x-www-form-urlencoded")];

const BENIGN: &[Req] = &[
    // WordPress (9100043 / 9000033): permalinks, hierarchical pages, admin, REST.
    get("/", Some("page_id=12&pagename=privacy-policy")),
    get("/", Some("pagename=company/team/leadership")),
    get("/", Some("pagename=blog%2F2026%2F11%2Fhello-world")),
    get("/wp-admin/admin-ajax.php", Some("action=heartbeat&_nonce=a1b2c3")),
    get("/wp-json/wp/v2/pages", Some("slug=appearance-settings&per_page=10")),
    Req { method: "POST", path: "/wp-login.php", query: None, headers: FORM,
          body: "log=admin&pwd=s3cret&redirect_to=%2Fwp-admin%2F&testcookie=1" },
    // Next.js (9100044): assets, data routes, image optimizer, Windows paths and ellipses in text.
    get("/_next/static/chunks/app/page-4f2c1a.js", None),
    get("/_next/data/build-123/en/blog/post.json", Some("slug=post")),
    get("/_next/image", Some("url=%2Fimages%2Fhero.png&w=1080&q=75")),
    get("/download", Some("file=C%3A%5CUsers%5CPublic%5Creport.pdf")),
    get("/search", Some("q=Loading...%5Cn+please+wait")),
    get("/docs/guide", Some("ref=..%2Fintro")),
    // Langflow (9100042): ordinary custom components, incl. PyTorch `.eval()` and env lookups.
    Req { method: "POST", path: "/api/v1/validate/code", query: None, headers: JSON,
          body: "{\"code\":\"from langflow.custom import Component\\nimport os\\n\\nclass MyComp(Component):\\n    display_name = 'Embed'\\n    def build(self):\\n        key = os.environ.get('OPENAI_API_KEY')\\n        self.model.eval()\\n        return ast.literal_eval(self.cfg)\"}" },
    Req { method: "POST", path: "/api/v1/validate/prompt", query: None, headers: JSON,
          body: "{\"name\":\"p\",\"template\":\"Answer: {question}\"}" },
    // Roller XML-RPC (9100040): MetaWeblog / Blogger calls, incl. base64 media upload.
    Req { method: "POST", path: "/roller-services/xmlrpc", query: None, headers: XML,
          body: "<?xml version=\"1.0\"?><methodCall><methodName>metaWeblog.newMediaObject</methodName><params><param><value><string>blog</string></value></param><param><value><struct><member><name>bits</name><value><base64>iVBORw0KGgo=</base64></value></member></struct></value></param></params></methodCall>" },
    Req { method: "POST", path: "/ws/soap", query: None, headers: XML,
          body: "<soap:Envelope><soap:Body><isSerializable>true</isSerializable></soap:Body></soap:Envelope>" },
    // TeamCity (9100041): agent traffic and REST API.
    Req { method: "POST", path: "/app/agents/v1/commands/next", query: None, headers: XML,
          body: "<commands><command name=\"runBuild\"><param name=\"buildId\">42</param></command></commands>" },
    Req { method: "POST", path: "/app/agents/v1/commands/error", query: None, headers: XML,
          body: "<error><message>java.io.IOException: Cannot run program\n\tat java.lang.ProcessBuilder.start(ProcessBuilder.java:1128)\n\tat java.lang.Runtime.exec(Runtime.java:594)</message></error>" },
    get("/app/rest/builds", Some("locator=buildType:Proj_Build,count:10")),
    // Ivanti / GPUStack (9100045 / 9100046): ordinary proxy headers.
    Req { method: "GET", path: "/dana-na/auth/url_default/welcome.cgi", query: None,
          headers: &[("X-Forwarded-For", "127.0.0.1"), ("X-Real-IP", "127.0.0.1")], body: "" },
    Req { method: "GET", path: "/v1/models", query: None,
          headers: &[("X-GPUStack-Real-IP", "198.51.100.7")], body: "" },
    // Kestra (9100047): the real API surface, incl. namespace files and the public config.
    get("/api/v1/configs", None),
    get("/api/v1/main/configs", None),
    get("/api/v1/main/flows/company.team/hello-world", None),
    Req { method: "POST", path: "/api/v1/main/executions/company.team/hello-world", query: None,
          headers: JSON, body: "{}" },
    get("/api/v1/main/namespaces/company.team/files", Some("path=%2Fconfigs%2Fapp.yml")),
    get("/api/v1/projects/42/configs", None),
    get("/api/v1/main/namespaces/company.team/kv/configs", None),
    get("/api/v1/main/logs/company.team/configs", None),
    get("/api/v1/main/namespaces/configs", None),
    get("/api/v1/main/flows/configs", None),
    get("/api/v1/main/flows/company.team/configs-loader", None),
    // Plex (9100048): real client timeline calls.
    get("/player/timeline/subscribe", Some("protocol=http&port=32500&commandID=1")),
    get("/player/timeline/poll", Some("wait=1&commandID=3")),
    get("/player/timeline/subscribe", Some("protocol=https&port=32500")),
    // Java form login / Cisco vManage (9100049).
    Req { method: "POST", path: "/j_security_check", query: None, headers: FORM,
          body: "j_username=admin&j_password=p%40ss" },
    Req { method: "POST", path: "/app/j_security_check", query: Some("redirect=%2Fhome"), headers: FORM,
          body: "j_username=u&j_password=p" },
    get("/dataservice/device", Some("site-id=100&personality=vedge")),
    // JFrog (9100050): token and search APIs; a GET to the join path.
    Req { method: "POST", path: "/access/api/v1/tokens", query: None, headers: JSON,
          body: "{\"scope\":\"applied-permissions/user\"}" },
    Req { method: "POST", path: "/artifactory/api/search/aql", query: None,
          headers: &[("Content-Type", "text/plain")], body: "items.find({\"repo\":\"libs-release\"})" },
    get("/access/api/v1/registry/join", None),
    // JWT (9100051): signed tokens of every common alg, Basic auth, opaque bearer tokens.
    Req { method: "GET", path: "/api/am/admin/v4/apis", query: None,
          headers: &[("Authorization", "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImsxIn0.eyJzdWIiOiJhbGljZSIsImFsZ3MiOlsibm9uZSJdfQ.c2ln")], body: "" },
    Req { method: "GET", path: "/api/me", query: None,
          headers: &[("Authorization", "Bearer eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiIxIn0.c2ln")], body: "" },
    Req { method: "GET", path: "/api/me", query: None,
          headers: &[("Authorization", "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoibm9uZSJ9.c2ln")], body: "" },
    Req { method: "GET", path: "/api/me", query: None,
          headers: &[("Authorization", "Basic dXNlcjpwYXNzd29yZA==")], body: "" },
    Req { method: "GET", path: "/api/me", query: None,
          headers: &[("Authorization", "Bearer ghp_16C7e42F292c6912E7710c838347Ae178B4a")], body: "" },
    Req { method: "GET", path: "/services/admin", query: None,
          headers: &[("X-JWT-Assertion", "eyJ0eXAiOiJKV1QiLCJhbGciOiJQUzI1NiJ9.eyJzdWIiOiJib2IifQ.c2ln")], body: "" },
];

fn build(r: &Req) -> RequestContext {
    RequestContext {
        client_ip: "198.51.100.20".parse().unwrap(),
        request_id: "fp".to_string(),
        timestamp: std::time::SystemTime::now(),
        method: r.method.to_string(),
        path: r.path.to_string(),
        raw_path: r.path.to_string(),
        query: r.query.map(str::to_string),
        http_version: "HTTP/1.1".to_string(),
        headers: r.headers.iter().map(|(n, v)| (n.to_string(), v.to_string())).collect(),
        cookies: vec![],
        body: Bytes::from(r.body.to_string()),
        normalized: Normalized::default(),
        score: 0,
        score_contributions: vec![],
    }
}

#[test]
fn realistic_benign_traffic_at_each_rule_edge_stays_clean() {
    let m = CrsModule::from_source(&curated_source());
    let fps: Vec<String> = BENIGN
        .iter()
        .filter_map(|r| {
            let hits = tier3_hits(&m, &build(r));
            (!hits.is_empty()).then(|| format!("{} {}?{} -> {hits:?}", r.method, r.path, r.query.unwrap_or("")))
        })
        .collect();
    assert!(fps.is_empty(), "Tier-3 false positives on benign traffic:\n{}", fps.join("\n"));
}
