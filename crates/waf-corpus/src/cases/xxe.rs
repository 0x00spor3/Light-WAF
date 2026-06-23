// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

//! XML External Entity (XXE) injection corpus cases (Fase 10b). Field: query
//! (the value round-trips the XML verbatim — `&`→`%26`→`&`, first-`=` split).
//! Rules (paranoia): xxe-entity-declaration 1, xxe-doctype-external 1,
//! xxe-utf7-encoding 1 (all Critical). Source: gotestwaf xml-injection +
//! community-xxe.
//!
//! ATTRIBUTION: the corpus runs at PL3, where lfi_rfi's `rfi-remote-url`
//! (`https?://`, Notice/PL3) fires on ANY remote URL. So the clean-attribution
//! triggers below use scheme-less SYSTEM ids (`//x/x`) or internal entities so
//! ONLY the xxe rule fires (break it → the case goes red, nothing rescues it);
//! the verbatim gotestwaf payloads that carry an `http://` are kept as declared
//! overlaps (mirrors the ssi/sqli-quote-comment precedent).

use crate::{Case, Expect, Field, Module};

pub static CASES: &[Case] = &[
    // ── malicious: clean attribution (scheme-less → ONLY the xxe rule fires) ──────
    Case {
        id: "xxe-entity-internal-query",
        module: Module::Xxe,
        field: Field::Query {
            name: "data",
            value: r#"<!DOCTYPE foo [ <!ENTITY xxe "lol" > ]><foo>&xxe;</foo>"#,
        },
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["xxe-entity-declaration"],
        desc: "internal entity declaration (no scheme) — isolates xxe-entity-declaration",
    },
    Case {
        id: "xxe-param-entity-query",
        module: Module::Xxe,
        field: Field::Query {
            name: "data",
            value: r#"<!DOCTYPE x [ <!ENTITY % y SYSTEM "//y/y" > %y; ]><x>a</x>"#,
        },
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["xxe-entity-declaration"],
        desc: "parameter-entity XXE (scheme-less SYSTEM id) — gotestwaf xml-injection; only xxe-entity-declaration fires (the `[` keeps xxe-doctype-external silent)",
    },
    Case {
        id: "xxe-doctype-system-query",
        module: Module::Xxe,
        field: Field::Query { name: "data", value: r#"<!DOCTYPE x SYSTEM "//x/x" > <x>a</x>"# },
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["xxe-doctype-external"],
        desc: "bare external DOCTYPE (SYSTEM, scheme-less) — gotestwaf xml-injection; isolates xxe-doctype-external",
    },
    Case {
        id: "xxe-utf7-encoding-query",
        module: Module::Xxe,
        field: Field::Query {
            name: "data",
            value: "<?xml version=\"1.0\" encoding=\"UTF-7\"?>+ADw-foo+AD4-",
        },
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["xxe-utf7-encoding"],
        desc: "UTF-7 XML declaration (scheme-less) — isolates xxe-utf7-encoding (the charset-smuggling signature)",
    },
    // ── malicious: verbatim gotestwaf payloads (declared http:// overlap with
    //     rfi-remote-url via the external entity URL — defense-in-depth) ──────────
    Case {
        id: "xxe-entity-system-http-query",
        module: Module::Xxe,
        field: Field::Query {
            name: "data",
            value: r#"<!DOCTYPE foo [ <!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "http://host/text.txt" > ] > <foo>&xxe;</foo>"#,
        },
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["xxe-entity-declaration"],
        desc: "verbatim gotestwaf XXE external entity (also trips rfi-remote-url via http://, declared; attribution stays xxe-entity-declaration)",
    },
    Case {
        id: "xxe-utf7-smuggled-query",
        module: Module::Xxe,
        field: Field::Query {
            name: "data",
            value: "<?xml version=\"1.0\" encoding=\"UTF-7\"?>\n+ADwAIQ-DOCTYPE foo+AFs +ADwAIQ-ELEMENT foo ANY +AD4\n+ADwAIQ-ENTITY xxe SYSTEM +ACI-http://hack-r.be:1337+ACI +AD4AXQA+\n+ADw-foo+AD4AJg-xxe+ADsAPA-/foo+AD4\n",
        },
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["xxe-utf7-encoding"],
        desc: "verbatim gotestwaf community-xxe: the real <!DOCTYPE/<!ENTITY are UTF-7-encoded (+ADwAIQ-…); xxe-utf7-encoding catches the charset (also rfi-remote-url via the http:// tail, declared)",
    },
    // ── §6-D5: external-schema XXE — now CAUGHT natively via anomalous-form anchors ──
    // (was deferred as FP-prohibitive; the structural anchors below are FP-probed clean
    // against real SOAP / xs:import / XHTML / noNamespaceSchemaLocation — see benign guards.)
    Case {
        id: "xxe-xsi-schemalocation-query",
        module: Module::Xxe,
        field: Field::Query {
            name: "data",
            value: r#"<?xml version="1.0" encoding="utf-8" standalone="no" ?><x xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://xxe-xsi-schemalocation.yourdomain[.]com/"/>"#,
        },
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["xxe-schemalocation-single-url"],
        desc: "external xsi:schemaLocation XXE (single URL, not a namespace/location pair) — \
               §6-D5; legit SOAP pairs + noNamespaceSchemaLocation stay clean (benign guards)",
    },
    Case {
        id: "xxe-xs-include-query",
        module: Module::Xxe,
        field: Field::Query {
            name: "data",
            value: r#"<?xml version="1.0" encoding="utf-8" standalone="no" ?><xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema"><xs:include namespace="http://xxe-xsinclude-namespace.yourdomain[.]com/"/></xs:schema>"#,
        },
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["xxe-xs-include-namespace"],
        desc: "external <xs:include namespace=…> XXE — malformed (include takes no namespace attr) \
               → §6-D5; legit xs:import (which DOES take namespace) stays clean (benign guard)",
    },
    // ── URLPath coverage (10c REOPEN, pcap): scheme-less SYSTEM id isolates xxe ───
    Case {
        id: "xxe-urlpath-entity",
        module: Module::Xxe,
        field: Field::Path("/<!ENTITY xxe SYSTEM '//attacker/x'>"),
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["xxe-entity-declaration"],
        desc: "external-entity declaration in the URL PATH — gotestwaf xml-injection; path now inspected",
    },
    // ── benign guards (must stay 200) ────────────────────────────────────────────
    Case {
        id: "xxe-benign-html5-doctype",
        module: Module::Xxe,
        field: Field::Query { name: "html", value: "<!DOCTYPE html><html><body>hi</body></html>" },
        min_pl: 1,
        expect: Expect::Clean,
        rules: &[],
        desc: "HTML5 doctype has no SYSTEM/ENTITY — must NOT match (xxe-doctype-external is SYSTEM-anchored)",
    },
    Case {
        id: "xxe-benign-xhtml-public-doctype",
        module: Module::Xxe,
        field: Field::Query {
            name: "html",
            value: r#"<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN">"#,
        },
        min_pl: 1,
        expect: Expect::Clean,
        rules: &[],
        desc: "XHTML doctype uses PUBLIC, not SYSTEM — the SYSTEM-only anchor is exactly what keeps this benign (no remote URL, so rfi-remote-url stays silent too)",
    },
    Case {
        id: "xxe-benign-utf8-encoding",
        module: Module::Xxe,
        field: Field::Query {
            name: "data",
            value: r#"<?xml version="1.0" encoding="UTF-8"?><note><to>Bob</to></note>"#,
        },
        min_pl: 1,
        expect: Expect::Clean,
        rules: &[],
        desc: "ordinary UTF-8 XML document — must NOT match xxe-utf7-encoding (8 != 7) or any markup-declaration rule",
    },
    // ── §6-D5 benign guards: legit SOAP/XSD schema refs must stay clean. NB: kept
    // http-FREE on purpose — a real http URL in a query value trips the unrelated
    // rfi-remote-url (Notice), which the strict benign oracle counts as a match. The
    // http-bearing variants (SOAP http-pair, http noNamespaceSchemaLocation) were
    // FP-probed separately and are clean; these lock the STRUCTURAL discrimination.
    Case {
        id: "xxe-benign-xs-import-namespace",
        module: Module::Xxe,
        field: Field::Query {
            name: "data",
            value: r#"<xs:schema><xs:import namespace="urn:example:ns" schemaLocation="common.xsd"/></xs:schema>"#,
        },
        min_pl: 1,
        expect: Expect::Clean,
        rules: &[],
        desc: "legit `xs:import` DOES carry a `namespace=` attr — the D5 rule anchors on `xs:include` (which must not), so import stays clean (D5 FP guard)",
    },
    Case {
        id: "xxe-benign-schemalocation-pair",
        module: Module::Xxe,
        field: Field::Query {
            name: "data",
            value: r#"<x xmlns:xsi="urn:w3:xsi" xsi:schemaLocation="urn:example:ns common.xsd"/>"#,
        },
        min_pl: 1,
        expect: Expect::Clean,
        rules: &[],
        desc: "legit `xsi:schemaLocation` = namespace+location PAIR (not a lone URL) — must NOT match the single-URL anchor (D5 FP guard)",
    },
    Case {
        id: "xxe-benign-nonamespace-schemalocation",
        module: Module::Xxe,
        field: Field::Query {
            name: "data",
            value: r#"<root xsi:noNamespaceSchemaLocation="common.xsd"><a/></root>"#,
        },
        min_pl: 1,
        expect: Expect::Clean,
        rules: &[],
        desc: "the legit single-URL schema attr is `noNamespaceSchemaLocation` — distinct name, must NOT match the `xsi:schemaLocation` anchor (D5 FP guard)",
    },
    Case {
        id: "xxe-benign-entity-prose",
        module: Module::Xxe,
        field: Field::Query { name: "q", value: "the XML ENTITY and DOCTYPE keywords explained" },
        min_pl: 1,
        expect: Expect::Clean,
        rules: &[],
        desc: "the words ENTITY/DOCTYPE as prose without the `<!` markup opener — must NOT match",
    },
];
