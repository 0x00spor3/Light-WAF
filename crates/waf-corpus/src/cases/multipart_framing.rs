// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

//! Multipart framing evasions, on exact wire bytes.
//!
//! Each shape below was accepted by at least one real backend parser (PHP, Go net/http,
//! Werkzeug, Starlette, busboy) while a strict WAF parser saw no field at all. Rules are
//! not the point of this table, the framing is: the same payload is caught when it is
//! well-formed, so a miss here means the body never reached the modules. `RawBytes` is
//! mandatory, `MultipartFile` always renders clean CRLF framing.
//!
//! The benign traps guard the other direction: binary uploads must stay out of the text
//! scan, and a sloppy client must not start being blocked for its line endings.

use crate::{Case, Expect, Field, Module};

const CT: &str = "multipart/form-data; boundary=B";

const fn attack(id: &'static str, body: &'static [u8], desc: &'static str) -> Case {
    Case {
        id,
        module: Module::PathTraversal,
        field: Field::RawBytes { content_type: CT, body },
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["pt-sensitive-unix"],
        desc,
    }
}

const fn payload(id: &'static str, module: Module, body: &'static [u8], desc: &'static str) -> Case {
    Case {
        id,
        module,
        field: Field::RawBytes { content_type: CT, body },
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &[],
        desc,
    }
}

const fn benign(id: &'static str, body: &'static [u8], desc: &'static str) -> Case {
    Case {
        id,
        module: Module::PathTraversal,
        field: Field::RawBytes { content_type: CT, body },
        min_pl: 1,
        expect: Expect::Clean,
        rules: &[],
        desc,
    }
}

pub static CASES: &[Case] = &[
    // ── line endings ───────────────────────────────────────────────────────────
    attack(
        "mp-wire-gotestwaf-lf-name",
        b"--B\nContent-disposition: form-data; name=\"/static/img/../../etc/passwd\"\n\nTest\n--B--\n",
        "WIRE: gotestwaf 0.5.8 community-lfi-multipart, bare LF everywhere, payload in the part name",
    ),
    attack(
        "mp-lf-value",
        b"--B\nContent-Disposition: form-data; name=\"f\"\n\n/static/img/../../etc/passwd\n--B--\n",
        "bare LF everywhere, payload in the value (PHP, Go, Werkzeug read it)",
    ),
    attack(
        "mp-lf-headers-only",
        b"--B\r\nContent-Disposition: form-data; name=\"f\"\n\n/static/img/../../etc/passwd\r\n--B--\r\n",
        "bare LF only inside the part headers",
    ),
    attack(
        "mp-lf-after-opening-boundary",
        b"--B\nContent-Disposition: form-data; name=\"f\"\r\n\r\n/static/img/../../etc/passwd\r\n--B--\r\n",
        "bare LF only after the opening delimiter",
    ),
    attack(
        "mp-lf-before-closing-boundary",
        b"--B\r\nContent-Disposition: form-data; name=\"f\"\r\n\r\n/static/img/../../etc/passwd\n--B--\r\n",
        "bare LF only before the closing delimiter",
    ),
    // ── delimiters ─────────────────────────────────────────────────────────────
    attack(
        "mp-padding-after-boundary",
        b"--B \t\r\nContent-Disposition: form-data; name=\"f\"\r\n\r\n/static/img/../../etc/passwd\r\n--B--\r\n",
        "RFC 2046 transport padding after the delimiter (Go, Werkzeug)",
    ),
    attack(
        "mp-no-closing-boundary",
        b"--B\r\nContent-Disposition: form-data; name=\"f\"\r\n\r\n/static/img/../../etc/passwd",
        "body ends without a closing delimiter (PHP keeps the part)",
    ),
    attack(
        "mp-part-after-closing-boundary",
        b"--B\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\n1\r\n--B--\r\n--B\r\nContent-Disposition: form-data; name=\"f\"\r\n\r\n/static/img/../../etc/passwd\r\n--B--\r\n",
        "payload placed after a premature closing delimiter",
    ),
    attack(
        "mp-cr-only-delimiter",
        b"--B\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\n1\r--B\r\nContent-Disposition: form-data; name=\"f\"\r\n\r\n/static/img/../../etc/passwd\r\n--B--\r\n",
        "delimiter preceded by a bare CR, which Werkzeug accepts as a line break",
    ),
    Case {
        id: "mp-duplicate-boundary-param",
        module: Module::PathTraversal,
        field: Field::RawBytes {
            content_type: "multipart/form-data; boundary=A; boundary=B",
            body: b"--B\r\nContent-Disposition: form-data; name=\"f\"\r\n\r\n/static/img/../../etc/passwd\r\n--B--\r\n",
        },
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["pt-sensitive-unix"],
        desc: "two boundary parameters, the WAF and the backend can pick different ones",
    },
    Case {
        id: "mp-quoted-boundary-with-semicolon",
        module: Module::PathTraversal,
        field: Field::RawBytes {
            content_type: "multipart/form-data; boundary=\"a;b\"",
            body: b"--a;b\r\nContent-Disposition: form-data; name=\"f\"\r\n\r\n/static/img/../../etc/passwd\r\n--a;b--\r\n",
        },
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["pt-sensitive-unix"],
        desc: "semicolon inside a quoted boundary parameter",
    },
    // ── part headers ───────────────────────────────────────────────────────────
    attack(
        "mp-non-utf8-header-then-attack",
        b"--B\r\nContent-Disposition: form-data; name=\"a\"\r\nX-Pad: \xff\r\n\r\n1\r\n--B\r\nContent-Disposition: form-data; name=\"f\"\r\n\r\n/static/img/../../etc/passwd\r\n--B--\r\n",
        "a non-UTF-8 header must not end parsing and hide the following parts",
    ),
    attack(
        "mp-semicolon-in-quoted-name",
        b"--B\r\nContent-Disposition: form-data; name=\"x;/static/img/../../etc/passwd\"\r\n\r\n1\r\n--B--\r\n",
        "semicolon inside a quoted name (all five backends read the whole name)",
    ),
    attack(
        "mp-semicolon-in-quoted-filename",
        b"--B\r\nContent-Disposition: form-data; name=\"f\"; filename=\"x;/static/img/../../etc/passwd\"\r\n\r\n1\r\n--B--\r\n",
        "semicolon inside a quoted filename",
    ),
    attack(
        "mp-filename-star-rfc5987",
        b"--B\r\nContent-Disposition: form-data; name=\"f\"; filename*=UTF-8''%2Fstatic%2Fimg%2F..%2F..%2Fetc%2Fpasswd\r\n\r\n1\r\n--B--\r\n",
        "RFC 5987 extended filename parameter",
    ),
    attack(
        "mp-no-name-filename-only",
        b"--B\r\nContent-Disposition: form-data; filename=\"/static/img/../../etc/passwd\"\r\n\r\n1\r\n--B--\r\n",
        "a part without name must not be dropped",
    ),
    attack(
        "mp-no-name-value",
        b"--B\r\nContent-Disposition: form-data\r\n\r\n/static/img/../../etc/passwd\r\n--B--\r\n",
        "a part without name or filename must still have its value inspected",
    ),
    attack(
        "mp-folded-disposition",
        b"--B\r\nContent-Disposition: form-data;\r\n name=\"/static/img/../../etc/passwd\"\r\n\r\n1\r\n--B--\r\n",
        "obsolete header folding (PHP, Go, Werkzeug, busboy)",
    ),
    attack(
        "mp-duplicate-disposition",
        b"--B\r\nContent-Disposition: form-data; name=\"a\"\r\nContent-Disposition: form-data; name=\"/static/img/../../etc/passwd\"\r\n\r\n1\r\n--B--\r\n",
        "two Content-Disposition headers, parsers disagree on which one wins",
    ),
    attack(
        "mp-duplicate-name-param",
        b"--B\r\nContent-Disposition: form-data; name=\"/static/img/../../etc/passwd\"; name=\"a\"\r\n\r\n1\r\n--B--\r\n",
        "two name parameters, the shadowed one must still be inspected",
    ),
    // ── values ─────────────────────────────────────────────────────────────────
    attack(
        "mp-non-utf8-before-value",
        b"--B\r\nContent-Disposition: form-data; name=\"f\"\r\n\r\n\xff/static/img/../../etc/passwd\r\n--B--\r\n",
        "one invalid byte before the payload must not take the whole value out of the scan",
    ),
    attack(
        "mp-non-utf8-after-value",
        b"--B\r\nContent-Disposition: form-data; name=\"f\"\r\n\r\n/static/img/../../etc/passwd\xff\r\n--B--\r\n",
        "one invalid byte after the payload",
    ),
    attack(
        "mp-non-utf8-empty-filename",
        b"--B\r\nContent-Disposition: form-data; name=\"f\"; filename=\"\"\r\n\r\n\xff/static/img/../../etc/passwd\r\n--B--\r\n",
        "an empty filename is not an upload: Go hands this part to the app as a form value",
    ),
    attack(
        "mp-quoted-printable-value",
        b"--B\r\nContent-Disposition: form-data; name=\"f\"\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n=2Fstatic=2Fimg=2F=2E=2E=2F=2E=2E=2Fetc=2Fpasswd\r\n--B--\r\n",
        "quoted-printable transfer encoding (Go decodes it for the app)",
    ),
    // ── the evasion is module-agnostic ─────────────────────────────────────────
    payload(
        "mp-sqli-non-utf8",
        Module::Sqli,
        b"--B\r\nContent-Disposition: form-data; name=\"q\"\r\n\r\n\xff1' UNION SELECT password FROM users--\r\n--B--\r\n",
        "SQLi behind one invalid byte",
    ),
    payload(
        "mp-sqli-lf",
        Module::Sqli,
        b"--B\nContent-Disposition: form-data; name=\"q\"\n\n1' UNION SELECT password FROM users--\n--B--\n",
        "SQLi in a bare-LF body",
    ),
    payload(
        "mp-xss-non-utf8",
        Module::Xss,
        b"--B\r\nContent-Disposition: form-data; name=\"q\"\r\n\r\n\xff<script>alert(1)</script>\r\n--B--\r\n",
        "XSS behind one invalid byte",
    ),
    payload(
        "mp-xss-lf",
        Module::Xss,
        b"--B\nContent-Disposition: form-data; name=\"q\"\n\n<script>alert(1)</script>\n--B--\n",
        "XSS in a bare-LF body",
    ),
    payload(
        "mp-rce-non-utf8",
        Module::Rce,
        b"--B\r\nContent-Disposition: form-data; name=\"q\"\r\n\r\n\xff; cat /etc/passwd\r\n--B--\r\n",
        "command injection behind one invalid byte",
    ),
    payload(
        "mp-rce-lf",
        Module::Rce,
        b"--B\nContent-Disposition: form-data; name=\"q\"\n\n; cat /etc/passwd\n--B--\n",
        "command injection in a bare-LF body",
    ),
    payload(
        "mp-ssti-non-utf8",
        Module::Ssti,
        b"--B\r\nContent-Disposition: form-data; name=\"q\"\r\n\r\n\xff{{7*7}}\r\n--B--\r\n",
        "SSTI behind one invalid byte",
    ),
    payload(
        "mp-ssti-lf",
        Module::Ssti,
        b"--B\nContent-Disposition: form-data; name=\"q\"\n\n{{7*7}}\n--B--\n",
        "SSTI in a bare-LF body",
    ),
    // ── benign traps ───────────────────────────────────────────────────────────
    benign(
        "mp-benign-binary-upload",
        b"--B\r\nContent-Disposition: form-data; name=\"f\"; filename=\"logo.png\"\r\nContent-Type: image/png\r\n\r\n\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\xff\xfe\r\n--B--\r\n",
        "well-formed binary upload: NUL and invalid UTF-8 in a named file stay out of the scan",
    ),
    benign(
        "mp-benign-lf-text",
        b"--B\nContent-Disposition: form-data; name=\"title\"\n\nquarterly report\n--B\nContent-Disposition: form-data; name=\"notes\"\n\nsee docs/../report.pdf\n--B--\n",
        "sloppy bare-LF client: the line endings alone must not fire anything",
    ),
    benign(
        "mp-benign-lf-binary-upload",
        b"--B\nContent-Disposition: form-data; name=\"f\"; filename=\"logo.png\"\nContent-Type: image/png\n\n\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\xff\xfe\n--B--\n",
        "bare-LF binary upload: the whole-body fallback must not fire pt-null-byte on file bytes",
    ),
    benign(
        "mp-benign-binary-no-filename",
        b"--B\r\nContent-Disposition: form-data; name=\"blob\"\r\nContent-Type: application/octet-stream\r\n\r\n\x00\x01\x02\xff\xfe\x00\r\n--B--\r\n",
        "binary field without filename: scanned as text now, its NULs must not read as an attack",
    ),
    benign(
        "mp-benign-latin1-filename",
        b"--B\r\nContent-Disposition: form-data; name=\"f\"; filename=\"caf\xe9.txt\"\r\n\r\nhello\r\n--B--\r\n",
        "legacy client sending a Latin-1 filename",
    ),
    benign(
        "mp-benign-windows-filename",
        b"--B\r\nContent-Disposition: form-data; name=\"f\"; filename=\"C:\\fakepath\\report.pdf\"\r\n\r\nhello\r\n--B--\r\n",
        "browser-style path in a filename",
    ),
    benign(
        "mp-benign-empty-values",
        b"--B\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\n\r\n--B\r\nContent-Disposition: form-data; name=\"f\"; filename=\"\"\r\nContent-Type: application/octet-stream\r\n\r\n\r\n--B--\r\n",
        "empty field plus an empty file input, as browsers send them",
    ),
];
