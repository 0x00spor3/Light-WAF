// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

//! Non-multipart bodies that are not clean UTF-8, on exact wire bytes.
//!
//! Text with a stray invalid byte or NUL is still text to the backend, and UTF-16 is text
//! to an XML parser, so none of it may leave the scan. The traps guard the other direction:
//! real binary bodies stay out of it, or their bytes would read as attacks.

use crate::{Case, Expect, Field, Module};

const fn attack(id: &'static str, content_type: &'static str, body: &'static [u8], desc: &'static str) -> Case {
    Case {
        id,
        module: Module::Sqli,
        field: Field::RawBytes { content_type, body },
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &[],
        desc,
    }
}

const fn benign(id: &'static str, content_type: &'static str, body: &'static [u8], desc: &'static str) -> Case {
    Case {
        id,
        module: Module::Sqli,
        field: Field::RawBytes { content_type, body },
        min_pl: 1,
        expect: Expect::Clean,
        rules: &[],
        desc,
    }
}

const FORM: &str = "application/x-www-form-urlencoded";

pub static CASES: &[Case] = &[
    // ── form-urlencoded ────────────────────────────────────────────────────────
    attack(
        "enc-form-invalid-byte-before",
        FORM,
        b"x=\xff&q=1' UNION SELECT password FROM users--",
        "one invalid byte in another parameter must not empty the whole form",
    ),
    attack(
        "enc-form-invalid-byte-after",
        FORM,
        b"q=1' UNION SELECT password FROM users--&x=\xff",
        "one invalid byte after the payload",
    ),
    attack(
        "enc-form-invalid-byte-in-value",
        FORM,
        b"q=\xff1' UNION SELECT password FROM users--",
        "one invalid byte inside the value, which PHP hands to the app as it is",
    ),
    attack(
        "enc-form-base64-behind-invalid-byte",
        FORM,
        b"q=\xffJyBVTklPTiBTRUxFQ1QgcGFzc3dvcmQgRlJPTSB1c2Vycy0t",
        "lenient base64 decoders skip the invalid byte, so the blob must still be decoded",
    ),
    // ── raw bodies ─────────────────────────────────────────────────────────────
    attack(
        "enc-text-invalid-byte",
        "text/plain",
        b"\xff1' UNION SELECT password FROM users--",
        "text/plain with one invalid byte",
    ),
    attack(
        "enc-text-nul",
        "text/plain",
        b"\x001' UNION SELECT password FROM users--",
        "text/plain with one NUL",
    ),
    attack(
        "enc-text-padded",
        "text/plain",
        b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff1' UNION SELECT password FROM users--",
        "declared text padded with invalid bytes must not pass for binary",
    ),
    attack(
        "enc-xml-invalid-byte",
        "application/xml",
        b"<a>\xff1' UNION SELECT password FROM users--</a>",
        "XML with one invalid byte, legal under a Latin-1 declaration",
    ),
    attack(
        "enc-xml-utf16-bom",
        "application/xml",
        b"\xff\xfe<\x00a\x00>\x00U\x00N\x00I\x00O\x00N\x00 \x00S\x00E\x00L\x00E\x00C\x00T\x00 \x00p\x00a\x00s\x00s\x00w\x00o\x00r\x00d\x00 \x00F\x00R\x00O\x00M\x00 \x00u\x00s\x00e\x00r\x00s\x00<\x00/\x00a\x00>\x00",
        "UTF-16LE XML with a BOM, which XML parsers decode",
    ),
    attack(
        "enc-xml-utf16-no-bom",
        "application/xml",
        b"\x00<\x00a\x00>\x00U\x00N\x00I\x00O\x00N\x00 \x00S\x00E\x00L\x00E\x00C\x00T\x00 \x00p\x00a\x00s\x00s\x00w\x00o\x00r\x00d\x00 \x00F\x00R\x00O\x00M\x00 \x00u\x00s\x00e\x00r\x00s\x00<\x00/\x00a\x00>",
        "UTF-16BE XML without a BOM, detected from its first bytes",
    ),
    attack(
        "enc-no-content-type-invalid-byte",
        "",
        b"\xff1' UNION SELECT password FROM users--",
        "no Content-Type, mostly text with one invalid byte",
    ),
    attack(
        "enc-octet-stream-text-invalid-byte",
        "application/octet-stream",
        b"\xff1' UNION SELECT password FROM users--",
        "the declared type is the client's word: this is text to a backend reading the raw body",
    ),
    // ── benign traps ───────────────────────────────────────────────────────────
    benign(
        "enc-benign-form-latin1",
        FORM,
        b"city=Forl\xec&note=caff\xe8",
        "legacy client sending raw Latin-1 in a form",
    ),
    benign(
        "enc-benign-text-latin1",
        "text/plain",
        b"Il caff\xe8 di Forl\xec costa pi\xf9 del t\xe8",
        "Latin-1 prose",
    ),
    benign(
        "enc-benign-xml-latin1",
        "application/xml",
        b"<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><city>Forl\xec</city>",
        "Latin-1 XML with its declaration",
    ),
    benign(
        "enc-benign-png",
        "image/png",
        b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x01\x00\x00\x00\x01\x00\x08\x06\x00\x00\x00\x5c\x72\xa8\x66\x00\x00\x00\x09\x70\x48\x59\x73",
        "binary image body",
    ),
    benign(
        "enc-benign-gzip-no-type",
        "",
        b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03\xab\x56\xca\x4b\xcc\x4d\x55\xb2\x52\x50\x2a\x49\x2d\x2e\x51\xaa\x05\x00\xe1\xc1\x8e\x28\x11\x00\x00\x00",
        "compressed bytes without a Content-Type",
    ),
    benign(
        "enc-benign-protobuf",
        "application/x-protobuf",
        b"\x0a\x05alice\x10\x96\x01\x1a\x0e\x0a\x0cquarterly up\x20\x01",
        "protobuf message: field tags around ordinary strings",
    ),
];
