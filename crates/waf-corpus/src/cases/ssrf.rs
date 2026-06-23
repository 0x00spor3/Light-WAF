// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

//! SSRF corpus cases. Field coverage: query + cookies + body. Detects the SSRF
//! *target* (metadata IP/host, SSRF-specific schemes, loopback/private/obfuscated
//! IPs), not bare http/https/ftp/file (those are RFI/LFI). Benign cases avoid
//! private/loopback IPs and bare URLs (the latter fire rfi-remote-url at PL3).
//! Rules (paranoia): ssrf-cloud-metadata 1, ssrf-dangerous-scheme 1,
//! ssrf-loopback 2, ssrf-ip-obfuscation 2, ssrf-private-ip 3.

use crate::{Case, Expect, Field, Module};

pub static CASES: &[Case] = &[
    // ── malicious: one per rule ────────────────────────────────────────────────
    Case {
        id: "ssrf-cloud-metadata-query",
        module: Module::Ssrf,
        field: Field::Query { name: "url", value: "http://169.254.169.254/latest/meta-data/" },
        min_pl: 1,
        expect: Expect::Triggers,
        // Declared overlap (ARCHITECTURE §8): 169.254.169.254 also matches
        // ssrf-private-ip (link-local, PL3) and rfi-remote-url (PL3). Assert the
        // cloud-metadata rule, which is the point.
        rules: &["ssrf-cloud-metadata"],
        desc: "cloud instance-metadata endpoint; declared overlap with private-ip",
    },
    Case {
        id: "ssrf-dangerous-scheme-query",
        module: Module::Ssrf,
        field: Field::Query { name: "url", value: "gopher://host.example/_payload" },
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["ssrf-dangerous-scheme"],
        desc: "gopher:// SSRF-specific scheme (isolated from loopback)",
    },
    Case {
        id: "ssrf-loopback-query",
        module: Module::Ssrf,
        field: Field::Query { name: "url", value: "http://localhost:8080/admin" },
        min_pl: 2,
        expect: Expect::Triggers,
        // also fires rfi-remote-url (PL3 http://) — assert the loopback rule.
        rules: &["ssrf-loopback"],
        desc: "loopback host (Warning/PL2)",
    },
    Case {
        id: "ssrf-ip-obfuscation-query",
        module: Module::Ssrf,
        field: Field::Query { name: "url", value: "http://2130706433/" },
        min_pl: 2,
        expect: Expect::Triggers,
        // also fires rfi-remote-url (PL3) — assert the obfuscation rule.
        rules: &["ssrf-ip-obfuscation"],
        desc: "decimal-encoded 127.0.0.1 (Warning/PL2)",
    },
    Case {
        id: "ssrf-private-ip-query",
        module: Module::Ssrf,
        field: Field::Query { name: "url", value: "http://192.168.1.1/internal" },
        min_pl: 3,
        expect: Expect::Triggers,
        // also fires rfi-remote-url (PL3) — assert the private-ip rule.
        rules: &["ssrf-private-ip"],
        desc: "RFC1918 private address (Notice/PL3)",
    },
    // ── known gaps (ARCHITECTURE §8): tracked, never gate ───────────────────────
    Case {
        id: "ssrf-gap-decimal-metadata",
        module: Module::Ssrf,
        field: Field::Query { name: "host", value: "2852039166" },
        min_pl: 1,
        expect: Expect::ExpectedMiss { until_phase: None },
        rules: &[],
        desc: "169.254.169.254 in decimal — uncovered (obfuscation rule only covers 127.0.0.1)",
    },
    Case {
        id: "ssrf-gap-ipv6-ula",
        module: Module::Ssrf,
        field: Field::Query { name: "host", value: "[fc00::1]" },
        min_pl: 3,
        expect: Expect::ExpectedMiss { until_phase: None },
        rules: &[],
        desc: "IPv6 ULA fc00::/7 — uncovered (coverage limited to [::1] and fd00:ec2::254)",
    },
    Case {
        id: "ssrf-gap-ipv6-link-local",
        module: Module::Ssrf,
        field: Field::Query { name: "host", value: "[fe80::1]" },
        min_pl: 3,
        expect: Expect::ExpectedMiss { until_phase: None },
        rules: &[],
        desc: "IPv6 link-local fe80::/10 — uncovered",
    },
    // ── benign ──────────────────────────────────────────────────────────────────
    Case {
        id: "ssrf-benign-public-host",
        module: Module::Ssrf,
        field: Field::Query { name: "host", value: "shop.example.com" },
        min_pl: 1,
        expect: Expect::Clean,
        rules: &[],
        desc: "bare public hostname, no scheme and not an internal target",
    },
    Case {
        id: "ssrf-benign-public-ip",
        module: Module::Ssrf,
        field: Field::Query { name: "resolver", value: "8.8.8.8" },
        min_pl: 1,
        expect: Expect::Clean,
        rules: &[],
        desc: "public IP, not in any private/loopback range",
    },
    Case {
        id: "ssrf-benign-version-string",
        module: Module::Ssrf,
        field: Field::Query { name: "v", value: "release 10.2 build 7" },
        min_pl: 1,
        expect: Expect::Clean,
        rules: &[],
        desc: "version-like string that is not a full dotted-quad private IP",
    },
];
