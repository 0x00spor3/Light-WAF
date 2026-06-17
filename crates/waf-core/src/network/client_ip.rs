//! Secure resolution of the real client IP behind trusted proxies.
//!
//! A L7 WAF almost always sits behind an LB/CDN/TLS-terminator, so the peer
//! socket address is the proxy's IP — keying rate limiting or logging on it
//! collapses all clients to one bucket. The `X-Forwarded-For` chain carries the
//! real client, but it is **attacker-controlled** unless we count hops from our
//! own trusted proxies.
//!
//! Resolution order (the order IS the security boundary):
//! 1. peer NOT in `trusted_proxies` → use peer (forwarded header ignored).
//! 2. peer IS trusted → read the header, take the IP `trusted_hops` from the
//!    RIGHT (closest to us). NEVER the leftmost IP (client-controlled).
//! 3. header missing/malformed, or chain shorter than `trusted_hops` → fall back
//!    to peer (NEVER to a spoofable IP).
//! 4. `trusted_proxies` empty (default) → always use peer; an unconfigured
//!    deploy must not be spoofable.

use std::net::IpAddr;
use std::str::FromStr;

use crate::NetworkConfig;

/// How `client_ip` was determined — for audit/logging and to decide warnings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpSource {
    /// Peer is not a trusted proxy → peer used; forwarded header ignored.
    DirectPeer,
    /// Peer is a trusted proxy → IP read from the forwarded header.
    TrustedHeader,
    /// Behind a trusted proxy but the header was absent → fell back to peer.
    FallbackMissingHeader,
    /// Behind a trusted proxy but the header was malformed, OR the chain was
    /// shorter than `trusted_hops` → fell back to peer (never the spoofable IP).
    FallbackMalformed,
}

/// Result of resolution: the chosen IP and how it was obtained.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedClientIp {
    pub ip: IpAddr,
    pub source: IpSource,
}

/// A parsed CIDR block (IPv4 or IPv6) supporting prefix-masked membership.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Cidr {
    V4(u32, u8),
    V6(u128, u8),
}

impl Cidr {
    /// Parse `"10.0.0.0/8"`, `"fd00::/8"`, or a bare address (`"::1"`,
    /// `"127.0.0.1"`) which implies a full-length prefix (/32 or /128).
    /// std parses the address (incl. compressed IPv6); only the prefix is ours.
    fn parse(s: &str) -> Option<Cidr> {
        let (addr_part, prefix_part) = match s.trim().split_once('/') {
            Some((a, p)) => (a.trim(), Some(p.trim())),
            None => (s.trim(), None),
        };
        match IpAddr::from_str(addr_part).ok()? {
            IpAddr::V4(a) => {
                let prefix = match prefix_part {
                    Some(p) => p.parse().ok().filter(|&p| p <= 32)?,
                    None => 32,
                };
                Some(Cidr::V4(u32::from(a), prefix))
            }
            IpAddr::V6(a) => {
                let prefix = match prefix_part {
                    Some(p) => p.parse().ok().filter(|&p| p <= 128)?,
                    None => 128,
                };
                Some(Cidr::V6(u128::from(a), prefix))
            }
        }
    }

    /// Membership test. A family mismatch (v4 vs v6) never matches.
    fn contains(&self, ip: IpAddr) -> bool {
        match (self, ip) {
            (Cidr::V4(net, prefix), IpAddr::V4(addr)) => mask_eq_u32(*net, u32::from(addr), *prefix),
            (Cidr::V6(net, prefix), IpAddr::V6(addr)) => {
                mask_eq_u128(*net, u128::from(addr), *prefix)
            }
            _ => false,
        }
    }
}

/// Top-`prefix`-bits comparison. The shift edges are handled EXPLICITLY:
/// `/0` → mask 0 (matches all), `/32` → full mask. This avoids `u32 << 32`,
/// which panics in debug builds.
fn mask_eq_u32(a: u32, b: u32, prefix: u8) -> bool {
    let mask = match prefix {
        0 => 0,
        32 => u32::MAX,
        p => u32::MAX << (32 - p),
    };
    (a & mask) == (b & mask)
}

/// IPv6 counterpart; `/0` → 0, `/128` → full mask (avoids `u128 << 128`).
fn mask_eq_u128(a: u128, b: u128, prefix: u8) -> bool {
    let mask = match prefix {
        0 => 0,
        128 => u128::MAX,
        p => u128::MAX << (128 - p),
    };
    (a & mask) == (b & mask)
}

/// True if `s` is a syntactically valid CIDR or bare IP (IPv4/IPv6). Used by
/// config validation to reject illegal `trusted_proxies` entries at startup
/// instead of silently dropping them at resolver-construction time.
pub fn is_valid_cidr(s: &str) -> bool {
    Cidr::parse(s).is_some()
}

/// Pre-compiled resolver: trusted CIDRs are parsed once at construction.
pub struct ClientIpResolver {
    trusted: Vec<Cidr>,
    header: String, // lowercased for case-insensitive lookup
    hops: usize,
}

impl ClientIpResolver {
    /// Build from config, parsing the trusted CIDRs once. Invalid CIDR strings
    /// are skipped (a misconfigured entry must not silently widen trust).
    pub fn from_config(cfg: &NetworkConfig) -> Self {
        let trusted = cfg.trusted_proxies.iter().filter_map(|s| Cidr::parse(s)).collect();
        Self {
            trusted,
            header: cfg.client_ip_header.to_ascii_lowercase(),
            hops: cfg.trusted_hops,
        }
    }

    /// Number of valid trusted CIDRs (lets the caller warn if some were dropped).
    pub fn trusted_count(&self) -> usize {
        self.trusted.len()
    }

    /// Resolve the real client IP from the peer address and request headers.
    pub fn resolve(&self, peer: IpAddr, headers: &[(String, String)]) -> ResolvedClientIp {
        // Steps 1 & 4: peer not trusted (or nothing trusted) → never trust XFF.
        if !self.trusted.iter().any(|c| c.contains(peer)) {
            return ResolvedClientIp { ip: peer, source: IpSource::DirectPeer };
        }

        // Step 3a: header absent behind a trusted proxy → fall back to peer.
        let Some(value) = self.header_value(headers) else {
            return ResolvedClientIp { ip: peer, source: IpSource::FallbackMissingHeader };
        };

        // The chain is "client, proxy1, proxy2" (left = closest to client = most
        // spoofable). Count `trusted_hops` from the RIGHT.
        let chain: Vec<&str> =
            value.split(',').map(str::trim).filter(|s| !s.is_empty()).collect();

        // Step 3b: chain shorter than the hops we trust (or hops=0) → fall back
        // to peer. Crucially we do NOT pick the leftmost available IP: that is the
        // first bypass an attacker would try (e.g. hops=2 but XFF="attacker").
        if self.hops == 0 || self.hops > chain.len() {
            return ResolvedClientIp { ip: peer, source: IpSource::FallbackMalformed };
        }

        let idx = chain.len() - self.hops;
        match IpAddr::from_str(chain[idx]) {
            Ok(ip) => ResolvedClientIp { ip, source: IpSource::TrustedHeader },
            // Step 3c: the trusted-position token is not an IP → fall back to peer.
            Err(_) => ResolvedClientIp { ip: peer, source: IpSource::FallbackMalformed },
        }
    }

    /// First header value matching the configured name (case-insensitive).
    fn header_value<'a>(&self, headers: &'a [(String, String)]) -> Option<&'a str> {
        headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(&self.header))
            .map(|(_, v)| v.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resolver(trusted: &[&str], hops: usize) -> ClientIpResolver {
        ClientIpResolver::from_config(&NetworkConfig {
            trusted_proxies: trusted.iter().map(|s| s.to_string()).collect(),
            client_ip_header: "x-forwarded-for".to_string(),
            trusted_hops: hops,
        })
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn xff(v: &str) -> Vec<(String, String)> {
        vec![("x-forwarded-for".to_string(), v.to_string())]
    }

    // ── CIDR masking edges ────────────────────────────────────────────────────

    #[test]
    fn cidr_v4_prefixes() {
        assert!(Cidr::parse("10.0.0.0/8").unwrap().contains(ip("10.255.1.2")));
        assert!(!Cidr::parse("10.0.0.0/8").unwrap().contains(ip("11.0.0.1")));
        // /32 exact (no shift overflow)
        assert!(Cidr::parse("127.0.0.1").unwrap().contains(ip("127.0.0.1")));
        assert!(!Cidr::parse("127.0.0.1").unwrap().contains(ip("127.0.0.2")));
        // /0 matches everything in-family
        assert!(Cidr::parse("0.0.0.0/0").unwrap().contains(ip("203.0.113.7")));
    }

    #[test]
    fn cidr_v6_prefixes() {
        assert!(Cidr::parse("::1").unwrap().contains(ip("::1")));
        assert!(!Cidr::parse("::1").unwrap().contains(ip("::2")));
        assert!(Cidr::parse("fd00::/8").unwrap().contains(ip("fd12:3456::1")));
        assert!(!Cidr::parse("fd00::/8").unwrap().contains(ip("fe80::1")));
        // /0 matches everything in-family
        assert!(Cidr::parse("::/0").unwrap().contains(ip("2001:db8::1")));
    }

    #[test]
    fn cidr_family_mismatch_never_matches() {
        assert!(!Cidr::parse("0.0.0.0/0").unwrap().contains(ip("::1")));
        assert!(!Cidr::parse("::/0").unwrap().contains(ip("1.2.3.4")));
    }

    #[test]
    fn invalid_cidr_is_skipped() {
        let r = resolver(&["not-an-ip", "10.0.0.0/8", "10.0.0.0/99"], 1);
        assert_eq!(r.trusted_count(), 1);
    }

    // ── resolution logic ──────────────────────────────────────────────────────

    #[test]
    fn untrusted_peer_uses_peer_ignoring_xff() {
        let r = resolver(&["10.0.0.0/8"], 1);
        let got = r.resolve(ip("203.0.113.9"), &xff("1.2.3.4"));
        assert_eq!(got.ip, ip("203.0.113.9"));
        assert_eq!(got.source, IpSource::DirectPeer);
    }

    #[test]
    fn trusted_peer_takes_hop_from_right_not_leftmost() {
        let r = resolver(&["10.0.0.0/8"], 1);
        // "attacker, real-lb": leftmost is attacker-controlled; hops=1 → real-lb.
        let got = r.resolve(ip("10.0.0.5"), &xff("attacker, 198.51.100.7"));
        assert_eq!(got.ip, ip("198.51.100.7"));
        assert_eq!(got.source, IpSource::TrustedHeader);
    }

    #[test]
    fn empty_trusted_proxies_always_uses_peer() {
        let r = resolver(&[], 1);
        let got = r.resolve(ip("10.0.0.5"), &xff("1.2.3.4"));
        assert_eq!(got.ip, ip("10.0.0.5"));
        assert_eq!(got.source, IpSource::DirectPeer);
    }

    #[test]
    fn malformed_xff_behind_trusted_falls_back_to_peer() {
        let r = resolver(&["10.0.0.0/8"], 1);
        let got = r.resolve(ip("10.0.0.5"), &xff("not-an-ip"));
        assert_eq!(got.ip, ip("10.0.0.5"));
        assert_eq!(got.source, IpSource::FallbackMalformed);
    }

    #[test]
    fn missing_header_behind_trusted_falls_back_to_peer() {
        let r = resolver(&["10.0.0.0/8"], 1);
        let got = r.resolve(ip("10.0.0.5"), &[]);
        assert_eq!(got.ip, ip("10.0.0.5"));
        assert_eq!(got.source, IpSource::FallbackMissingHeader);
    }

    #[test]
    fn chain_shorter_than_hops_never_picks_leftmost() {
        // The first bypass an attacker tries: hops=2 but only one IP present.
        // Must fall back to peer, NOT to "attacker".
        let r = resolver(&["10.0.0.0/8"], 2);
        let got = r.resolve(ip("10.0.0.5"), &xff("attacker"));
        assert_eq!(got.ip, ip("10.0.0.5"));
        assert_eq!(got.source, IpSource::FallbackMalformed);
    }

    #[test]
    fn ipv6_trusted_peer_reads_xff() {
        let r = resolver(&["::1"], 1);
        let got = r.resolve(ip("::1"), &xff("198.51.100.7"));
        assert_eq!(got.ip, ip("198.51.100.7"));
        assert_eq!(got.source, IpSource::TrustedHeader);
    }

    #[test]
    fn two_hops_selects_correct_position() {
        let r = resolver(&["10.0.0.0/8"], 2);
        // "client, real-lb, edge-lb" with hops=2 from the right → real-lb.
        let got = r.resolve(ip("10.0.0.5"), &xff("9.9.9.9, 198.51.100.7, 10.0.0.9"));
        assert_eq!(got.ip, ip("198.51.100.7"));
        assert_eq!(got.source, IpSource::TrustedHeader);
    }
}
