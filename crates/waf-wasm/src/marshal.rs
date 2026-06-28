// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

//! Pure (no-wasm) serialization between our request view and the Proxy-Wasm wire formats.
//!
//! Kept free of `wasmi` so it is unit-testable in isolation and fuzz-friendly (these are
//! the hand-rolled binary formats a malicious/buggy guest will poke at). The host module
//! ([`crate::host`]) does the linear-memory plumbing; this module only encodes/decodes.

/// A read-only snapshot of the request the host exposes to the guest. Owned (set per
/// checkout) so it can live in `Store` data across pooled requests; `body` is
/// `bytes::Bytes` (cheap, refcount-only clone).
#[derive(Debug, Clone, Default)]
pub struct RequestView {
    pub method: String,
    /// Path including query (Proxy-Wasm `request.path`).
    pub path: String,
    /// Path without query (Proxy-Wasm `request.url_path`).
    pub url_path: String,
    pub protocol: String,
    pub scheme: String,
    pub host: String,
    pub source_addr: String,
    /// Header names lowercased, values as received.
    pub headers: Vec<(String, String)>,
    pub body: bytes::Bytes,
}

/// Encode header pairs into the Proxy-Wasm header-map format:
/// ```text
///   i32  num_pairs                       (little-endian)
///   [ i32 key_len, i32 value_len ] * N   (little-endian, NOT counting the NUL)
///   ( key_bytes 0x00 value_bytes 0x00 ) * N
/// ```
pub fn encode_header_map_pairs(pairs: &[(String, String)]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(pairs.len() as u32).to_le_bytes());
    for (k, v) in pairs {
        out.extend_from_slice(&(k.len() as u32).to_le_bytes());
        out.extend_from_slice(&(v.len() as u32).to_le_bytes());
    }
    for (k, v) in pairs {
        out.extend_from_slice(k.as_bytes());
        out.push(0);
        out.extend_from_slice(v.as_bytes());
        out.push(0);
    }
    out
}

/// Decode the Proxy-Wasm header-map format. Used by tests (and, symmetrically, would let a
/// future `set_header_map_pairs` read guest-written maps). Returns `None` on a malformed
/// buffer rather than panicking (a guest controls these bytes).
pub fn decode_header_map_pairs(buf: &[u8]) -> Option<Vec<(Vec<u8>, Vec<u8>)>> {
    let read_u32 = |b: &[u8], off: usize| -> Option<usize> {
        let slice = b.get(off..off + 4)?;
        Some(u32::from_le_bytes(slice.try_into().ok()?) as usize)
    };
    let num = read_u32(buf, 0)?;
    let mut sizes = Vec::with_capacity(num);
    let mut off = 4;
    for _ in 0..num {
        let kl = read_u32(buf, off)?;
        let vl = read_u32(buf, off + 4)?;
        off += 8;
        sizes.push((kl, vl));
    }
    let mut out = Vec::with_capacity(num);
    for (kl, vl) in sizes {
        let key = buf.get(off..off + kl)?.to_vec();
        off += kl;
        if buf.get(off) != Some(&0) {
            return None; // missing key NUL terminator
        }
        off += 1;
        let val = buf.get(off..off + vl)?.to_vec();
        off += vl;
        if buf.get(off) != Some(&0) {
            return None; // missing value NUL terminator
        }
        off += 1;
        out.push((key, val));
    }
    Some(out)
}

/// Resolve a Proxy-Wasm property path to a byte value. The guest passes the path as
/// NUL-separated segments (e.g. `request\0path`). Unknown paths return `None` (the host
/// then answers `Status::NotFound`). v1 covers the request-time properties a WAF filter
/// commonly reads; the rest are out of subset.
pub fn resolve_property(path: &[u8], req: &RequestView) -> Option<Vec<u8>> {
    let segs: Vec<&[u8]> = path.split(|&b| b == 0).filter(|s| !s.is_empty()).collect();
    let s: Vec<&str> = segs.iter().filter_map(|b| std::str::from_utf8(b).ok()).collect();
    let val: &str = match s.as_slice() {
        ["request", "path"] => &req.path,
        ["request", "url_path"] => &req.url_path,
        ["request", "method"] => &req.method,
        ["request", "protocol"] => &req.protocol,
        ["request", "scheme"] => &req.scheme,
        ["request", "host"] => &req.host,
        ["source", "address"] => &req.source_addr,
        // A header lookup: `request.headers.<name>`.
        ["request", "headers", name] => {
            return header_value(&req.headers, name).map(|v| v.as_bytes().to_vec());
        }
        _ => return None,
    };
    Some(val.as_bytes().to_vec())
}

/// Case-insensitive header lookup (names are stored lowercased).
pub fn header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a String> {
    let lname = name.to_ascii_lowercase();
    headers.iter().find(|(k, _)| *k == lname).map(|(_, v)| v)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn view() -> RequestView {
        RequestView {
            method: "POST".into(),
            path: "/login?next=/x".into(),
            url_path: "/login".into(),
            protocol: "HTTP/1.1".into(),
            scheme: "http".into(),
            host: "example.test".into(),
            source_addr: "203.0.113.7:4444".into(),
            headers: vec![
                ("content-type".into(), "application/json".into()),
                ("x-block".into(), "1".into()),
            ],
            body: bytes::Bytes::from_static(b"payload"),
        }
    }

    #[test]
    fn header_map_round_trip() {
        let pairs = vec![
            ("content-type".to_string(), "application/json".to_string()),
            ("x-block".to_string(), "1".to_string()),
        ];
        let enc = encode_header_map_pairs(&pairs);
        let dec = decode_header_map_pairs(&enc).unwrap();
        assert_eq!(dec.len(), 2);
        assert_eq!(dec[0].0, b"content-type");
        assert_eq!(dec[0].1, b"application/json");
        assert_eq!(dec[1].0, b"x-block");
        assert_eq!(dec[1].1, b"1");
    }

    #[test]
    fn empty_header_map() {
        let enc = encode_header_map_pairs(&[]);
        assert_eq!(enc, 0u32.to_le_bytes());
        assert_eq!(decode_header_map_pairs(&enc).unwrap().len(), 0);
    }

    #[test]
    fn decode_rejects_truncated_buffer() {
        let mut enc = encode_header_map_pairs(&[("a".into(), "b".into())]);
        enc.truncate(enc.len() - 3); // chop the value + its NUL
        assert!(decode_header_map_pairs(&enc).is_none());
    }

    #[test]
    fn decode_rejects_missing_nul() {
        // Hand-build a 1-pair buffer where the key NUL is replaced by a non-zero byte.
        let mut enc = Vec::new();
        enc.extend_from_slice(&1u32.to_le_bytes());
        enc.extend_from_slice(&1u32.to_le_bytes()); // key_len
        enc.extend_from_slice(&1u32.to_le_bytes()); // val_len
        enc.extend_from_slice(b"kXv\x00"); // 'k', then 'X' where the NUL should be
        assert!(decode_header_map_pairs(&enc).is_none());
    }

    #[test]
    fn property_resolution() {
        let r = view();
        assert_eq!(resolve_property(b"request\0path", &r).unwrap(), b"/login?next=/x");
        assert_eq!(resolve_property(b"request\0url_path", &r).unwrap(), b"/login");
        assert_eq!(resolve_property(b"request\0method", &r).unwrap(), b"POST");
        assert_eq!(resolve_property(b"source\0address", &r).unwrap(), b"203.0.113.7:4444");
        assert_eq!(resolve_property(b"request\0headers\0x-block", &r).unwrap(), b"1");
        assert!(resolve_property(b"request\0nonsense", &r).is_none());
        assert!(resolve_property(b"connection\0id", &r).is_none());
    }
}
