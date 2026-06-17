//! Shared network helpers. Currently the trusted-proxy client-IP resolver,
//! reused by rate limiting, structured logging and future Geo/IP-reputation —
//! the real client IP is derived **once** and read by everyone from
//! `RequestContext::client_ip`.

mod client_ip;

pub use client_ip::{is_valid_cidr, ClientIpResolver, IpSource, ResolvedClientIp};
