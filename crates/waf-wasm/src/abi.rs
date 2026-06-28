// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

//! Proxy-Wasm ABI constants (ABI v0.2.x).
//!
//! These mirror the `proxy-wasm` specification's integer enums so the host speaks the
//! exact contract a compiled Proxy-Wasm guest expects. We model only the values the v1
//! WAF subset uses or must recognise; the host returns [`Status::Unimplemented`] for
//! anything outside the subset (never a silent partial — policy D3=A, as in B2).

/// ABI version export the guest must declare. We accept either 0.2.0 or 0.2.1 (the SDKs
/// emit one of these as a marker export named `proxy_abi_version_0_2_0`/`_1`).
pub const ABI_VERSION_EXPORTS: &[&str] =
    &["proxy_abi_version_0_2_1", "proxy_abi_version_0_2_0"];

/// Guest allocator export names, newest first. Proxy-Wasm hosts call this to obtain a
/// region in guest linear memory before writing host-owned bytes into it.
pub const ALLOC_EXPORTS: &[&str] = &["proxy_on_memory_allocate", "malloc"];

/// `proxy_result_t` — the status every host function returns to the guest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum Status {
    Ok = 0,
    NotFound = 1,
    BadArgument = 2,
    SerializationFailure = 3,
    ParseFailure = 4,
    BadExpression = 5,
    InvalidMemoryAccess = 6,
    Empty = 7,
    CasMismatch = 8,
    ResultMismatch = 9,
    InternalFailure = 10,
    BrokenConnection = 11,
    Unimplemented = 12,
}

impl Status {
    /// The raw `i32` the guest reads as the host-call result.
    pub fn code(self) -> i32 {
        self as i32
    }
}

/// `proxy_action_t` — what a header/body callback tells the host to do next. In our
/// synchronous buffer-then-inspect model only `Continue` proceeds; `Pause` (streaming)
/// is treated as "continue" because the whole body is already buffered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum Action {
    Continue = 0,
    Pause = 1,
}

impl Action {
    pub fn from_i32(v: i32) -> Option<Action> {
        match v {
            0 => Some(Action::Continue),
            1 => Some(Action::Pause),
            _ => None,
        }
    }
}

/// `proxy_buffer_type_t` — which byte buffer `proxy_get_buffer_bytes` addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum BufferType {
    HttpRequestBody = 0,
    HttpResponseBody = 1,
    DownstreamData = 2,
    UpstreamData = 3,
    HttpCallResponseBody = 4,
    GrpcReceiveBuffer = 5,
    VmConfiguration = 6,
    PluginConfiguration = 7,
    CallData = 8,
}

impl BufferType {
    pub fn from_i32(v: i32) -> Option<BufferType> {
        use BufferType::*;
        Some(match v {
            0 => HttpRequestBody,
            1 => HttpResponseBody,
            2 => DownstreamData,
            3 => UpstreamData,
            4 => HttpCallResponseBody,
            5 => GrpcReceiveBuffer,
            6 => VmConfiguration,
            7 => PluginConfiguration,
            8 => CallData,
            _ => return None,
        })
    }
}

/// `proxy_map_type_t` — which header/trailer map a map host-call addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum MapType {
    HttpRequestHeaders = 0,
    HttpRequestTrailers = 1,
    HttpResponseHeaders = 2,
    HttpResponseTrailers = 3,
    GrpcReceiveInitialMetadata = 4,
    GrpcReceiveTrailingMetadata = 5,
    HttpCallResponseHeaders = 6,
    HttpCallResponseTrailers = 7,
}

impl MapType {
    pub fn from_i32(v: i32) -> Option<MapType> {
        use MapType::*;
        Some(match v {
            0 => HttpRequestHeaders,
            1 => HttpRequestTrailers,
            2 => HttpResponseHeaders,
            3 => HttpResponseTrailers,
            4 => GrpcReceiveInitialMetadata,
            5 => GrpcReceiveTrailingMetadata,
            6 => HttpCallResponseHeaders,
            7 => HttpCallResponseTrailers,
            _ => return None,
        })
    }
}

/// `proxy_log_level_t`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum LogLevel {
    Trace = 0,
    Debug = 1,
    Info = 2,
    Warn = 3,
    Error = 4,
    Critical = 5,
}

impl LogLevel {
    pub fn from_i32(v: i32) -> LogLevel {
        use LogLevel::*;
        match v {
            0 => Trace,
            1 => Debug,
            2 => Info,
            4 => Error,
            5 => Critical,
            _ => Warn, // 3 and anything unexpected map to Warn (conservative)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_codes_match_spec() {
        assert_eq!(Status::Ok.code(), 0);
        assert_eq!(Status::NotFound.code(), 1);
        assert_eq!(Status::Empty.code(), 7);
        assert_eq!(Status::Unimplemented.code(), 12);
    }

    #[test]
    fn enum_round_trips() {
        assert_eq!(BufferType::from_i32(7), Some(BufferType::PluginConfiguration));
        assert_eq!(BufferType::from_i32(99), None);
        assert_eq!(MapType::from_i32(0), Some(MapType::HttpRequestHeaders));
        assert_eq!(Action::from_i32(1), Some(Action::Pause));
        assert_eq!(LogLevel::from_i32(5), LogLevel::Critical);
        assert_eq!(LogLevel::from_i32(42), LogLevel::Warn);
    }
}
