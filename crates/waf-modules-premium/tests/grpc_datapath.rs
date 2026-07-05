// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: BUSL-1.1

//! STEP-0 datapath bite-test (gRPC): the schema-enforcement module, loaded as a `WafModule`, BLOCKS
//! an unknown-method gRPC request on the REAL pipeline — and the SAME request with no module passes
//! (control). Also proves the fail-safe: a schema-valid message passes even WITH the module on, and
//! a non-gRPC request / default-off is inert.

use prost::Message;
use waf_core::{Bytes, Config, Normalized, ParsedBody, RequestContext, WafMode};
use waf_modules_premium::{grpc::GrpcSchemaModule, rules};
use waf_pipeline::{Pipeline, PipelineVerdict};

/// Compile the fixture `.proto` to FileDescriptorSet bytes (no `protoc` — protox), mirroring the
/// real flow (operator ships a compiled `.bin`).
fn fixture_fds() -> Vec<u8> {
    // Unique per call: parallel tests in one process would race on a PID-only dir.
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "waf-grpc-dp-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let proto = dir.join("greeter.proto");
    std::fs::write(
        &proto,
        r#"
            syntax = "proto3";
            package test.v1;
            message HelloRequest { string name = 1; }
            message HelloReply { string message = 1; }
            service Greeter { rpc SayHello(HelloRequest) returns (HelloReply); }
        "#,
    )
    .unwrap();
    let fds = protox::compile([&proto], [&dir]).expect("compile proto");
    let _ = std::fs::remove_dir_all(&dir);
    fds.encode_to_vec()
}

/// One uncompressed gRPC frame: `[0][len:4 BE][msg]`.
fn frame(msg: &[u8]) -> Vec<u8> {
    let mut b = vec![0u8];
    b.extend_from_slice(&(msg.len() as u32).to_be_bytes());
    b.extend_from_slice(msg);
    b
}

/// One COMPRESSED gRPC frame: `[1][len:4 BE][opaque]` (payload not inspectable).
fn compressed_frame(payload: &[u8]) -> Vec<u8> {
    let mut b = vec![1u8];
    b.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    b.extend_from_slice(payload);
    b
}

fn blocking_config() -> Config {
    let mut c = Config::default();
    c.waf.mode = WafMode::Blocking;
    c.waf.block_threshold = 5; // a single Critical unknown-method hit (severity 6) crosses this
    c
}

fn grpc_request(path: &str, body: Vec<u8>) -> RequestContext {
    let normalized = Normalized {
        path: path.to_string(),
        headers: vec![("content-type".to_string(), "application/grpc".to_string())],
        body: ParsedBody::Raw(Bytes::from(body)),
        ..Default::default()
    };
    RequestContext {
        client_ip: "203.0.113.10".parse().unwrap(),
        request_id: "bite".to_string(),
        timestamp: std::time::SystemTime::now(),
        method: "POST".to_string(),
        path: path.to_string(),
        raw_path: path.to_string(),
        query: None,
        http_version: "HTTP/2".to_string(),
        headers: vec![],
        cookies: vec![],
        body: Bytes::new(),
        normalized,
        score: 0,
        score_contributions: vec![],
    }
}

// HelloRequest { name = "x" } → field 1, wire-type 2, len 1, 'x'.
const VALID_MSG: [u8; 3] = [0x0a, 0x01, b'x'];

#[test]
fn unknown_method_blocks_on_the_pipeline_but_control_without_the_module_passes() {
    let config = blocking_config();
    let fds = fixture_fds();
    let req = || grpc_request("/test.v1.Greeter/DoesNotExist", frame(&VALID_MSG));

    let module = GrpcSchemaModule::from_fds_bytes(&fds, true).expect("valid fds");
    let pipe = Pipeline::new(&config, vec![Box::new(module)]);
    let mut ctx = req();
    let verdict = pipe.run(&mut ctx);
    assert!(
        !matches!(verdict, PipelineVerdict::Allow),
        "unknown-method gRPC request must block on the datapath (got {verdict:?})"
    );
    assert!(
        ctx.score_contributions.iter().any(|c| c.rule_id == rules::GRPC_UNKNOWN_METHOD.id()),
        "the block must be attributed to the gRPC schema rule"
    );

    let bare = Pipeline::new(&config, vec![]);
    let mut ctx_ctrl = req();
    assert!(
        matches!(bare.run(&mut ctx_ctrl), PipelineVerdict::Allow),
        "without the module the same request must pass (control)"
    );
}

#[test]
fn valid_message_passes_even_with_the_module_on() {
    let config = blocking_config();
    let module = GrpcSchemaModule::from_fds_bytes(&fixture_fds(), true).expect("valid fds");
    let pipe = Pipeline::new(&config, vec![Box::new(module)]);
    let mut ctx = grpc_request("/test.v1.Greeter/SayHello", frame(&VALID_MSG));
    assert!(
        matches!(pipe.run(&mut ctx), PipelineVerdict::Allow),
        "a schema-valid gRPC message must not be flagged (fail-safe / no FP)"
    );
}

#[test]
fn default_off_never_contributes() {
    let config = blocking_config();
    let module = GrpcSchemaModule::from_fds_bytes(&fixture_fds(), false).expect("valid fds");
    let pipe = Pipeline::new(&config, vec![Box::new(module)]);
    let mut ctx = grpc_request("/test.v1.Greeter/DoesNotExist", frame(&VALID_MSG));
    assert!(
        matches!(pipe.run(&mut ctx), PipelineVerdict::Allow),
        "disabled module must be inert even on an unknown-method request"
    );
}

#[test]
fn legit_grpc_messages_pass_through_the_pipeline() {
    // FP-guard end-to-end (module ON, blocking): traffic a real client sends must NOT be flagged.
    let config = blocking_config();
    let module = GrpcSchemaModule::from_fds_bytes(&fixture_fds(), true).expect("valid fds");
    let pipe = Pipeline::new(&config, vec![Box::new(module)]);

    // A valid HelloRequest on a known method.
    let mut a = grpc_request("/test.v1.Greeter/SayHello", frame(&VALID_MSG));
    assert!(matches!(pipe.run(&mut a), PipelineVerdict::Allow), "valid message must pass");

    // A message carrying a field NOT in the descriptor (field 5) — with the default (flag off),
    // protobuf forward-compat means a newer client legitimately sends it → must NOT be flagged.
    let unknown_field_msg = [0x0a, 0x01, b'x', 0x2a, 0x01, b'y'];
    let mut b = grpc_request("/test.v1.Greeter/SayHello", frame(&unknown_field_msg));
    assert!(
        matches!(pipe.run(&mut b), PipelineVerdict::Allow),
        "unknown field with flagging off must pass (forward-compat)"
    );

    // A COMPRESSED frame is opaque → skipped, never a decode-error FP.
    let mut c = grpc_request("/test.v1.Greeter/SayHello", compressed_frame(&[0xde, 0xad, 0xbe, 0xef]));
    assert!(matches!(pipe.run(&mut c), PipelineVerdict::Allow), "compressed frame must pass");

    // Two valid frames (client-streaming-style batch) → still clean.
    let mut two = frame(&VALID_MSG);
    two.extend_from_slice(&frame(&VALID_MSG));
    let mut d = grpc_request("/test.v1.Greeter/SayHello", two);
    assert!(matches!(pipe.run(&mut d), PipelineVerdict::Allow), "multiple valid frames must pass");
}

#[test]
fn non_grpc_request_is_ignored() {
    let config = blocking_config();
    let module = GrpcSchemaModule::from_fds_bytes(&fixture_fds(), true).expect("valid fds");
    let pipe = Pipeline::new(&config, vec![Box::new(module)]);
    // A plain request (no application/grpc content-type) must not be inspected as gRPC.
    let mut ctx = grpc_request("/test.v1.Greeter/DoesNotExist", frame(&VALID_MSG));
    ctx.normalized.headers = vec![("content-type".to_string(), "application/json".to_string())];
    assert!(matches!(pipe.run(&mut ctx), PipelineVerdict::Allow));
}
