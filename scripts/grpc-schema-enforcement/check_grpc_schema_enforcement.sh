#!/usr/bin/env bash
# SPDX-License-Identifier: BUSL-1.1
#
# check_grpc_schema_enforcement.sh — fire a battery of raw gRPC frames at a running enterprise WAF
# and confirm an unknown-method call is BLOCKED (schema-grpc-unknown-method, Critical) while
# legitimate traffic — a valid message, a compressed (opaque) frame, and a message carrying an
# unknown field (tolerated by default, forward-compat) — passes.
#
# We send the framed gRPC body over h2c with `curl --http2-prior-knowledge`, so we control the exact
# bytes and the `:path` (no gRPC client / reflection needed). A gRPC frame is
# `[compressed-flag:1][length:4 big-endian][message]`.
#
# The module (`[enterprise.grpc_schema_enforcement]`) must be ENABLED with `descriptor_path` at the
# compiled `app.bin`, WAF in `mode = "blocking"`, `block_threshold <= 6`. Blocked calls never reach
# the backend, so the backend can be absent for the attack rows.
#
# NOTE: a malformed message scores `schema-grpc-decode-error` (Warning) — additive, it does NOT block
# on its own at block_threshold=5 (see RUNBOOK B.5 to force it). Unknown-field flagging is opt-in.
#
# Env (defaults):  HOST [127.0.0.1]  PORT [8080]  TIMEOUT [5]  BLOCK_CODE [403]
set -uo pipefail

HOST="${HOST:-127.0.0.1}"
PORT="${PORT:-8080}"
TIMEOUT="${TIMEOUT:-5}"
BLOCK_CODE="${BLOCK_CODE:-403}"
BASE="http://${HOST}:${PORT}"

pass=0
fail=0

# HelloRequest{name:"x"} = 0a 01 78 ; framed (len 3) = 00 00000003 0a 01 78
VALID_FRAME='\x00\x00\x00\x00\x03\x0a\x01\x78'
# field 1 length-delimited claiming 255 bytes but truncated → decode error ; framed len 2
MALFORMED_FRAME='\x00\x00\x00\x00\x02\x0a\xff'
# HelloRequest{name:"x"} + unknown field 5 (2a 01 79) ; framed len 6
UNKNOWN_FIELD_FRAME='\x00\x00\x00\x00\x06\x0a\x01\x78\x2a\x01\x79'
# a COMPRESSED frame (flag=1) with opaque payload ; framed len 2
COMPRESSED_FRAME='\x01\x00\x00\x00\x02\xde\xad'

# grpc_send <path> <printf-frame> → HTTP status code.
grpc_send() {
  printf "$2" | curl -s -o /dev/null -w '%{http_code}' --max-time "$TIMEOUT" \
    --http2-prior-knowledge \
    -H 'content-type: application/grpc' -H 'te: trailers' \
    --data-binary @- "${BASE}$1" 2>/dev/null || echo 000
}

expect_block() {
  local name=$1 code; code=$(grpc_send "$2" "$3")
  if [[ "$code" == "$BLOCK_CODE" ]]; then
    printf '  [BLOCK ok ] %-40s -> %s\n' "$name" "$code"; pass=$((pass + 1))
  else
    printf '  [MISS     ] %-40s -> %s (expected %s)\n' "$name" "$code" "$BLOCK_CODE"; fail=$((fail + 1))
  fi
}

expect_pass() {
  local name=$1 code; code=$(grpc_send "$2" "$3")
  if [[ "$code" != "$BLOCK_CODE" ]]; then
    printf '  [PASS ok  ] %-40s -> %s\n' "$name" "$code"; pass=$((pass + 1))
  else
    printf '  [FALSE +  ] %-40s -> %s (blocked legit gRPC!)\n' "$name" "$code"; fail=$((fail + 1))
  fi
}

echo "Target: ${BASE}  (block code = ${BLOCK_CODE})"
echo
echo "Schema-INVALID — must BLOCK (schema-grpc-unknown-method, Critical):"
expect_block "unknown method"        "/test.v1.Greeter/DoesNotExist" "$VALID_FRAME"
expect_block "unknown service"       "/test.v1.Unknown/SayHello"     "$VALID_FRAME"

echo
echo "Legitimate — must PASS (no false positive):"
expect_pass  "valid message"         "/test.v1.Greeter/SayHello"     "$VALID_FRAME"
expect_pass  "compressed frame"      "/test.v1.Greeter/SayHello"     "$COMPRESSED_FRAME"
expect_pass  "unknown field (flag off)" "/test.v1.Greeter/SayHello"  "$UNKNOWN_FIELD_FRAME"

echo
echo "passed: ${pass}   failed: ${fail}"
if [[ "$fail" -eq 0 ]]; then
  echo "gRPC schema-enforcement verified on the wire."
  exit 0
else
  echo "FAILURES above — see RUNBOOK.md Troubleshooting."
  exit 1
fi
