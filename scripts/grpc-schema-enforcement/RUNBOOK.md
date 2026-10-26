<!-- SPDX-License-Identifier: Apache-2.0 -->
# Runbook — gRPC schema-enforcement (§4-B part 2)

Verifies the enterprise gRPC schema-enforcement module (`waf-modules-premium`): each unary gRPC
request message (protobuf) is validated against the app's **compiled schema** (a `FileDescriptorSet`
`.bin` from `protoc`/`buf`) via `prost-reflect` and injected as a `structural()` `WafModule`. The
`:path` (`/pkg.Service/Method`) selects the RPC's input type; the message bytes are decoded against
it. An unknown method scores `schema-grpc-unknown-method` (Critical); a message that won't decode
scores `schema-grpc-decode-error` (Warning); a message carrying a field not in the descriptor scores
`schema-grpc-unknown-field` **only when `flag_unknown_fields`** (opt-in — protobuf tolerates unknown
fields by design). Governance of the schema, not baseline detection — field content stays in the OPEN
§6 channel, the structural DoS caps in the OPEN `grpc` module (which runs first).

Two layers:
- **A. Offline suite** (`cargo test`, no environment) — unit + datapath bite-tests: descriptor load
  (boot-fatal on invalid), method resolution, decode, unknown-field opt-in, de-framing (skips
  compressed), the FP-guard, and a REAL-pipeline block/control. This is the authoritative gate.
- **B. Live wire check** (`check_grpc_schema_enforcement.sh`) — a running enterprise WAF with the
  module enabled, hit with raw gRPC frames over h2c (`curl --http2-prior-knowledge`).

---

## A. Offline suite

```sh
cargo test -p waf-modules-premium          # 41 unit (grpc: load/resolve/decode/unknown-field/de-frame/gating)
                                           # + 5 grpc_datapath (REAL pipeline: block/control/FP-guard)
cargo test -p waf-enterprise               # incl. 3 grpc_schema_enforcement config tests
```

## B. Live wire check

### B.1 Prereqs

- Build once: `cargo build -p waf-enterprise` (from `enterprise/`).
- `bash` + a `curl` with HTTP/2 (`curl --version` shows `HTTP2`).
- A compiled descriptor `app.bin`. Either compile the sample proto:

  ```sh
  protoc --include_imports --descriptor_set_out=app.bin scripts/grpc-schema-enforcement/greeter.proto
  # or:  buf build -o app.bin
  ```

  …or, **without protoc/buf**, emit the same demo descriptor from the crate:

  ```sh
  WAF_FDS_OUT=app.bin cargo test -p waf-modules-premium emit_fixture_descriptor -- --ignored --nocapture
  ```

### B.2 Node config (`grpc-node.toml`)

```toml
[proxy]
listen  = "127.0.0.1:8080"
backend = "http://127.0.0.1:3000"

[waf]
mode            = "blocking"
block_threshold = 5            # a single Critical unknown-method hit (severity 6) crosses this

[enterprise.grpc_schema_enforcement]
enabled         = true
descriptor_path = "app.bin"
# flag_unknown_fields   = false   # opt-in (forward-compat); leave off to avoid drift FPs
# decode_error_severity = "warning"
```

### B.3 Run

```sh
WAF_CONFIG=grpc-node.toml cargo run -p waf-enterprise
# boot log: "wiring gRPC schema-enforcement module (§4-B part 2)  descriptor=app.bin flag_unknown_fields=false"
# a missing/invalid descriptor_path is a FATAL boot error (fail-closed on config).
```

In another terminal (from `enterprise/`):

```sh
PORT=8080 scripts/grpc-schema-enforcement/check_grpc_schema_enforcement.sh
```

### B.4 What to observe

- The **unknown-method / unknown-service** rows → `[BLOCK ok ] … -> 403` (blocked before the backend).
- The **legitimate** rows → `[PASS ok  ]`: a valid message, a **compressed** (opaque → skipped) frame,
  and a message with an **unknown field** (tolerated with `flag_unknown_fields` off) all pass.
- Summary `failed: 0` and `gRPC schema-enforcement verified on the wire.`

### B.5 Optional — see the decode-error / unknown-field leaves block

`decode-error` is Warning and `unknown-field` is opt-in, so neither blocks under the default config.
To watch them block, raise their severity / enable the flag and send the matching frame:

```toml
[enterprise.grpc_schema_enforcement]
enabled = true
descriptor_path = "app.bin"
flag_unknown_fields   = true
decode_error_severity = "critical"
unknown_field_severity = "critical"
```

```sh
# malformed message on a known method → decode-error → 403
printf '\x00\x00\x00\x00\x02\x0a\xff' | curl -s -o /dev/null -w '%{http_code}\n' \
  --http2-prior-knowledge -H 'content-type: application/grpc' -H 'te: trailers' \
  --data-binary @- http://127.0.0.1:8080/test.v1.Greeter/SayHello
```

---

## Troubleshooting

- **Unknown-method rows MISS** — the module isn't active: check the boot log for `wiring gRPC
  schema-enforcement module`; confirm `enabled = true`, `mode = "blocking"`, `block_threshold <= 6`.
- **Boot fails with `gRPC schema-enforcement: cannot read descriptor file …`** — `descriptor_path` is
  wrong/missing. Deliberate fail-closed boot error, not a bug (relative paths resolve from the run dir).
- **Boot fails with `invalid FileDescriptorSet`** — the `.bin` is not a descriptor set (e.g. you passed
  the `.proto`). Recompile with `protoc --descriptor_set_out` / `buf build -o`.
- **A legit message is blocked (`FALSE +`)** — usually **schema drift** (the app's `.proto` is newer
  than `app.bin`). Rebuild the descriptor. With `flag_unknown_fields = true` a newer client's extra
  fields will score — that flag is opt-in precisely because protobuf allows unknown fields.
- **Everything MISSes with 000 / curl errors** — your `curl` lacks HTTP/2, or the WAF isn't serving h2c;
  confirm `curl --version` shows `HTTP2` and the WAF booted (`listening (enterprise)`).
