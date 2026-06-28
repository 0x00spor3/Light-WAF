# Example WASM plugin — custom denylist filter

A small, real [Proxy-Wasm](https://github.com/proxy-wasm/spec) filter you can build and load
into the WAF's WASM runtime (B3). It blocks (HTTP 403) any request whose **path**,
**`User-Agent`**, or **body** contains one of a configurable list of substrings, plus an
explicit **`X-Block`** kill-switch header. Source: [`src/lib.rs`](src/lib.rs).

It's the canonical way to add an app-specific rule **without forking the core**: write a
filter, compile it to `.wasm`, point a config entry at it.

## 1. Build

```sh
rustup target add wasm32-unknown-unknown          # once
cd examples/wasm-plugin
cargo build --release --target wasm32-unknown-unknown
# → target/wasm32-unknown-unknown/release/waf_wasm_example.wasm
```

## 2. Wire it into a WAF config

Add a `[modules.wasm]` block to your `config.toml` (see the documented one in
[`../strict.toml`](../strict.toml)). The `config` string is passed verbatim to the plugin —
here a comma-separated, case-insensitive denylist:

```toml
[modules.wasm]
enabled = true

[[modules.wasm.plugins]]
path   = "examples/wasm-plugin/target/wasm32-unknown-unknown/release/waf_wasm_example.wasm"
config = "/admin,sqlmap,union select,../"
```

Then run the proxy:

```sh
cargo run -p waf-proxy -- --config examples/balanced.toml   # with the block above added
```

## 3. Test it on the wire

With the denylist `"/admin,sqlmap,union select,../"`:

```sh
# Blocked — path matches "/admin"
curl -i http://127.0.0.1:8080/admin/users

# Blocked — User-Agent matches "sqlmap"
curl -i -H 'User-Agent: sqlmap/1.7' http://127.0.0.1:8080/

# Blocked — body matches "union select"
curl -i -X POST --data 'q=1 UNION SELECT password FROM users' http://127.0.0.1:8080/search

# Blocked — explicit kill switch
curl -i -H 'X-Block: 1' http://127.0.0.1:8080/

# Allowed — nothing matches
curl -i http://127.0.0.1:8080/home
```

A blocked request returns `403` (in `blocking` mode) with an `x-blocked-by: waf-wasm-example`
header; in `detection-only` mode it is logged but not blocked, like every other module. The
plugin's `proxy_send_local_response` is **captured** by the WAF and turned into a decision —
the plugin never writes the response wire itself.

## Notes

- **DoS is bounded by the runtime**, not the plugin: `fuel_per_request` caps CPU/latency,
  `max_memory_bytes` caps memory, and any trap fails closed (`500`). See
  [`ARCHITECTURE.md`](../../ARCHITECTURE.md) §9.
- **Host surface used**: plugin config, request headers (incl. the injected `:path`
  pseudo-header), the request body buffer, `send_http_response`, and logging — all in the v1
  implemented subset. Host calls outside the subset (network egress, shared data, header
  mutation…) return `Unimplemented`; if a plugin actually invokes one, the WAF logs it as
  degraded at runtime.
- This same `.wasm` is also what the env-gated ABI-fidelity smoke can load
  (`WAF_WASM_FIXTURE=…/waf_wasm_example.wasm cargo test -p waf-wasm --test smoke`).
