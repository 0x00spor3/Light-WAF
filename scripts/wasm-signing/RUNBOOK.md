<!-- SPDX-License-Identifier: Apache-2.0 -->
# Runbook — signed WASM plugin loader (§4-C)

Verifies the enterprise signed-plugin loader (`waf-marketplace`): a Proxy-Wasm plugin is loaded ONLY
after a detached **minisign (ed25519)** signature over the exact `.wasm` bytes verifies against a
configured trusted key. The OPEN runtime (`waf-wasm`) and its unsigned `[modules.wasm]` loader are
unchanged; this adds the **trust gate** on top.

**Posture (K5).** Unlike the OPEN loader (a broken UNSIGNED plugin is skipped), a SIGNED plugin whose
signature does not verify is **boot-fatal / fail-closed** — it is indistinguishable from tampering.

Two layers:
- **A. Offline suite** (`cargo test`) — unit (verify: valid / tampered / wrong-key / malformed /
  no-keys; the `exclusive` conflict predicate) + an **env-gated** real-plugin bite-test
  (`WAF_WASM_FIXTURE`): sign a real plugin, load it through the gate, watch its verdict flow on the
  REAL pipeline, and confirm tampering / wrong-key are refused.
- **B. Live wire check** (`check_wasm_signing.sh`) — a running enterprise WAF with a signed plugin;
  the plugin's `X-Block` kill-switch blocks on the wire (that it loaded at all proves the signature).

---

## A. Offline suite

```sh
cargo test -p waf-marketplace          # 8 unit (minisign verify + gate ordering)
cargo test -p waf-enterprise           # incl. wasm config + exclusive_conflict tests

# Env-gated bite-test with a REAL plugin (build the B3 example once if needed):
#   (cd ../examples/wasm-plugin && cargo build --release --target wasm32-unknown-unknown)
WAF_WASM_FIXTURE=../examples/wasm-plugin/target/wasm32-unknown-unknown/release/waf_wasm_example.wasm \
  cargo test -p waf-marketplace --test datapath
```

## B. Live wire check

### B.1 Prereqs

- Build once: `cargo build -p waf-enterprise` and the example plugin (above) → `waf_wasm_example.wasm`.
- **Sign the plugin.** With the real tool: `minisign -Sm waf_wasm_example.wasm` (creates
  `waf_wasm_example.wasm.minisig`; the public key line goes in `trusted_keys`). **Without minisign**,
  use the crate helper — it writes the `.minisig` and prints the `trusted_keys` line:

  ```sh
  WAF_WASM_IN=waf_wasm_example.wasm WAF_SIG_OUT=plugin.minisig \
    cargo test -p waf-marketplace sign_plugin -- --ignored --nocapture
  # → wrote signature to plugin.minisig
  # → trusted_keys = ["RWQ...base64..."]
  ```

- A dummy backend (benign requests get a 200): `python3 -m http.server 3000`.

### B.2 Node config (`wasm-node.toml`)

```toml
[proxy]
listen  = "127.0.0.1:8080"
backend = "http://127.0.0.1:3000"

[waf]
mode = "blocking"

[enterprise.wasm]
enabled      = true
# exclusive  = true                      # optional: refuse to boot if [modules.wasm] loads unsigned plugins
trusted_keys = ["RWQ...paste the printed key..."]
[[enterprise.wasm.plugins]]
wasm_path = "waf_wasm_example.wasm"
sig_path  = "plugin.minisig"
```

### B.3 Run

```sh
WAF_CONFIG=wasm-node.toml cargo run -p waf-enterprise
# boot log: "wiring signed WASM plugin (§4-C, signature verified)  plugin=waf_wasm_example"
# a BAD/absent signature is a FATAL boot error — the WAF refuses to start.
```

```sh
PORT=8080 scripts/wasm-signing/check_wasm_signing.sh
```

### B.4 What to observe

- The **X-Block** row → `[BLOCK ok ] … -> 403` (the verified plugin's verdict on the wire).
- The **benign** row → `[PASS ok  ] … -> 200`.
- To prove **fail-closed**: tamper one byte of the `.wasm` (or use a stale `.minisig`) and restart —
  the WAF **refuses to boot** (`signed WASM plugin … signature does not verify`), it does not run
  unprotected.

---

## Troubleshooting

- **WAF refuses to boot: `signature does not verify against any trusted key`** — the `.minisig` does
  not match the `.wasm` under any `trusted_keys` entry: re-sign, or fix the pasted key. This is the
  intended fail-closed behaviour (K5), not a bug.
- **Boot: `no trusted_keys — nothing can verify`** — `[enterprise.wasm].enabled` but `trusted_keys` is
  empty; add the public key line.
- **Boot: `exclusive = true but [modules.wasm] loads N unsigned plugin(s)`** — remove the OPEN
  `[modules.wasm]` plugins (or drop `exclusive`): the flag enforces "signed plugins only".
- **X-Block MISSes** — the plugin loaded but the request shape isn't matching; confirm the boot log
  shows the plugin wired, and that you sent the `X-Block` header.
