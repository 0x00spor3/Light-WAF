<!-- SPDX-License-Identifier: BUSL-1.1 -->
# Runbook — demo/trial license gate

Cuts **time-limited demo builds** of the three enterprise binaries (`waf-enterprise`, `waf-node-agent`,
`waf-controlplane`) with **every feature unlocked** but a hard expiry: past the date each binary logs
`licenza demo scaduta` and stops.

**How it works.** The gate lives in the enterprise-only crate `waf-license` (zero-core, zero-datapath).
A demo build (feature `demo-license`) checks a signed `license.json` at boot and again on a background
watchdog. The license is signed with **Ed25519** by *your* private seed; only the matching public key
is compiled into the binary, so a prospect can neither change the expiry (breaks the signature) nor
mint their own (no seed).

**Posture.** Fail-closed: missing / tampered / wrong-key license → `licenza demo non valida` + exit;
past expiry → `licenza demo scaduta` + exit. A plain build (no `demo-license` feature) carries **no**
license logic at all — this is only for demo artifacts.

**Threat model (be honest with yourself).** This is a *client-side* gate. Whoever controls the demo
machine, its clock and the binary can bypass it. The goal is to stop *casual* continued use of a demo
and prompt a purchase — not to stop a determined attacker. No obfuscation, no phone-home by design.

---

## 1. One-time: mint your signing keypair (offline)

```sh
cd enterprise
cargo run -q -p waf-license --bin waf-license-keygen
# WAF_LICENSE_SIGNING_KEY=<64 hex>   ← SECRET. Keep it off the demo machines; never commit it.
# LICENSE_PUBKEY_HEX=<64 hex>        ← the trust anchor to bake into the demo build.
```

Keep the **seed** in your vault. The **public key** goes into the build (step 3).

## 2. Issue a license for a prospect

```sh
export WAF_LICENSE_SIGNING_KEY=<your-seed-hex>
cargo run -q -p waf-license --bin waf-license-sign -- \
  --issued-to "Acme Corp — POC" --days 30 --out license.json
```

`--days 30` = valid one month from now. Ship `license.json` alongside the binaries. `features` is
`["*"]` (everything on); v1 enforces only the expiry.

## 3. Build the demo binaries (license gate on, real key baked in)

Bake the public key at compile time via `WAF_LICENSE_PUBKEY` (or edit `LICENSE_PUBKEY_HEX` in
`waf-license/src/lib.rs`):

```sh
export WAF_LICENSE_PUBKEY=<your-pubkey-hex>
cargo build --release -p waf-enterprise   --features demo-license
cargo build --release -p waf-node-agent   --features demo-license
cargo build --release -p waf-controlplane --features demo-license   # add embed-ui for the single-binary UI
```

The normal (paying) build is just the same commands **without** `--features demo-license` and without
`WAF_LICENSE_PUBKEY` — it contains no expiry.

## 4. Run

Each binary looks for `license.json` in its working directory (override with `WAF_LICENSE_FILE`) and
keeps an anti-rollback heartbeat in `.license.state` (override with `WAF_LICENSE_STATE`).

- Valid → `{"message":"licenza demo valida","expires_at":...}` then normal startup.
- Expired / invalid → logs and exits with code 2.

Paths:

| env | default | meaning |
|-----|---------|---------|
| `WAF_LICENSE_FILE`  | `license.json`    | the signed license |
| `WAF_LICENSE_STATE` | `.license.state`  | monotonic heartbeat (rollback guard) |

---

## 5. Verify it works (bite-test)

```sh
cd enterprise
# Unit tests (pure): sign→verify→tamper→wrong-key→expired→rollback.
cargo test -p waf-license

# End-to-end on the lightest binary:
KEYS=$(cargo run -q -p waf-license --bin waf-license-keygen)
SEED=$(printf '%s\n' "$KEYS" | sed -n 's/^WAF_LICENSE_SIGNING_KEY=//p')
PUB=$( printf '%s\n' "$KEYS" | sed -n 's/^LICENSE_PUBKEY_HEX=//p')

WAF_LICENSE_SIGNING_KEY=$SEED cargo run -q -p waf-license --bin waf-license-sign -- \
  --issued-to "Bite" --days -1 --out /tmp/expired.json      # already expired
WAF_LICENSE_PUBKEY=$PUB cargo build -p waf-node-agent --features demo-license

( cd /tmp && cp expired.json license.json && \
  "$OLDPWD/target/debug/waf-node-agent" ; echo "exit=$?" )
# → {"message":"licenza demo scaduta"} ; exit=2
```

A `--days 30` license instead logs `licenza demo valida` and proceeds to normal startup.

## Notes / limits

- **Anti-rollback** is best-effort (a plaintext high-water-mark file); it stops a naive clock rollback,
  not disk edits.
- Expiry is checked at boot and every 15 min by the watchdog; a long-running demo stops mid-run when
  the month elapses.
- Follow-on (not built): per-feature entitlements (the `features` field is already there), a bound
  hostname/fingerprint, a phone-home license server.
