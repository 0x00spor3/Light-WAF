<!-- SPDX-License-Identifier: BUSL-1.1 -->
# Runbook — curated premium CRS ruleset (§6)

Verifies the enterprise curated ruleset (`waf-crs-curated`): the premium `SecRule` CONTENT
(category signatures + named CVEs) loaded through the OPEN CRS engine and injected as a `WafModule`.

Two layers:
- **A. Offline suite** (`cargo test`, no environment needed) — the compat/coverage **gate** (every
  rule loads, nothing silently skipped, one bite-test per rule) plus the datapath bite-test. This is
  the CI-level proof and runs anywhere.
- **B. Live wire check** (`check_curated_rules.sh`) — a running enterprise WAF with the module
  enabled, hit with a battery of real payloads (Log4Shell, Joomla JCE, SharePoint ToolShell, …) that
  must be BLOCKED, plus a benign control that must pass. This is the "needs an environment" test —
  the analogue of the §3 Redis env-gated run (there is no `WAF_*`-gated cargo test here; the gate is
  offline).

---

## A. Offline suite

```sh
cd enterprise
cargo test -p waf-crs-curated
# gate.rs (31): 1 load-gate + 28 per-rule bite-tests + 1 obfuscation FP-trap + 1 benign control ; datapath.rs: 2 pipeline
# block/control ; lib: 1 embed sanity
```

What it proves (the enterprise value — a *guaranteed-compatible, tested* ruleset):
- `all_curated_rules_load_and_nothing_is_silently_skipped` — the engine loads exactly
  `EXPECTED_LOADED` (28) rules with **zero** skipped. If a future edit reaches outside the supported
  subset (which the engine would *skip*, not load) this fails — no silent coverage loss.
- one bite-test per rule — each signature fires on its payload with the declared severity.
- `datapath.rs` — the module, on the REAL pipeline, blocks a Log4Shell request; the same request
  with no curated module passes (control) — proving the module is what blocks.

## B. Live wire check

### B.1 Prereqs

- Build once: `cargo build -p waf-enterprise` (repo root: `enterprise/`).
- `bash` + `curl`. A dummy backend (so benign requests get a 200, not a 502):

```sh
python3 -m http.server 3000
```

### B.2 Node config (`crs-node.toml`)

```toml
[proxy]
listen  = "127.0.0.1:8080"
backend = "http://127.0.0.1:3000"

[waf]
mode            = "blocking"   # detection-only would LOG, not actually block
block_threshold = 5            # a single CRITICAL curated hit (severity 6) crosses this

[enterprise.crs_curated]
enabled = true                 # load the curated premium ruleset
```

### B.3 Run

```sh
WAF_CONFIG=crs-node.toml cargo run -p waf-enterprise
# boot log: "wiring curated premium CRS ruleset: CRS import: 28 rules loaded, 0 skipped"
```

In another terminal:

```sh
PORT=8080 scripts/crs-curated/check_curated_rules.sh
```

### B.4 What to observe

- Every **attack** row → `[BLOCK ok ] … -> 403` (blocked before the backend is reached).
- The **control** row → `[PASS ok  ] … -> 200` (proxied to the dummy backend).
- Summary `failed: 0` and `curated ruleset verified on the wire.`
- Confirm the boot log shows **28 rules loaded, 0 skipped** — the wire counterpart of the offline
  gate. Fewer-than-expected also raises a `warn` at boot.

The script only asserts CRITICAL-severity signatures block (they cross `block_threshold = 5` alone).
ERROR/WARNING rules (e.g. recon UA, `.git` exposure) are additive and may not block on their own —
by design, the operator tunes the threshold with the curated ruleset on (they contribute to the
same cumulative anomaly score as the native modules).

---

## Troubleshooting

- **All attacks MISS (not blocked)** — the module isn't active or isn't scoring: check the boot log
  for `wiring curated premium CRS ruleset`; confirm `[enterprise.crs_curated].enabled = true`,
  `mode = "blocking"`, and `block_threshold <= 6`.
- **`BLOCK ok` never seen but a different code repeats** — your build's block status differs from
  `403`; re-run with `BLOCK_CODE=<code> scripts/crs-curated/check_curated_rules.sh`.
- **Boot log says fewer than 28 loaded / N skipped** — a rule fell outside the engine subset (the
  offline gate would have caught this first); inspect `skipped` reasons at debug log level.
- **The benign control is blocked (`FALSE +`)** — a curated rule is too broad; identify it from the
  decision log (`rule_id = crs-<id>`) and tighten or drop it.
