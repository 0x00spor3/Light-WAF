<!-- SPDX-License-Identifier: Apache-2.0 -->
# Runbook — client-integrity / bot detection (§4-A)

Verifies the enterprise bot-detection module (`waf-modules-premium`): native cross-header heuristics
injected as a `structural()` `WafModule`. v1 = **browser impersonation (S1)**: a request whose
User-Agent advertises a *modern* browser (Chromium/Firefox with a 3-digit major version) but which
carries **no** `sec-fetch-*` headers scores `bot-browser-impersonation` (Critical). A crude bot
spoofing a Chrome UA via `curl`/`requests` omits Fetch-Metadata; a real non-browser client advertises
no browser, so it is not flagged. This is deliberately NOT the OPEN `scanner` module (UA-tool
matching) nor curated content (CRS-curated §6).

Two layers:
- **A. Offline suite** (`cargo test`, no environment) — unit (UA classifier, `sec-fetch` detection,
  config) + datapath bite-tests: impersonation blocks vs a real browser passes (control), non-browser
  clients pass, default-off inert, the FP-guard (curl/SDK/old/Safari/no-UA all clean).
- **B. Live wire check** (`check_bot_detection.sh`) — a running enterprise WAF with the module
  enabled, hit with curl (with/without the browser UA and Sec-Fetch headers).

---

## A. Offline suite

```sh
cargo test -p waf-modules-premium          # bot: classifier + S1 + 6 bot_datapath (REAL pipeline + FP-guard)
cargo test -p waf-enterprise               # incl. 3 bot_detection config tests
```

## B. Live wire check

### B.1 Prereqs

- Build once: `cargo build -p waf-enterprise` (from `enterprise/`).
- `bash` + `curl`. A dummy backend (so legit requests get a 200):

```sh
python3 -m http.server 3000
```

### B.2 Node config (`bot-node.toml`)

```toml
[proxy]
listen  = "127.0.0.1:8080"
backend = "http://127.0.0.1:3000"

[waf]
mode            = "blocking"
block_threshold = 5            # a single Critical impersonation hit (severity 6) crosses this

[enterprise.bot_detection]
enabled = true
# browser_impersonation_severity = "critical"
```

### B.3 Run

```sh
WAF_CONFIG=bot-node.toml cargo run -p waf-enterprise
# boot log: "wiring client-integrity / bot-detection module (§4-A)"
```

In another terminal (from `enterprise/`):

```sh
PORT=8080 scripts/bot-detection/check_bot_detection.sh
```

### B.4 What to observe

- The **impersonation** row (`chrome UA, NO sec-fetch`) → `[BLOCK ok ] … -> 403`.
- Every **legitimate** row → `[PASS ok  ] … -> 200`: a real Chrome (WITH `sec-fetch-site`), plain
  curl, an old 2-digit Chrome (below the modern-version floor), and a request with no User-Agent.
- Summary `failed: 0` and `bot-detection verified on the wire.`

---

## Troubleshooting

- **Impersonation row MISSes** — the module isn't active or the UA didn't classify as a modern
  browser: check the boot log for `wiring client-integrity / bot-detection`; confirm `enabled = true`,
  `mode = "blocking"`, `block_threshold <= 6`, and that the UA has a **3-digit** major version
  (`Chrome/1xx`, `Firefox/1xx`).
- **A real browser is blocked (`FALSE +`)** — the browser sent no `Sec-Fetch-*` (very old browser, or
  a proxy stripped them). That is the known FP source; lower `browser_impersonation_severity` or accept
  the score. The rule fires only when a modern-browser UA has **zero** `sec-fetch-*` headers.
- **Safari is not flagged** — by design: Safari is excluded in v1 (historically inconsistent
  Sec-Fetch), so a Safari UA never triggers S1.
