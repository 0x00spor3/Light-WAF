<!-- SPDX-License-Identifier: Apache-2.0 -->

# Benchmark

A reproducible comparison of Light WAF with no WAF at all and with the reference open-source WAF,
**ModSecurity v3 + OWASP Core Rule Set**. It measures the two things anyone evaluating a WAF asks:

1. **What does it cost?** Added latency and maximum throughput, on clean traffic and on attacks.
2. **What does it catch?** Attacks blocked and legitimate requests wrongly blocked, measured with
   [gotestwaf](https://github.com/wallarm/gotestwaf).

Everything runs in Docker from pinned images; the only requirements are Docker and bash.

```sh
cd bench
./run.sh                      # ~25 minutes; results in results/<timestamp>/summary.md
SKIP_GOTESTWAF=1 ./run.sh     # performance only
SKIP_PERF=1 ./run.sh          # detection only
```

The latest published results, with the machine they ran on, are on
[lightwaf.org/benchmarks](https://lightwaf.org/benchmarks).

## What runs

| Container | Image | Role |
|---|---|---|
| `backend` | `nginx:1.27.5-alpine` | Answers `200 ok` to every request, as cheaply as possible, so the numbers are the WAF's. |
| `lightwaf` | `ghcr.io/0x00spor3/waf-enterprise:1.0.1` | Light WAF, the recommended baseline ([`lightwaf.toml`](lightwaf.toml): `examples/balanced.toml`, PL2, threshold 5, all 15 detection modules) without the per-IP rate limit. |
| `lightwaf-strict` | same | The strict profile ([`lightwaf-strict.toml`](lightwaf-strict.toml): the detection settings of `examples/strict.toml`, PL4, threshold 3), for high-value targets. |
| `modsec-pl1` | `owasp/modsecurity-crs:4.30.0-nginx-…` | ModSecurity + CRS 4.30 as shipped: paranoia 1, inbound anomaly threshold 5. |
| `modsec-pl2` | same | The same at paranoia 2, which is closer to Light WAF's PL2 baseline. |
| `modsec-strict` | same | The CRS at the strict profile's settings: paranoia 4, inbound threshold 3. **Detection only**: at this level the CRS also blocks the clean benchmark requests (it is meant to run with rule exclusions), so its latency would be the latency of a deny. |
| load generator | `ghcr.io/hatoo/oha:1.16.0` | HTTP load, with coordinated-omission correction on fixed-rate runs. |
| detection | `wallarm/gotestwaf:0.5.8` | Attack and false-positive test sets. |

**Fairness rules.**

- Every WAF gets the **same CPU set** (`WAF_CPUS`, default 2 CPUs), and only one WAF is under load at a
  time. The backend and the load generator have their own CPUs, so they never compete with the WAF.
- Both WAFs inspect **requests only**. Light WAF does not inspect responses, so ModSecurity's response
  body inspection is turned off.
- Both use their **shipped logging**. Nothing is tuned to win: no rule exclusions, no custom
  thresholds beyond the documented defaults.
- In gotestwaf, a `403` (blocked by a rule) and a `400` (rejected as malformed) both count as
  blocked, for every WAF. Light WAF uses `400` for requests it refuses to parse.

## Performance

Three request shapes, each sent to every target:

| Scenario | Request |
|---|---|
| `clean-get` | A browser-like `GET` with a query string and eight headers, a cookie among them. |
| `clean-post` | The same headers plus a ~400-byte JSON order body. |
| `attack` | A `GET` carrying a SQL injection (`1' UNION SELECT …`). The WAF blocks it, so the backend is never reached. This measures the cost of a deny. |

The clean requests must reach the backend through every target in the performance runs, otherwise
the row would time a deny; `summary.md` flags any clean request that was not answered `200`. (The
first version of `clean-get` searched for `q=history of computing`: CRS PL2 blocked it, reading
`history` as a Unix command. That is a real false positive, but it made the PL2 latency row
meaningless, so the query was changed.)

Each scenario runs twice per target, after a warm-up:

- **Fixed rate** (`RATE`, default 250 req/s, `CONNECTIONS` 64): latency percentiles at a load every
  target can sustain. *Added p99* is the target's p99 minus the backend-direct p99. A target that
  cannot keep up with the rate is marked **saturated**: its latency is then mostly queueing time.
- **Maximum rate** (no rate limit, 64 connections): the throughput ceiling, also as a percentage of
  backend-direct.

Memory is the WAF container's usage after its load runs.

## Detection

gotestwaf sends its attack test sets (SQLi, XSS, path traversal, RCE, SSTI, XXE, LDAP, NoSQL, mail
injection, SSI, CRLF, …, each through several encodings and placements) and a **true-negative** set of
legitimate requests that look suspicious. The report scores the share of attacks blocked
(true-positive) and of legitimate requests let through (true-negative).

## Read this before quoting the numbers

- **Light WAF was developed against gotestwaf.** Its detection modules were tuned by running gotestwaf
  and closing the bypasses it found (see `ARCHITECTURE.md`). The CRS was not tuned against
  gotestwaf. That makes the detection comparison favourable to Light WAF by construction; treat the
  gotestwaf score as a regression measure for Light WAF more than as an independent ranking. An
  independent dataset is on the to-do list.
- **One ModSecurity stack.** The numbers are those of ModSecurity v3 — libmodsecurity 3.0.17 with
  the nginx connector 1.0.4 and CRS 4.30.0, from the official `owasp/modsecurity-crs` image — not of
  ModSecurity in general. ModSecurity v2 on Apache, or the CRS on another engine, will perform
  differently.
- **The CRS and Light WAF use different paranoia scales.** PL2 in one is not PL2 in the other; several
  CRS levels are shown for that reason.
- **The strict profiles trade false positives for coverage.** gotestwaf's legitimate-request set is
  small (141 texts), so a perfect true-negative score there does not mean zero false positives on
  real traffic. Paranoia 4 with threshold 3 blocks on accumulated weak signals; run it in
  detection-only mode on your own traffic first. Neither WAF gets rule exclusions here, which is why
  the strict CRS blocks every legitimate request.
- **The machine matters.** Absolute numbers depend on the CPU, on whether Docker runs in a VM
  (Docker Desktop) or natively, and on the CPU sets. Compare targets within a run, not across runs.
  Every run records its environment (`env.txt`): CPU model, Docker, kernel, and the digest of every
  image.
- **One backend, one host.** This measures the WAF's own cost on a loopback network. It does not model
  a real application, TLS, or a network between client and WAF.

## Corrections welcome

Maintain one of the compared projects, or think the setup is unfair to it? Open an issue: we'll fix
the setup, re-run, and say on the results page what changed.

## Tunables

| Variable | Default | |
|---|---|---|
| `PERF_TARGETS` | `direct lightwaf lightwaf-strict modsec-pl1 modsec-pl2` | Targets of the performance runs. |
| `DETECTION_TARGETS` | `lightwaf lightwaf-strict modsec-pl1 modsec-pl2 modsec-strict` | Targets of the gotestwaf runs. |
| `RATE` | `250` | Requests per second for the fixed-rate runs. |
| `CONNECTIONS` | `64` | Concurrent connections. |
| `DURATION` / `WARMUP` | `30s` / `5s` | Per-run measurement and warm-up time. |
| `WAF_CPUS` / `BACKEND_CPUS` / `LOADGEN_CPUS` | `0-1` / `2` / `3-5` | CPU sets (`docker --cpuset-cpus` syntax). |
| `LIGHTWAF_VERSION` | `1.0.1` | Light WAF image tag. |

## Files

- `run.sh` — starts the stack, runs everything, writes `results/<timestamp>/`.
- `summarize.py` — turns a run directory into `summary.md` and `summary.json`.
- `docker-compose.yml`, `backend.conf`, `lightwaf.toml`, `lightwaf-strict.toml` — the stack.
- `results/` — local runs, not committed. The published run is the site's `src/data/benchmark.json`
  (a run's `summary.json`, copied as is).
