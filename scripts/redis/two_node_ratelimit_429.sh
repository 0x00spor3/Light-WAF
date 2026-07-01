#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# two_node_ratelimit_429.sh — drive two WAF nodes (same host, different ports) with the
# SAME concurrent load until BOTH return a 429, then report how long it took.
#
# Purpose: smoke the distributed rate-limit store (waf-state-redis). With a SHARED Redis
# the token bucket is cluster-wide, so the two nodes drain ONE budget — both should hit
# 429 quickly. Run it once with the default in-memory store (no Redis) as the control:
# there the two budgets are independent, so the total admitted before 429 is ~2x.
#
# Requirements on the WAF nodes:
#   - both in `mode = "blocking"` (detection-only would log, not actually 429),
#   - identical `[rate_limit]` config + identical `[network]`/trusted-proxy (so both
#     resolve the SAME client IP -> SAME bucket key for this client),
#   - both pointed at the SAME Redis URL.
#   - keep the burst fast vs `refill_per_sec`, else refill outpaces the loop and 429
#     never lands (the script will just time out — see MAX_SECONDS).
#
# Config via env vars (defaults in brackets):
#   HOST [127.0.0.1]   PORT_A [8080]   PORT_B [8081]
#   REQ_PATH [/]       CONCURRENCY [25]   MAX_SECONDS [60]   TIMEOUT [2]
#
# Usage:  ./two_node_ratelimit_429.sh
#         PORT_A=8080 PORT_B=8081 CONCURRENCY=50 ./two_node_ratelimit_429.sh
set -euo pipefail

HOST="${HOST:-127.0.0.1}"
PORT_A="${PORT_A:-8080}"
PORT_B="${PORT_B:-8081}"
REQ_PATH="${REQ_PATH:-/}"
CONCURRENCY="${CONCURRENCY:-25}"   # parallel requests fired at EACH node per round
MAX_SECONDS="${MAX_SECONDS:-60}"   # safety: give up if both 429s never land
TIMEOUT="${TIMEOUT:-2}"            # per-request curl timeout (s)

URL_A="http://${HOST}:${PORT_A}${REQ_PATH}"
URL_B="http://${HOST}:${PORT_B}${REQ_PATH}"

now()      { date +%s.%N; }
elapsed()  { awk "BEGIN{printf \"%.2f\", $(now) - $START}"; }

# Fire CONCURRENCY parallel requests at $1; print one HTTP status code per line.
# Each curl writes to its own temp file so concurrent stdout can't interleave a line.
batch() {
  local url=$1 tmp i
  tmp=$(mktemp -d)
  for ((i = 0; i < CONCURRENCY; i++)); do
    curl -s -o /dev/null -w '%{http_code}\n' --max-time "$TIMEOUT" "$url" >"$tmp/$i" 2>/dev/null || echo 000 >"$tmp/$i" &
  done
  wait
  cat "$tmp"/*
  rm -rf "$tmp"
}

echo "Node A: $URL_A"
echo "Node B: $URL_B"
echo "Load: ${CONCURRENCY} concurrent req/round per node — stopping when BOTH return 429"
echo

START=$(now)
sent_a=0 sent_b=0
t_first_a="" t_first_b=""   # elapsed seconds at first 429
sent_at_first_a=0 sent_at_first_b=0
round=0

while :; do
  round=$((round + 1))

  codes_a=$(batch "$URL_A"); sent_a=$((sent_a + CONCURRENCY))
  codes_b=$(batch "$URL_B"); sent_b=$((sent_b + CONCURRENCY))

  if [[ -z "$t_first_a" ]] && grep -q '^429$' <<<"$codes_a"; then
    t_first_a=$(elapsed); sent_at_first_a=$sent_a
    echo "[+] Node A first 429 at ${t_first_a}s (after ${sent_at_first_a} requests)"
  fi
  if [[ -z "$t_first_b" ]] && grep -q '^429$' <<<"$codes_b"; then
    t_first_b=$(elapsed); sent_at_first_b=$sent_b
    echo "[+] Node B first 429 at ${t_first_b}s (after ${sent_at_first_b} requests)"
  fi

  if [[ -n "$t_first_a" && -n "$t_first_b" ]]; then
    both=$(elapsed)
    echo
    echo "==================================================================="
    echo "BOTH nodes reached 429 after ${both}s"
    echo "  Node A: first 429 at ${t_first_a}s  (${sent_at_first_a} reqs)"
    echo "  Node B: first 429 at ${t_first_b}s  (${sent_at_first_b} reqs)"
    echo "  Total admitted-then-rejected workload: A=${sent_a}, B=${sent_b}, sum=$((sent_a + sent_b))"
    echo "==================================================================="
    exit 0
  fi

  if awk "BEGIN{exit !($(elapsed) > $MAX_SECONDS)}"; then
    echo
    echo "[!] TIMEOUT after ${MAX_SECONDS}s — did NOT see 429 on both nodes." >&2
    echo "    Node A first 429: ${t_first_a:-never}   Node B first 429: ${t_first_b:-never}" >&2
    echo "    Check: mode=blocking, rate_limit enabled, refill not outpacing the burst." >&2
    exit 1
  fi
done
