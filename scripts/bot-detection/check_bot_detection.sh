#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# check_bot_detection.sh — fire a battery of requests at a running enterprise WAF and confirm a
# browser-IMPERSONATION request (a modern-browser User-Agent with NO `sec-fetch-*` headers) is
# BLOCKED (`bot-browser-impersonation`, Critical), while legitimate clients pass:
# a real browser (sends Sec-Fetch), curl/SDK (advertises no browser), an old browser, and no-UA.
#
# The module (`[enterprise.bot_detection]`) must be ENABLED, WAF in `mode = "blocking"`,
# `block_threshold <= 6`. A dummy backend gives legit requests a 200.
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

CHROME='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
OLD_CHROME='Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.88 Safari/537.36'

# send <name> <extra curl args...> → HTTP status.
code_for() { curl -s -o /dev/null -w '%{http_code}' --max-time "$TIMEOUT" "$@" 2>/dev/null || echo 000; }

expect_block() {
  local name=$1; shift
  local code; code=$(code_for "$@")
  if [[ "$code" == "$BLOCK_CODE" ]]; then
    printf '  [BLOCK ok ] %-40s -> %s\n' "$name" "$code"; pass=$((pass + 1))
  else
    printf '  [MISS     ] %-40s -> %s (expected %s)\n' "$name" "$code" "$BLOCK_CODE"; fail=$((fail + 1))
  fi
}
expect_pass() {
  local name=$1; shift
  local code; code=$(code_for "$@")
  if [[ "$code" != "$BLOCK_CODE" ]]; then
    printf '  [PASS ok  ] %-40s -> %s\n' "$name" "$code"; pass=$((pass + 1))
  else
    printf '  [FALSE +  ] %-40s -> %s (blocked a legit client!)\n' "$name" "$code"; fail=$((fail + 1))
  fi
}

echo "Target: ${BASE}  (block code = ${BLOCK_CODE})"
echo
echo "Impersonation — must BLOCK (bot-browser-impersonation, Critical):"
expect_block "chrome UA, NO sec-fetch"   -H "user-agent: ${CHROME}"                     "${BASE}/"

echo
echo "Legitimate — must PASS (no false positive):"
expect_pass  "chrome UA WITH sec-fetch"  -H "user-agent: ${CHROME}" -H 'sec-fetch-site: none' "${BASE}/"
expect_pass  "curl (default UA)"          "${BASE}/"
expect_pass  "old chrome (2-digit)"      -H "user-agent: ${OLD_CHROME}"                 "${BASE}/"
expect_pass  "no user-agent"             -H 'user-agent;'                               "${BASE}/"

echo
echo "passed: ${pass}   failed: ${fail}"
if [[ "$fail" -eq 0 ]]; then
  echo "bot-detection verified on the wire."
  exit 0
else
  echo "FAILURES above — see RUNBOOK.md Troubleshooting."
  exit 1
fi
