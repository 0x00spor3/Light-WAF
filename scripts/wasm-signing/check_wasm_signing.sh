#!/usr/bin/env bash
# SPDX-License-Identifier: BUSL-1.1
#
# check_wasm_signing.sh — confirm a signature-VERIFIED WASM plugin is active on a running enterprise
# WAF: the plugin (the B3 example denylist filter) blocks 403 on its `X-Block` kill-switch, and a
# benign request passes. That the plugin loaded AT ALL proves its signature verified (a bad signature
# is boot-fatal — the WAF would not be running).
#
# The negative path (tampered / wrong-key / unsigned → boot-fatal) is proven by the offline suite and
# the env-gated bite-test; here we only confirm the verified plugin is live on the wire.
#
# Env (defaults):  HOST [127.0.0.1]  PORT [8080]  TIMEOUT [5]  BLOCK_CODE [403]
set -uo pipefail

HOST="${HOST:-127.0.0.1}"; PORT="${PORT:-8080}"; TIMEOUT="${TIMEOUT:-5}"; BLOCK_CODE="${BLOCK_CODE:-403}"
BASE="http://${HOST}:${PORT}"
pass=0; fail=0
code_for() { curl -s -o /dev/null -w '%{http_code}' --max-time "$TIMEOUT" "$@" 2>/dev/null || echo 000; }

echo "Target: ${BASE}  (block code = ${BLOCK_CODE})"
echo
echo "Verified plugin active — X-Block kill-switch must BLOCK:"
code=$(code_for -H 'x-block: 1' "${BASE}/")
if [[ "$code" == "$BLOCK_CODE" ]]; then
  printf '  [BLOCK ok ] %-30s -> %s\n' "X-Block request" "$code"; pass=$((pass + 1))
else
  printf '  [MISS     ] %-30s -> %s (expected %s)\n' "X-Block request" "$code" "$BLOCK_CODE"; fail=$((fail + 1))
fi

echo
echo "Benign request must PASS:"
code=$(code_for "${BASE}/")
if [[ "$code" != "$BLOCK_CODE" ]]; then
  printf '  [PASS ok  ] %-30s -> %s\n' "plain GET /" "$code"; pass=$((pass + 1))
else
  printf '  [FALSE +  ] %-30s -> %s\n' "plain GET /" "$code"; fail=$((fail + 1))
fi

echo
echo "passed: ${pass}   failed: ${fail}"
if [[ "$fail" -eq 0 ]]; then echo "signed WASM plugin verified on the wire."; exit 0
else echo "FAILURES above — see RUNBOOK.md Troubleshooting."; exit 1; fi
