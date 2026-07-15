#!/usr/bin/env bash
# SPDX-License-Identifier: BUSL-1.1
#
# check_api_schema_enforcement.sh — fire a battery of HTTP requests at a running enterprise WAF and
# confirm OpenAPI positive-security is enforced: a request to an endpoint/method the app's spec does
# NOT declare is BLOCKED (schema-api-unknown-route / -method-not-allowed, Critical), while legitimate
# requests that honour the contract PASS — and a non-API path outside the guarded prefix is untouched.
#
# The module (`[enterprise.api_schema]`) must be ENABLED with `spec_path` at the demo `openapi.json`,
# WAF in `mode = "blocking"`, `block_threshold <= 6`. Blocked requests never reach the backend, so the
# backend can be absent for the attack rows (a passing row that reaches an absent backend returns a
# 5xx, which is simply "not blocked" — still a PASS here).
#
# NOTE: contract violations (bad param/body shape) score `violation_severity` (Warning by default) —
# additive, they do NOT block on their own at block_threshold=5 (see RUNBOOK B.5 to force them).
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

# send <method> <path> [json-body] → HTTP status code.
send() {
  local m=$1 p=$2 data=${3:-}
  if [[ -n "$data" ]]; then
    printf '%s' "$data" | curl -s -o /dev/null -w '%{http_code}' --max-time "$TIMEOUT" \
      -X "$m" -H 'content-type: application/json' --data-binary @- "${BASE}${p}" 2>/dev/null || echo 000
  else
    curl -s -o /dev/null -w '%{http_code}' --max-time "$TIMEOUT" \
      -X "$m" "${BASE}${p}" 2>/dev/null || echo 000
  fi
}

expect_block() {
  local name=$1 code; code=$(send "$2" "$3" "${4:-}")
  if [[ "$code" == "$BLOCK_CODE" ]]; then
    printf '  [BLOCK ok ] %-40s -> %s\n' "$name" "$code"; pass=$((pass + 1))
  else
    printf '  [MISS     ] %-40s -> %s (expected %s)\n' "$name" "$code" "$BLOCK_CODE"; fail=$((fail + 1))
  fi
}

expect_pass() {
  local name=$1 code; code=$(send "$2" "$3" "${4:-}")
  if [[ "$code" != "$BLOCK_CODE" ]]; then
    printf '  [PASS ok  ] %-40s -> %s\n' "$name" "$code"; pass=$((pass + 1))
  else
    printf '  [FALSE +  ] %-40s -> %s (blocked legit request!)\n' "$name" "$code"; fail=$((fail + 1))
  fi
}

echo "Target: ${BASE}  (block code = ${BLOCK_CODE})"
echo
echo "Not in the contract — must BLOCK (Critical):"
expect_block "unknown route"          "GET"    "/api/nope"
expect_block "method not allowed"     "DELETE" "/api/users"

echo
echo "Honours the contract — must PASS (no false positive):"
expect_pass  "valid GET by id"        "GET"    "/api/users/5"
expect_pass  "valid GET ?verbose"     "GET"    "/api/users/5?verbose=true"
expect_pass  "valid POST body"        "POST"   "/api/users"            '{"name":"ada","age":30}'
expect_pass  "nullable field = null"  "POST"   "/api/users"            '{"name":"ada","nickname":null}'
expect_pass  "non-API path untouched" "GET"    "/health"

echo
echo "passed: ${pass}   failed: ${fail}"
if [[ "$fail" -eq 0 ]]; then
  echo "OpenAPI positive-security verified on the wire."
  exit 0
else
  echo "FAILURES above — see RUNBOOK.md Troubleshooting."
  exit 1
fi
