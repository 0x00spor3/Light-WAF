#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# check_schema_enforcement.sh — fire a battery of GraphQL operations at a running enterprise WAF and
# confirm that schema-INVALID operations are BLOCKED (they score `schema-graphql-unknown-field`,
# Critical) while legitimate operations — including introspection, which is the OPEN module's
# concern, not this one — pass through. Exercises all three transports (application/graphql body,
# JSON body, GET ?query=) plus the path-gating guard.
#
# The schema-enforcement module (`[enterprise.schema_enforcement]`) must be ENABLED with
# `schema_path` pointing at ./app.graphql, and the WAF in `mode = "blocking"` with a
# `block_threshold` a single CRITICAL hit crosses (<= 6). Blocked operations never reach the
# backend, so the backend can be any dummy server.
#
# A blocked request returns the WAF's block status (403 by default). "Passed" = the request reached
# the backend (2xx/3xx/404 from the backend, NOT 403).
#
# NOTE: a non-GraphQL body scores `schema-graphql-parse-error` (Warning by default) — additive, it
# does NOT block on its own at block_threshold=5. That case is covered by the offline suite and by
# the optional `parse_error_severity = "critical"` variant in the RUNBOOK, not asserted here.
#
# Config via env (defaults in brackets):  HOST [127.0.0.1]  PORT [8080]  TIMEOUT [5]
#                                          BLOCK_CODE [403]  GQL_PATH [/graphql]
#
# Usage:  ./check_schema_enforcement.sh
#         PORT=8080 ./check_schema_enforcement.sh
set -uo pipefail

HOST="${HOST:-127.0.0.1}"
PORT="${PORT:-8080}"
TIMEOUT="${TIMEOUT:-5}"
BLOCK_CODE="${BLOCK_CODE:-403}"
GQL_PATH="${GQL_PATH:-/graphql}"
BASE="http://${HOST}:${PORT}"

pass=0
fail=0

# HTTP status for an `application/graphql` POST carrying <query>.
gql_body() {
  curl -s -o /dev/null -w '%{http_code}' --max-time "$TIMEOUT" \
    -H 'content-type: application/graphql' --data "$1" "${BASE}${GQL_PATH}" 2>/dev/null || echo 000
}
# HTTP status for a JSON POST `{"query": "<query>"}`.
gql_json() {
  curl -s -o /dev/null -w '%{http_code}' --max-time "$TIMEOUT" \
    -H 'content-type: application/json' \
    --data "$(printf '{"query": %s}' "$(json_str "$1")")" "${BASE}${GQL_PATH}" 2>/dev/null || echo 000
}
# HTTP status for a GET `?query=<url-encoded query>`.
gql_get() {
  curl -s -o /dev/null -w '%{http_code}' --max-time "$TIMEOUT" \
    --get "${BASE}${GQL_PATH}" --data-urlencode "query=$1" 2>/dev/null || echo 000
}
# Minimal JSON string escaping (quotes + backslashes) for the JSON-transport body.
json_str() {
  local s=${1//\\/\\\\}
  s=${s//\"/\\\"}
  printf '"%s"' "$s"
}

# expect_block <transport-fn> <name> <query> — the operation MUST be blocked (status == BLOCK_CODE).
expect_block() {
  local fn=$1 name=$2 q=$3 code
  code=$($fn "$q")
  if [[ "$code" == "$BLOCK_CODE" ]]; then
    printf '  [BLOCK ok ] %-42s -> %s\n' "$name" "$code"; pass=$((pass + 1))
  else
    printf '  [MISS     ] %-42s -> %s (expected %s)\n' "$name" "$code" "$BLOCK_CODE"; fail=$((fail + 1))
  fi
}

# expect_pass <transport-fn> <name> <query> — the operation MUST pass through (status != BLOCK_CODE).
expect_pass() {
  local fn=$1 name=$2 q=$3 code
  code=$($fn "$q")
  if [[ "$code" != "$BLOCK_CODE" ]]; then
    printf '  [PASS ok  ] %-42s -> %s\n' "$name" "$code"; pass=$((pass + 1))
  else
    printf '  [FALSE +  ] %-42s -> %s (blocked a legit query!)\n' "$name" "$code"; fail=$((fail + 1))
  fi
}

echo "Target: ${BASE}${GQL_PATH}  (block code = ${BLOCK_CODE})"
echo
echo "Schema-INVALID operations — must BLOCK (schema-graphql-unknown-field, Critical):"
expect_block gql_body "unknown field"              '{ user(id: 1) { password } }'
expect_block gql_body "unknown top-level field"    '{ admin { id } }'
expect_block gql_body "unknown argument"           '{ user(id: 1, role: "x") { id } }'
expect_block gql_body "missing subselection"       '{ user(id: 1) }'
expect_block gql_body "undefined variable"         '{ user(id: $x) { id } }'
expect_block gql_json "unknown field (JSON body)"  '{ user(id: 1) { password } }'
expect_block gql_get  "unknown field (GET query)"  '{ user(id: 1) { password } }'

echo
echo "Legitimate operations — must PASS (no false positive):"
expect_pass gql_body "plain query"                 '{ user(id: 1) { id name } }'
expect_pass gql_body "field alias + __typename"    '{ a: user(id: 1) { __typename id } }'
expect_pass gql_body "declared+used variable"      'query($id: ID!) { user(id: $id) { id } }'
expect_pass gql_body "named fragment"              'query { user(id: 1) { ...F } } fragment F on User { id name }'
expect_pass gql_body "introspection (OPEN's job)"  '{ __schema { queryType { name } } }'
expect_pass gql_json "plain query (JSON body)"     '{ me { id } }'
expect_pass gql_get  "plain query (GET query)"     '{ me { id } }'

echo
echo "Path-gating guard — a non-GraphQL JSON API is left alone:"
# `{"query": "{ bogus }"}` on a NON-GraphQL path must NOT be inspected as GraphQL (would be a FP).
off_code=$(curl -s -o /dev/null -w '%{http_code}' --max-time "$TIMEOUT" \
  -H 'content-type: application/json' --data '{"query": "{ bogus }"}' "${BASE}/api/search" 2>/dev/null || echo 000)
if [[ "$off_code" != "$BLOCK_CODE" ]]; then
  printf '  [PASS ok  ] %-42s -> %s\n' "non-GraphQL /api/search {query}" "$off_code"; pass=$((pass + 1))
else
  printf '  [FALSE +  ] %-42s -> %s (inspected a non-GraphQL endpoint!)\n' "non-GraphQL /api/search {query}" "$off_code"; fail=$((fail + 1))
fi

echo
echo "passed: ${pass}   failed: ${fail}"
if [[ "$fail" -eq 0 ]]; then
  echo "GraphQL schema-enforcement verified on the wire."
  exit 0
else
  echo "FAILURES above — see RUNBOOK.md Troubleshooting."
  exit 1
fi
