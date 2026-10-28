#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Light WAF benchmark: latency/throughput overhead and detection quality, against no WAF and against
# ModSecurity + OWASP CRS. Needs only Docker (and bash). See README.md for the methodology.
#
#   ./run.sh                      # everything, results in results/<timestamp>/
#   SKIP_GOTESTWAF=1 ./run.sh     # performance only
#   SKIP_PERF=1 ./run.sh          # detection only
#
# Tunables (environment): PERF_TARGETS, DETECTION_TARGETS, RATE, CONNECTIONS, DURATION, WARMUP,
# WAF_CPUS, BACKEND_CPUS, LOADGEN_CPUS, LIGHTWAF_VERSION.
set -euo pipefail

# The whole script is one block, so bash parses it before running it: editing this file during a
# (long) run cannot change what the run does.
{
cd "$(dirname "$0")"

PERF_TARGETS=${PERF_TARGETS:-"direct lightwaf lightwaf-strict modsec-pl1 modsec-pl2"}
# modsec-strict blocks the clean benchmark requests, so it is measured for detection only.
DETECTION_TARGETS=${DETECTION_TARGETS:-"lightwaf lightwaf-strict modsec-pl1 modsec-pl2 modsec-strict"}
ALL_SERVICES="lightwaf lightwaf-strict modsec-pl1 modsec-pl2 modsec-strict"
RATE=${RATE:-250}               # fixed-rate runs: requests per second, sustainable by every target
CONNECTIONS=${CONNECTIONS:-64}
DURATION=${DURATION:-30s}
WARMUP=${WARMUP:-5s}
export WAF_CPUS=${WAF_CPUS:-0-1}
export BACKEND_CPUS=${BACKEND_CPUS:-2}
LOADGEN_CPUS=${LOADGEN_CPUS:-3-5}
export LIGHTWAF_VERSION=${LIGHTWAF_VERSION:-1.0.1}

OHA_IMAGE=ghcr.io/hatoo/oha:1.16.0
GOTESTWAF_IMAGE=wallarm/gotestwaf:0.5.8
PYTHON_IMAGE=python:3.13.5-alpine
NETWORK=light-waf-bench_default

RUN_ID=$(date -u +%Y%m%dT%H%M%SZ)
OUT="results/$RUN_ID"
mkdir -p "$OUT/perf" "$OUT/gotestwaf"
# Absolute host path for bind mounts (Git Bash on Windows needs the Windows form).
OUT_ABS=$(cd "$OUT" && { pwd -W 2>/dev/null || pwd; })
export MSYS_NO_PATHCONV=1

log() { printf '\n== %s\n' "$*"; }

url_of() {
  case "$1" in
    direct) echo "http://backend:80" ;;
    *)      echo "http://$1:8080" ;;
  esac
}

# Requests a browser would send: realistic headers and a cookie, so the WAF inspects a normal amount
# of input — not a bare GET with a tool User-Agent.
BROWSER_HEADERS=(
  -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36"
  -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
  -H "Accept-Language: en-US,en;q=0.9,it;q=0.8"
  -H "Accept-Encoding: gzip, deflate, br"
  -H "Cookie: session=4f9c2a7e1b8d4c3fa6e5d2c1b0a99887; theme=dark; consent=analytics%3D0%26ads%3D0"
  -H "Sec-Fetch-Dest: document" -H "Sec-Fetch-Mode: navigate" -H "Sec-Fetch-Site: same-origin"
)
POST_BODY='{"customer":{"name":"Ada Lovelace","email":"ada@example.com","address":{"street":"12 St James Square","city":"London","zip":"SW1Y 4JH"}},"items":[{"sku":"BK-1843","qty":1,"note":"gift wrap, please"},{"sku":"PN-0042","qty":3,"note":""}],"coupon":"AUTUMN-10","comment":"Leave it with the neighbour if nobody is home."}'

# scenario name -> oha arguments (minus the base URL)
scenario_args() {
  local base=$1
  case "$2" in
    clean-get)  echo "GET"  "$base/api/products?category=books&sort=price&page=2&q=ada+lovelace+biography" ;;
    clean-post) echo "POST" "$base/api/orders" ;;
    attack)     echo "GET"  "$base/search?q=1%27%20UNION%20SELECT%20username%2Cpassword%20FROM%20users--%20" ;;
  esac
}

oha() {
  # $1 = output file (or empty), rest = oha arguments
  local out=$1; shift
  if [ -n "$out" ]; then
    docker run --rm --network "$NETWORK" --cpuset-cpus "$LOADGEN_CPUS" "$OHA_IMAGE" \
      --no-tui --output-format json "$@" > "$out"
  else
    docker run --rm --network "$NETWORK" --cpuset-cpus "$LOADGEN_CPUS" "$OHA_IMAGE" \
      --no-tui "$@" > /dev/null
  fi
}

run_scenario() {
  local target=$1 scenario=$2 mode=$3
  local base; base=$(url_of "$target")
  local method url
  read -r method url < <(scenario_args "$base" "$scenario")
  local extra=(-m "$method" "${BROWSER_HEADERS[@]}")
  if [ "$method" = POST ]; then extra+=(-T application/json -d "$POST_BODY"); fi

  local rate=()
  if [ "$mode" = fixed ]; then rate=(-q "$RATE" --latency-correction); fi

  oha "" -z "$WARMUP" -c "$CONNECTIONS" "${extra[@]}" "$url"
  oha "$OUT/perf/$target.$scenario.$mode.json" -z "$DURATION" -c "$CONNECTIONS" "${rate[@]}" "${extra[@]}" "$url"
}

wait_ready() {
  local target=$1 url; url=$(url_of "$target")
  for _ in $(seq 1 60); do
    # Any HTTP answer means it is up (a strict WAF may well answer this bare request with a 403).
    local code
    code=$(docker run --rm --network "$NETWORK" curlimages/curl:8.11.1 -s -o /dev/null -w '%{http_code}' "$url/" 2>/dev/null || true)
    if [ -n "$code" ] && [ "$code" != 000 ]; then return 0; fi
    sleep 1
  done
  echo "$target did not become ready" >&2
  exit 1
}

container_of() { docker compose ps -q "$1"; }

log "Starting the stack (Light WAF $LIGHTWAF_VERSION)"
docker compose pull -q
for img in "$OHA_IMAGE" "$GOTESTWAF_IMAGE" "$PYTHON_IMAGE" curlimages/curl:8.11.1 alpine:3.21; do
  docker pull -q "$img" > /dev/null
done
docker compose up -d --force-recreate

for t in direct $ALL_SERVICES; do wait_ready "$t"; done

log "Recording the environment"
# One key=value per line; image.* values are "<reference> <digest>".
{
  echo "run_id=$RUN_ID"
  echo "rate=$RATE"
  echo "connections=$CONNECTIONS"
  echo "duration=$DURATION"
  echo "warmup=$WARMUP"
  echo "waf_cpus=$WAF_CPUS"
  echo "backend_cpus=$BACKEND_CPUS"
  echo "loadgen_cpus=$LOADGEN_CPUS"
  echo "docker=$(docker version --format '{{.Server.Version}} {{.Server.Os}}/{{.Server.Arch}}')"
  echo "host_cpus=$(docker info --format '{{.NCPU}}')"
  echo "host_mem_bytes=$(docker info --format '{{.MemTotal}}')"
  echo "kernel=$(docker info --format '{{.KernelVersion}}')"
  echo "os=$(docker info --format '{{.OperatingSystem}}')"
  echo "cpu_model=$(docker run --rm alpine:3.21 sh -c "grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | sed 's/^ //'" 2>/dev/null || echo unknown)"
  for svc in backend $ALL_SERVICES; do
    echo "image.$svc=$(docker inspect --format '{{.Config.Image}} {{.Image}}' "$(container_of "$svc")")"
  done
  echo "image.loadgen=$OHA_IMAGE $(docker image inspect --format '{{.Id}}' "$OHA_IMAGE")"
  echo "image.gotestwaf=$GOTESTWAF_IMAGE $(docker image inspect --format '{{.Id}}' "$GOTESTWAF_IMAGE")"
} > "$OUT/env.txt"

if [ -z "${SKIP_PERF:-}" ]; then
  for t in $PERF_TARGETS; do
    for s in clean-get clean-post attack; do
      # Without a WAF the "attack" is just another request to the backend; keep it for reference.
      for m in fixed max; do
        log "perf: $t / $s / $m"
        run_scenario "$t" "$s" "$m"
      done
    done
    if [ "$t" != direct ]; then
      docker stats --no-stream --format '{{.MemUsage}}' "$(container_of "$t")" \
        | awk '{print $1}' > "$OUT/perf/$t.memory.txt"
    fi
  done
fi

if [ -z "${SKIP_GOTESTWAF:-}" ]; then
  for t in $DETECTION_TARGETS; do
    log "gotestwaf: $t"
    # 403 = blocked by a rule; 400 = rejected as malformed/over-limit. Both mean "did not reach the
    # app", for every WAF alike.
    docker run --rm --network "$NETWORK" -v "$OUT_ABS/gotestwaf:/app/reports" "$GOTESTWAF_IMAGE" \
      --url "$(url_of "$t")/" --wafName "$t" --noEmailReport \
      --blockStatusCodes 403,400 --skipWAFIdentification \
      --reportFormat json --reportPath /app/reports --reportName "$t" \
      > "$OUT/gotestwaf/$t.log" 2>&1 || echo "gotestwaf exited non-zero for $t (see $t.log)"
  done
fi

log "Summarising"
docker run --rm -v "$(cd . && { pwd -W 2>/dev/null || pwd; }):/bench" -w /bench "$PYTHON_IMAGE" \
  python3 summarize.py "results/$RUN_ID"

docker compose down
log "Done: $OUT/summary.md"
exit 0
}
