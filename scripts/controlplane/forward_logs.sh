#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Minimal reference log shipper for the control plane (§7). Tails the WAF's JSON decision-log and
# POSTs each new line to the control plane's /ingest/events endpoint, tagged with a node name.
#
# This is a REFERENCE only — in production use a real shipper (Vector, Fluent Bit, Filebeat) which
# batches, retries and handles rotation. The control plane never reaches into the WAF; the WAF just
# writes logs, and this out-of-process shipper forwards them (zero datapath cost).
#
# Usage: ./forward_logs.sh <waf-log-file> <control-plane-url> <node-name> [api-token]

set -euo pipefail

LOG="${1:?usage: forward_logs.sh <waf-log-file> <control-plane-url> <node-name> [api-token]}"
CP="${2:?missing control-plane url, e.g. http://127.0.0.1:9600}"
NODE="${3:?missing node name}"
TOKEN="${4:-}"

AUTH=()
if [[ -n "$TOKEN" ]]; then
    AUTH=(-H "Authorization: Bearer ${TOKEN}")
fi

echo "shipping ${LOG} -> ${CP}/ingest/events?node=${NODE}" >&2

# Follow the file from its current end; forward each new line as a one-line NDJSON batch.
tail -n0 -F "$LOG" | while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    curl -s -o /dev/null "${AUTH[@]}" \
        -X POST "${CP}/ingest/events?node=${NODE}" \
        --data-binary "$line" || echo "warn: POST failed for one line" >&2
done
