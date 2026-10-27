#!/usr/bin/env bash
# Idempotent SPDX applier (Apache-2.0) for the whole workspace.
#   - prepends a 2-line SPDX header to every .rs under crates/ and fuzz/
#   - sets `license = "Apache-2.0"` in each crate Cargo.toml that has a [package]
# Safe to re-run: files that already carry the header / license are skipped.
# Run from the repo root:  bash add-spdx.sh
set -euo pipefail

# ── EDIT THESE ───────────────────────────────────────────────────────────────
HOLDER="0x00spor3"          # copyright holder string — keep IDENTICAL everywhere
YEAR="2026"
LICENSE_ID="Apache-2.0"
# ─────────────────────────────────────────────────────────────────────────────

H1="// SPDX-FileCopyrightText: ${YEAR} ${HOLDER}"
H2="// SPDX-License-Identifier: ${LICENSE_ID}"

added=0 skipped=0
echo "== .rs SPDX headers =="
while IFS= read -r -d '' f; do
  if grep -q 'SPDX-License-Identifier' "$f"; then
    skipped=$((skipped + 1)); continue
  fi
  tmp="$(mktemp)"
  printf '%s\n%s\n\n' "$H1" "$H2" > "$tmp"
  cat "$f" >> "$tmp"
  mv "$tmp" "$f"
  added=$((added + 1))
  echo "  + $f"
done < <(find crates fuzz -name '*.rs' -print0)
echo "   $added added, $skipped already present"

setl=0 skipl=0
echo "== Cargo.toml license field =="
while IFS= read -r -d '' m; do
  grep -qE '^\[package\]' "$m" || continue          # skip the root [workspace] manifest
  if grep -qE '^[[:space:]]*license' "$m"; then
    skipl=$((skipl + 1)); continue
  fi
  awk -v lic="license = \"${LICENSE_ID}\"" '
    { print }
    /^\[package\]/ && !ins { print lic; ins = 1 }
  ' "$m" > "$m.tmp" && mv "$m.tmp" "$m"
  setl=$((setl + 1))
  echo "  + license -> $m"
done < <(find crates fuzz -name 'Cargo.toml' -print0)
echo "   $setl set, $skipl already present"

echo
echo "Done. Review:  git diff   then build:  cargo build --workspace"
echo "Reminder: add root LICENSE (Apache-2.0 full text) + NOTICE manually."

