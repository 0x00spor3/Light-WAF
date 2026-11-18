// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0
//
// `npm audit --audit-level=high` with an accept list. npm audit cannot ignore an advisory, so a
// HIGH/CRITICAL one with no fixed version (or whose only "fix" is a downgrade) would keep the gate red
// forever. This runs `npm audit --json` and fails on every HIGH/CRITICAL advisory EXCEPT those
// accepted in ./osv-scanner.toml — the same file OSV-Scanner / Scorecard read for this lockfile, so
// there is one accept list, each entry with a reason and an expiry. An expired entry fails again.
//
// Usage (from crates/waf-controlplane/ui): npm run audit:gate

import { execSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const UI_DIR = join(dirname(fileURLToPath(import.meta.url)), "..");
const GATED = new Set(["high", "critical"]);

function fail(msg) {
  console.error(`audit-gate: ${msg}`);
  process.exit(1);
}

// The accept list: [[IgnoredVulns]] blocks with `id`, `ignoreUntil` (or `effectiveUntil`) and
// `reason`. An entry missing any of them is a hard error, not a silent accept.
function loadAccepted() {
  const toml = readFileSync(join(UI_DIR, "osv-scanner.toml"), "utf8");
  const accepted = new Map();
  for (const block of toml.split(/^\[\[IgnoredVulns\]\]\s*$/m).slice(1)) {
    const id = block.match(/^id\s*=\s*"([^"]+)"/m)?.[1];
    const until = block.match(/^(?:ignoreUntil|effectiveUntil)\s*=\s*(\d{4}-\d{2}-\d{2})/m)?.[1];
    const reason = block.match(/^reason\s*=\s*"([^"]+)"/m)?.[1];
    if (!id || !until || !reason) {
      fail(`osv-scanner.toml: every [[IgnoredVulns]] needs id, ignoreUntil and reason:\n${block.trim()}`);
    }
    accepted.set(id, { until, reason });
  }
  return accepted;
}

function runAudit() {
  let out;
  try {
    out = execSync("npm audit --json", { cwd: UI_DIR, encoding: "utf8", maxBuffer: 64 << 20 });
  } catch (e) {
    // npm audit exits non-zero when it finds anything; the report is still on stdout.
    out = e.stdout;
  }
  try {
    return JSON.parse(out);
  } catch {
    fail(`could not parse \`npm audit --json\` output:\n${String(out).slice(0, 2000)}`);
  }
}

const accepted = loadAccepted();
const report = runAudit();
if (report.error) fail(`npm audit failed: ${JSON.stringify(report.error)}`);

// The advisories themselves are the object entries of `via`; string entries ("vite" depends on
// "picomatch") only propagate them, so gating on the advisories covers every affected package.
const advisories = new Map();
for (const vuln of Object.values(report.vulnerabilities ?? {})) {
  for (const via of vuln.via) {
    if (typeof via !== "object" || !GATED.has(via.severity)) continue;
    const id = via.url?.split("/").pop() ?? String(via.source);
    const seen = advisories.get(id) ?? { ...via, id, packages: new Set() };
    seen.packages.add(vuln.name);
    advisories.set(id, seen);
  }
}

const today = new Date().toISOString().slice(0, 10);
const blocking = [];
for (const adv of advisories.values()) {
  const acc = accepted.get(adv.id);
  const pkgs = [...adv.packages].join(", ");
  if (acc && today <= acc.until) {
    console.log(`accepted  ${adv.id} (${adv.severity}, ${pkgs}) until ${acc.until}: ${acc.reason}`);
  } else if (acc) {
    blocking.push(`${adv.id} (${adv.severity}, ${pkgs}): accept EXPIRED on ${acc.until} — fix or re-review`);
  } else {
    blocking.push(`${adv.id} (${adv.severity}, ${pkgs}): ${adv.title} — ${adv.url}`);
  }
}

if (blocking.length) {
  fail(`${blocking.length} HIGH/CRITICAL advisory(ies) not accepted in osv-scanner.toml:\n  ${blocking.join("\n  ")}`);
}
console.log(`audit-gate: OK (${advisories.size} HIGH/CRITICAL advisory(ies), all accepted)`);
