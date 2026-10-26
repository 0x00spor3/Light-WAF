// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

// Shared visual tokens: chart palette + semantic colors for decisions/severities, so the whole
// dashboard reads consistently.

export const CHART_AXIS = "#5a6377";
export const CHART_GRID = "#232a38";

/// Color for a decision class (blocked/rejected are the denied verdicts v1 stores).
export function decisionColor(decision: string): string {
  switch (decision.toLowerCase()) {
    case "blocked":
      return "#fb5468";
    case "rejected":
      return "#ff9d42";
    case "allowed":
    case "passed":
      return "#2fce8e";
    case "internal_error":
    case "upstream_error":
      return "#a78bfa";
    default:
      return "#2fe0c0";
  }
}

/// Color for a severity label (free-form string from the core; unknown → neutral).
export function severityColor(severity: string | null | undefined): string {
  switch ((severity ?? "").toLowerCase()) {
    case "critical":
      return "#fb5468";
    case "warning":
      return "#ff9d42";
    case "notice":
      return "#5b9dff";
    default:
      return "#8791a4";
  }
}

/// Latency quantile palette (p50/p95/p99) — cool signal → hot, as pressure rises.
export const LATENCY_COLORS = ["#2fe0c0", "#ff9d42", "#fb5468"];

/// Color for an API-inventory classification (§4-B pt3 discovery): shadow (undeclared surface being
/// hit) → alarm red; documented (declared endpoint drawing blocks) → teal; unclassified → muted.
export function classificationColor(classification: string): string {
  switch (classification.toLowerCase()) {
    case "shadow":
      return "#fb5468";
    case "documented":
      return "#2fe0c0";
    default:
      return "#5a6377";
  }
}

/// Color for a lifecycle / apply status: healthy (active, applied, current) → allowed green;
/// soft-negative (rejected, pending) → amber; hard-negative (error, disabled, revoked) → blocked red.
export function statusColor(status: string): string {
  switch (status.toLowerCase()) {
    case "applied":
    case "active":
    case "current":
    case "enabled":
      return "#2fce8e";
    case "rejected":
    case "pending":
      return "#ff9d42";
    case "error":
    case "disabled":
    case "revoked":
      return "#fb5468";
    default:
      return "#8791a4";
  }
}

/// Format an RFC3339 timestamp as a compact local date-time; falls back to the raw string.
export function fmtTime(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString(undefined, {
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

/// Format an RFC3339 timestamp as HH:MM (for dense time-series axes).
export function fmtClock(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
}

/// Compact number formatting (1.2k, 3.4M).
export function fmtNum(n: number): string {
  return new Intl.NumberFormat(undefined, { notation: "compact", maximumFractionDigits: 1 }).format(n);
}
