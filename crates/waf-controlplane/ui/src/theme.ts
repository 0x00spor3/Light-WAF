// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: BUSL-1.1

// Shared visual tokens: chart palette + semantic colors for decisions/severities, so the whole
// dashboard reads consistently.

export const CHART_AXIS = "#6b7280";
export const CHART_GRID = "#232833";

/// Color for a decision class (blocked/rejected are the denied verdicts v1 stores).
export function decisionColor(decision: string): string {
  switch (decision.toLowerCase()) {
    case "blocked":
      return "#ff5c5c";
    case "rejected":
      return "#ff8a3d";
    case "allowed":
    case "passed":
      return "#34d399";
    case "internal_error":
    case "upstream_error":
      return "#a78bfa";
    default:
      return "#4f8cff";
  }
}

/// Color for a severity label (free-form string from the core; unknown → neutral).
export function severityColor(severity: string | null | undefined): string {
  switch ((severity ?? "").toLowerCase()) {
    case "critical":
      return "#ff5c5c";
    case "warning":
      return "#ffb020";
    case "notice":
      return "#4f8cff";
    default:
      return "#9aa3b2";
  }
}

/// Latency quantile palette (p50/p95/p99).
export const LATENCY_COLORS = ["#4f8cff", "#ffb020", "#ff5c5c"];

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
