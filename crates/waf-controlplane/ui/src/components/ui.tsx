// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

import type { ReactNode } from "react";
import type { Contribution } from "../api";
import { decisionColor, severityColor } from "../theme";

/// A titled surface. `actions` render on the right of the header (e.g. a range selector).
export function Panel({
  title,
  subtitle,
  actions,
  children,
  className,
}: {
  title?: string;
  subtitle?: string;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section className={`panel ${className ?? ""}`}>
      {(title || actions) && (
        <header className="panel-head">
          <div>
            {title && <h3>{title}</h3>}
            {subtitle && <span className="panel-sub">{subtitle}</span>}
          </div>
          {actions && <div className="panel-actions">{actions}</div>}
        </header>
      )}
      <div className="panel-body">{children}</div>
    </section>
  );
}

/// A big-number stat tile with an accent bar.
export function StatCard({ label, value, accent }: { label: string; value: ReactNode; accent?: string }) {
  return (
    <div className="stat-card" style={accent ? { ["--accent" as string]: accent } : undefined}>
      <span className="stat-label">{label}</span>
      <span className="stat-value">{value}</span>
    </div>
  );
}

/// The Verdict Meter — the signature element. A horizontal risk track where each rule's score
/// contribution stacks as a severity-colored segment; the filled length is the accumulated score,
/// which tipped the request to its verdict. Embodies the WAF's core model: scores accumulate until
/// they cross the block threshold. When no per-rule contributions were recorded, the whole filled
/// length takes the verdict's own color.
export function VerdictMeter({
  score,
  decision,
  contributions,
}: {
  score: number;
  decision: string;
  contributions: Contribution[];
}) {
  const denied = ["blocked", "rejected"].includes(decision.toLowerCase());
  const contribTotal = contributions.reduce((sum, c) => sum + Math.max(0, c.points), 0);
  const filled = Math.max(score, contribTotal);
  // Headroom so a blocked bar never pins the full track — the threshold lives to the left of the end.
  const scaleMax = Math.max(filled * 1.3, 10);

  const segments =
    contributions.length > 0
      ? contributions.map((c, i) => ({
          key: `${c.rule_id}-${i}`,
          width: Math.max(0, c.points),
          color: severityColor(c.severity),
          title: `${c.rule_id} · +${c.points}`,
        }))
      : [{ key: "verdict", width: filled, color: decisionColor(decision), title: decision }];

  // Distinct severities present, for a compact legend.
  const legend = [...new Set(contributions.map((c) => (c.severity ?? "unscored").toLowerCase()))];

  return (
    <div className="meter">
      <div className="meter-head">
        <span className="meter-score">
          {score}
          <small>accumulated score</small>
        </span>
        <span className="meter-flag" style={{ color: decisionColor(decision) }}>
          {denied ? "▲" : "●"} {decision}
        </span>
      </div>
      <div className="meter-track" role="img" aria-label={`score ${score}, ${decision}`}>
        {segments.map((s) => (
          <span
            key={s.key}
            className="meter-seg"
            style={{ width: `${(s.width / scaleMax) * 100}%`, background: s.color }}
            title={s.title}
          />
        ))}
        <span className="meter-rest" />
      </div>
      {legend.length > 0 && (
        <div className="meter-legend">
          {legend.map((sev) => (
            <span key={sev}>
              <i style={{ background: severityColor(sev) }} />
              {sev}
            </span>
          ))}
        </div>
      )}
    </div>
  );
}

/// A colored pill for a decision class.
export function DecisionBadge({ decision }: { decision: string }) {
  return (
    <span className="badge" style={{ ["--c" as string]: decisionColor(decision) }}>
      {decision}
    </span>
  );
}

/// A colored pill for a severity label.
export function SeverityBadge({ severity }: { severity: string | null | undefined }) {
  return (
    <span className="badge" style={{ ["--c" as string]: severityColor(severity) }}>
      {severity ?? "—"}
    </span>
  );
}

/// A subtle "auto-refreshing" marker: a pulsing dot + the clock time of the last successful update.
/// Renders nothing until the first successful load. Meant for a polled `Panel`'s `actions` slot.
export function LiveIndicator({ at }: { at: number | null }) {
  if (!at) return null;
  const clock = new Date(at).toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
  return (
    <span className="live" title="Auto-refreshing — no page reload needed">
      <span className="live-dot" />
      <span className="live-label">live</span>
      <span className="live-time">{clock}</span>
    </span>
  );
}

/// Loading / error / empty placeholders, so every view handles the three states the same way.
export function Loading({ label = "Loading…" }: { label?: string }) {
  return (
    <div className="state">
      <span className="spinner" /> {label}
    </div>
  );
}

export function ErrorState({ error, onRetry }: { error: string; onRetry?: () => void }) {
  return (
    <div className="state error">
      <span>⚠ {error}</span>
      {onRetry && (
        <button className="ghost" onClick={onRetry}>
          Retry
        </button>
      )}
    </div>
  );
}

export function Empty({ label = "No data yet." }: { label?: string }) {
  return <div className="state muted">{label}</div>;
}
