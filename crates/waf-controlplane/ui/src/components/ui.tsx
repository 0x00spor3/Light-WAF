// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: BUSL-1.1

import type { ReactNode } from "react";
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
