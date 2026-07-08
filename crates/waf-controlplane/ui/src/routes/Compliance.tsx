// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: BUSL-1.1

import { useState } from "react";
import { api, type ComplianceReport } from "../api";
import { ErrorState, Loading, Panel } from "../components/ui";
import { fmtTime } from "../theme";

/** yyyy-mm-dd for a `type=date` input, `days` ago (0 = today). */
function dateInput(days: number): string {
  const d = new Date();
  d.setDate(d.getDate() - days);
  return d.toISOString().slice(0, 10);
}
/** A date input (yyyy-mm-dd) → RFC3339 at the start / end of that UTC day (what the API expects). */
function toRfc3339(date: string, endOfDay: boolean): string {
  return new Date(`${date}${endOfDay ? "T23:59:59.999Z" : "T00:00:00.000Z"}`).toISOString();
}

/** A row of SOC2/PCI control labels a section satisfies. */
function Controls({ items }: { items: string[] }) {
  return (
    <div className="controls-row">
      <span className="controls-label">Controls:</span>
      {items.map((c) => (
        <span key={c} className="control-chip">
          {c}
        </span>
      ))}
    </div>
  );
}

/** §8: generate a signed SOC2/PCI evidence bundle over a period and render it (admin / ViewAudit). */
export function Compliance() {
  const [from, setFrom] = useState(dateInput(90));
  const [to, setTo] = useState(dateInput(0));
  const [report, setReport] = useState<ComplianceReport | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [sigOk, setSigOk] = useState<boolean | null>(null);

  async function generate() {
    setLoading(true);
    setError(null);
    setSigOk(null);
    try {
      setReport(await api.complianceReport(toRfc3339(from, false), toRfc3339(to, true)));
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }

  async function runVerify() {
    if (!report) return;
    try {
      const { ok } = await api.verifyCompliance(report);
      setSigOk(ok);
    } catch (e) {
      alert(String(e));
    }
  }

  const filters = (
    <div className="filters">
      <label>
        From <input type="date" value={from} onChange={(e) => setFrom(e.target.value)} />
      </label>
      <label>
        To <input type="date" value={to} onChange={(e) => setTo(e.target.value)} />
      </label>
      <button onClick={generate} disabled={loading}>
        {loading ? "Generating…" : "Generate"}
      </button>
      {report && (
        <button className="ghost" onClick={runVerify}>
          Verify signature
        </button>
      )}
      {report && (
        <button className="ghost" onClick={() => window.print()}>
          Print
        </button>
      )}
    </div>
  );

  return (
    <div className="stack compliance">
      <Panel title="Compliance report" subtitle="Signed SOC2 / PCI-DSS evidence bundle" actions={filters}>
        {loading ? (
          <Loading label="Generating evidence…" />
        ) : error ? (
          <ErrorState error={error} onRetry={generate} />
        ) : !report ? (
          <div className="state muted">Pick a period and Generate a signed evidence report.</div>
        ) : (
          <ReportMeta report={report} sigOk={sigOk} />
        )}
      </Panel>
      {report && <ReportSections report={report} />}
    </div>
  );
}

function ReportMeta({ report, sigOk }: { report: ComplianceReport; sigOk: boolean | null }) {
  const ai = report.sections.audit_integrity;
  return (
    <>
      <div className="report-meta">
        <span>
          Period <b>{fmtTime(report.period.from)}</b> → <b>{fmtTime(report.period.to)}</b>
        </span>
        <span className="muted">
          generated {fmtTime(report.generated_at)} by <span className="mono">{report.generated_by}</span>
        </span>
      </div>
      <div className={ai.chain_ok ? "verify-banner ok" : "verify-banner bad"}>
        {ai.chain_ok ? (
          <>
            ✓ Audit chain verified through seq {ai.verified_through_seq} ({ai.total_records} records)
          </>
        ) : (
          <>
            ⚠ Audit chain BROKEN after seq {ai.verified_through_seq}: {ai.break_reason}
          </>
        )}
      </div>
      {sigOk !== null && (
        <div className={sigOk ? "verify-banner ok" : "verify-banner bad"}>
          {sigOk ? "✓ Bundle signature verified" : "⚠ Bundle signature FAILED verification"}
        </div>
      )}
    </>
  );
}

function ReportSections({ report }: { report: ComplianceReport }) {
  const s = report.sections;
  const ac = s.access_control;
  const ai = s.audit_integrity;
  const wf = s.waf_effectiveness;
  const al = s.alerts_incidents;

  return (
    <>
      <Panel title="Access control" subtitle="Accounts, roles and service tokens">
        <div className="metric-row">
          <Metric label="Users" value={ac.total_users} />
          <Metric label="Admins" value={ac.admins} />
          <Metric label="Disabled" value={ac.disabled_accounts} />
          <Metric label="Active sessions" value={ac.active_sessions} />
          <Metric label="Local / OIDC" value={`${ac.auth_sources.local} / ${ac.auth_sources.oidc}`} />
        </div>
        <div className="table-wrap">
          <table className="rows-hover">
            <thead>
              <tr>
                <th>Username</th>
                <th>Role</th>
                <th>Source</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {ac.users.map((u) => (
                <tr key={u.id}>
                  <td className="mono">{u.username}</td>
                  <td>{u.role}</td>
                  <td className="muted">{u.auth_source}</td>
                  <td>{u.disabled ? "disabled" : "active"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <Controls items={ac.controls} />
      </Panel>

      <Panel title="Audit integrity & activity" subtitle="Tamper-evident log + period event summary">
        <div className="metric-row">
          <Metric label="Events (period)" value={ai.events_in_period.total_in_period} />
          <Metric label="Logins ✓ / ✗" value={`${ai.events_in_period.logins_success} / ${ai.events_in_period.logins_failed}`} />
          <Metric label="Throttled" value={ai.events_in_period.throttled} />
          <Metric label="Admin actions" value={ai.events_in_period.admin_actions} />
          <Metric label="Rule changes" value={ai.events_in_period.rule_changes} />
        </div>
        <Controls items={ai.controls} />
      </Panel>

      <Panel title="WAF protection effectiveness" subtitle="Denied traffic + most-triggered rules">
        <div className="metric-row">
          {wf.denied_in_period.map((d) => (
            <Metric key={d.decision} label={`Denied: ${d.decision}`} value={d.count} />
          ))}
          <Metric label="Nodes covered" value={wf.nodes_covered.length} />
        </div>
        {wf.top_rules.length > 0 && (
          <div className="table-wrap">
            <table className="rows-hover">
              <thead>
                <tr>
                  <th>Top rule</th>
                  <th className="num">Hits</th>
                </tr>
              </thead>
              <tbody>
                {wf.top_rules.map((r) => (
                  <tr key={r.rule_id}>
                    <td className="mono">{r.rule_id}</td>
                    <td className="num">{r.count}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <p className="muted caveat">{wf.caveat}</p>
        <Controls items={wf.controls} />
      </Panel>

      <Panel title="Alerts & incidents" subtitle={`${al.total} fired in the period`}>
        {al.fired_alerts.length === 0 ? (
          <div className="state muted">No alerts fired in the period.</div>
        ) : (
          <div className="table-wrap">
            <table className="rows-hover">
              <thead>
                <tr>
                  <th>Rule</th>
                  <th>Group</th>
                  <th>Severity</th>
                  <th>Fired</th>
                </tr>
              </thead>
              <tbody>
                {al.fired_alerts.map((a, i) => (
                  <tr key={`${a.rule_name}-${i}`}>
                    <td className="mono">{a.rule_name}</td>
                    <td className="mono">{a.group_key || "—"}</td>
                    <td>{a.severity}</td>
                    <td className="muted nowrap">{fmtTime(a.fired_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <Controls items={al.controls} />
      </Panel>

      <Panel title="Signature" subtitle="This bundle is tamper-evident (Ed25519)">
        <dl className="sig-list">
          <dt>Content hash</dt>
          <dd className="mono">{report.content_hash}</dd>
          <dt>Signature</dt>
          <dd className="mono">{report.signature}</dd>
          <dt>Public key</dt>
          <dd className="mono">{report.public_key}</dd>
        </dl>
      </Panel>
    </>
  );
}

function Metric({ label, value }: { label: string; value: number | string }) {
  return (
    <div className="metric">
      <span className="metric-value">{value}</span>
      <span className="metric-label">{label}</span>
    </div>
  );
}
