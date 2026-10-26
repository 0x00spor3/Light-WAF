// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api, UnauthorizedError, type CapturedRequest } from "../api";
import { useAuth } from "../auth";
import { useApi } from "../hooks/useApi";
import { ErrorState, Loading, Panel, SeverityBadge, VerdictMeter } from "../components/ui";
import { fmtTime } from "../theme";

export function EventDetail() {
  const { id = "" } = useParams();
  const { data, loading, error, reload } = useApi(() => api.event(id), [id]);
  const { mode, role } = useAuth();
  // Viewing a captured request needs ViewCaptures (operator-and-up). In token mode the bearer is the
  // admin-equivalent, so the panel is offered; a viewer session never sees it (and never triggers the
  // audited fetch). This mirrors the server-side RBAC — it is a UX gate, not the security boundary.
  const canViewCaptures = mode === "token" || role === "operator" || role === "admin";

  return (
    <div className="stack">
      <div className="crumbs">
        <Link to="/events">← Events</Link>
      </div>

      {loading ? (
        <Panel>
          <Loading />
        </Panel>
      ) : error ? (
        <Panel>
          <ErrorState error={error} onRetry={reload} />
        </Panel>
      ) : !data ? null : (
        <>
          <Panel title="Verdict" subtitle={data.request_id}>
            <VerdictMeter score={data.score} decision={data.decision} contributions={data.contributions} />
            <dl className="kv" style={{ marginTop: "1.25rem" }}>
              <div>
                <dt>Node</dt>
                <dd className="mono">{data.node}</dd>
              </div>
              <div>
                <dt>Time</dt>
                <dd className="mono">{fmtTime(data.ts)}</dd>
              </div>
              <div>
                <dt>Method</dt>
                <dd className="mono">{data.method ?? "—"}</dd>
              </div>
              <div>
                <dt>Path</dt>
                <dd className="mono wrap">{data.path ?? "—"}</dd>
              </div>
              <div>
                <dt>Client IP</dt>
                <dd className="mono">{data.client_ip ?? "—"}</dd>
              </div>
              <div>
                <dt>Rule</dt>
                <dd className="mono">{data.rule_id ?? "—"}</dd>
              </div>
              <div>
                <dt>Reason</dt>
                <dd>{data.reason ?? "—"}</dd>
              </div>
            </dl>
          </Panel>

          <Panel title="Score breakdown" subtitle="Per-rule contributions that produced the verdict">
            {data.contributions.length === 0 ? (
              <p className="muted">No per-rule contributions were recorded for this event.</p>
            ) : (
              <table>
                <thead>
                  <tr>
                    <th>Module</th>
                    <th>Rule</th>
                    <th>Severity</th>
                    <th className="num">Points</th>
                  </tr>
                </thead>
                <tbody>
                  {data.contributions.map((c, i) => (
                    <tr key={`${c.module}-${c.rule_id}-${i}`}>
                      <td>{c.module}</td>
                      <td className="mono">{c.rule_id}</td>
                      <td>
                        <SeverityBadge severity={c.severity} />
                      </td>
                      <td className="num">{c.points}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </Panel>

          {canViewCaptures && <CapturePanel requestId={id} />}
        </>
      )}
    </div>
  );
}

// ── Captured request (request-capture feature, C5) ────────────────────────────────────────────────

type CaptureFetch = "idle" | "loading" | "loaded" | "none" | "error";

/// The full captured request for a denied event. Revealed on demand (not auto-loaded) because it may
/// hold raw secrets and every view is audited server-side — the reveal makes that access deliberate.
function CapturePanel({ requestId }: { requestId: string }) {
  const [status, setStatus] = useState<CaptureFetch>("idle");
  const [cap, setCap] = useState<CapturedRequest | null>(null);
  const [err, setErr] = useState("");
  const [view, setView] = useState<"text" | "hex">("text");

  async function reveal() {
    setStatus("loading");
    setErr("");
    try {
      const c = await api.eventCapture(requestId);
      setCap(c);
      setStatus("loaded");
    } catch (e) {
      if (e instanceof UnauthorizedError) {
        setErr("Not authorized to view captures.");
        setStatus("error");
      } else if (e instanceof Error && e.message.startsWith("404")) {
        // No capture for this request: feature off, evicted from the node ring before the verdict, or
        // a connection-phase denial the capture module never observed.
        setStatus("none");
      } else {
        setErr(e instanceof Error ? e.message : String(e));
        setStatus("error");
      }
    }
  }

  return (
    <Panel
      title="Captured request"
      subtitle="Full denied request (headers, cookies, body) — access is audited"
      actions={
        status === "loaded" ? (
          <span className="badge" style={{ ["--c" as string]: "var(--signal)" }}>
            revealed
          </span>
        ) : undefined
      }
    >
      {status === "idle" ? (
        <div className="cap-reveal">
          <p className="muted">
            The full request body and headers may contain sensitive data. Revealing it is recorded in
            the audit log.
          </p>
          <button className="ghost" onClick={reveal}>
            Reveal captured request
          </button>
        </div>
      ) : status === "loading" ? (
        <Loading label="Loading capture…" />
      ) : status === "none" ? (
        <div className="cap-reveal">
          <p className="muted">
            No captured request is stored for this event yet. The capture ships on a side-channel a
            moment after the verdict, so it may still be in flight — or it was dropped under heavy
            load, evicted before shipping, or the request was denied before inspection
            (connection-phase). Capture may also be disabled for this node.
          </p>
          <button className="ghost" onClick={reveal}>
            Try again
          </button>
        </div>
      ) : status === "error" ? (
        <ErrorState error={err} onRetry={reveal} />
      ) : cap ? (
        <CaptureView cap={cap} view={view} setView={setView} />
      ) : null}
    </Panel>
  );
}

function CaptureView({
  cap,
  view,
  setView,
}: {
  cap: CapturedRequest;
  view: "text" | "hex";
  setView: (v: "text" | "hex") => void;
}) {
  const bytes = b64ToBytes(cap.body_b64);
  const bodyText = view === "text" ? new TextDecoder().decode(bytes) : toHex(bytes);
  const hasBody = bytes.length > 0;

  return (
    <div className="stack">
      {(cap.redacted.length > 0 || cap.body_truncated) && (
        <div className="cap-banner">
          {cap.redacted.length > 0 && (
            <span>
              🛡 Redacted node-side:{" "}
              {cap.redacted.map((r) => (
                <code key={r} className="mono">
                  {r}
                </code>
              ))}
            </span>
          )}
          {cap.body_truncated && (
            <span>
              ✂ Body truncated to {bytes.length.toLocaleString()} of {cap.body_size.toLocaleString()}{" "}
              bytes.
            </span>
          )}
        </div>
      )}

      <dl className="kv">
        <div>
          <dt>Request line</dt>
          <dd className="mono wrap">
            {cap.method} {cap.path}
            {cap.query ? `?${cap.query}` : ""} {cap.http_version}
          </dd>
        </div>
      </dl>

      <div>
        <h4 className="cap-h">Headers</h4>
        {cap.headers.length === 0 ? (
          <p className="muted">No headers captured.</p>
        ) : (
          <table>
            <tbody>
              {cap.headers.map(([k, v], i) => (
                <tr key={`${k}-${i}`}>
                  <td className="mono nowrap">{k}</td>
                  <td className="mono wrap">{v}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {cap.cookies.length > 0 && (
        <div>
          <h4 className="cap-h">Cookies</h4>
          <table>
            <tbody>
              {cap.cookies.map(([k, v], i) => (
                <tr key={`${k}-${i}`}>
                  <td className="mono nowrap">{k}</td>
                  <td className="mono wrap">{v}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <div>
        <div className="cap-body-head">
          <h4 className="cap-h">Body ({cap.body_size.toLocaleString()} bytes)</h4>
          {hasBody && (
            <div className="cap-body-actions">
              <div className="segmented">
                <button
                  className={`seg ${view === "text" ? "active" : ""}`}
                  onClick={() => setView("text")}
                  type="button"
                >
                  Text
                </button>
                <button
                  className={`seg ${view === "hex" ? "active" : ""}`}
                  onClick={() => setView("hex")}
                  type="button"
                >
                  Hex
                </button>
              </div>
              <button className="ghost" type="button" onClick={() => void navigator.clipboard?.writeText(bodyText)}>
                Copy
              </button>
              <button className="ghost" type="button" onClick={() => downloadBytes(bytes, `capture-${cap.request_id}.bin`)}>
                Download
              </button>
            </div>
          )}
        </div>
        {hasBody ? <pre className="cap-body mono">{bodyText}</pre> : <p className="muted">Empty body.</p>}
      </div>
    </div>
  );
}

/// Decode a base64 body to raw bytes (browser-side; the server stores/serves it unchanged).
function b64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

/// A classic `offset  hex  ascii` hex dump so a binary/obfuscated body stays inspectable.
function toHex(bytes: Uint8Array): string {
  const lines: string[] = [];
  for (let off = 0; off < bytes.length; off += 16) {
    const slice = bytes.subarray(off, off + 16);
    const hex = Array.from(slice)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join(" ");
    const ascii = Array.from(slice)
      .map((b) => (b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : "."))
      .join("");
    lines.push(`${off.toString(16).padStart(8, "0")}  ${hex.padEnd(47)}  ${ascii}`);
  }
  return lines.join("\n");
}

function downloadBytes(bytes: Uint8Array, filename: string) {
  const blob = new Blob([bytes as BlobPart], { type: "application/octet-stream" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}
