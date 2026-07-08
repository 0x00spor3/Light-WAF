// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: BUSL-1.1

// Thin client for the control-plane API. Same-origin (the control plane serves this SPA and the
// API), so no CORS. Two auth modes (detected via GET /api/auth/config):
//  - token mode  (governance off): a bearer token in sessionStorage → Authorization header.
//  - session mode (governance on): an HttpOnly session cookie (set on login) → sent automatically
//    with `credentials: "include"`; no token is held by JS (closes the sessionStorage XSS trade-off).

const TOKEN_KEY = "waf_cp_token";

export function getToken(): string | null {
  return sessionStorage.getItem(TOKEN_KEY);
}

export function setToken(token: string): void {
  sessionStorage.setItem(TOKEN_KEY, token);
}

export function clearToken(): void {
  sessionStorage.removeItem(TOKEN_KEY);
}

/// Thrown on a 401 so the app can drop back to the token prompt.
export class UnauthorizedError extends Error {
  constructor() {
    super("unauthorized");
    this.name = "UnauthorizedError";
  }
}

function authHeaders(): Record<string, string> {
  const token = getToken();
  return token ? { Authorization: `Bearer ${token}` } : {};
}

async function handle<T>(res: Response): Promise<T> {
  if (res.status === 401) {
    clearToken();
    throw new UnauthorizedError();
  }
  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new Error(`${res.status} ${res.statusText}: ${body}`);
  }
  // Some endpoints reply with a bare "ok" (not JSON); fall back to text.
  const text = await res.text();
  if (!text) return undefined as T;
  try {
    return JSON.parse(text) as T;
  } catch {
    return text as unknown as T;
  }
}

async function apiFetch<T>(path: string): Promise<T> {
  return handle<T>(await fetch(path, { headers: authHeaders(), credentials: "include" }));
}

/// POST/PATCH/DELETE with an optional JSON body.
async function apiSend<T>(method: string, path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = { ...authHeaders() };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  return handle<T>(
    await fetch(path, {
      method,
      headers,
      credentials: "include",
      body: body !== undefined ? JSON.stringify(body) : undefined,
    }),
  );
}

// ── DTOs (mirror the Rust model / server response shapes) ─────────────────────────────────────

export interface VersionInfo {
  version: string;
}

export interface NodeStatus {
  node: string;
  last_seen: string;
}

export interface DecisionVolume {
  decision: string;
  total: number;
}

export interface SeriesPoint {
  t: string;
  decision: string;
  count: number;
}

export interface LatencyStats {
  node: string;
  p50_ms: number;
  p95_ms: number;
  p99_ms: number;
  sample_count: number;
}

export interface Contribution {
  module: string;
  rule_id: string;
  severity: string | null;
  points: number;
}

export interface DecisionEvent {
  request_id: string;
  ts: string;
  node: string;
  method: string | null;
  path: string | null;
  client_ip: string | null;
  decision: string;
  rule_id: string | null;
  reason: string | null;
  score: number;
  contributions: Contribution[];
}

export interface Alert {
  rule_name: string;
  group_key: string;
  fired_at: string;
  severity: string;
  value: number;
  threshold: number;
  summary: string;
}

export type GroupBy = "none" | "client_ip" | "rule_id";

export interface AlertRule {
  name: string;
  decision: string | null;
  rule_id: string | null;
  client_ip: string | null;
  group_by: GroupBy;
  window_seconds: number;
  threshold: number;
  severity: string;
  cooldown_seconds: number;
}

// ── Rule management DTOs (§7 write-path) ──────────────────────────────────────────────────────

export interface RuleVersionMeta {
  id: number;
  author: string;
  note: string;
  created_at: string;
  current: boolean;
}

export interface RuleVersion {
  id: number;
  content: string;
  author: string;
  note: string;
  created_at: string;
}

export interface CurrentRule {
  version: number | null;
  content: string | null;
}

export interface NodeRuleStatus {
  node: string;
  applied_version: number | null;
  status: string;
  detail: string;
  reported_at: string;
}

// ── Compliance report DTOs (§8) ───────────────────────────────────────────────────────────────

export interface DecisionCount {
  decision: string;
  count: number;
}

export interface RuleCount {
  rule_id: string;
  count: number;
}

export interface ComplianceReport {
  report_version: number;
  period: { from: string; to: string };
  generated_at: string;
  generated_by: string;
  sections: {
    access_control: {
      total_users: number;
      admins: number;
      disabled_accounts: number;
      active_sessions: number;
      auth_sources: { local: number; oidc: number; other: number };
      users: GovUser[];
      service_tokens: ServiceTokenInfo[];
      controls: string[];
    };
    audit_integrity: {
      chain_ok: boolean;
      verified_through_seq: number;
      chain_head_hash: string;
      total_records: number;
      break_reason: string | null;
      events_in_period: {
        total_in_period: number;
        logins_success: number;
        logins_failed: number;
        throttled: number;
        admin_actions: number;
        rule_changes: number;
      };
      sample: AuditRecord[];
      controls: string[];
    };
    waf_effectiveness: {
      denied_in_period: DecisionCount[];
      top_rules: RuleCount[];
      nodes_covered: string[];
      cumulative_totals: DecisionCount[];
      caveat: string;
      controls: string[];
    };
    alerts_incidents: {
      total: number;
      fired_alerts: Alert[];
      controls: string[];
    };
  };
  content_hash: string;
  signature: string;
  public_key: string;
}

// ── Governance DTOs (§8) ────────────────────────────────────────────────────────────────────────

export type Role = "viewer" | "operator" | "admin";

export interface AuthConfigInfo {
  governance: boolean;
  oidc: boolean;
}

export interface Me {
  actor: string;
  role: Role;
  via: "session" | "token";
}

export interface GovUser {
  id: number;
  username: string;
  role: Role;
  disabled: boolean;
  auth_source: string;
  created_at: string;
}

export interface ServiceTokenInfo {
  id: number;
  name: string;
  role: Role;
  revoked: boolean;
  created_at: string;
}

export interface CreatedToken {
  id: number;
  name: string;
  role: Role;
  token: string;
}

export interface SessionInfo {
  id: string;
  created_at: string;
  expires_at: string;
  current: boolean;
}

export interface AuditRecord {
  seq: number;
  ts: string;
  actor: string;
  action: string;
  target: string | null;
  details: string;
  prev_hash: string;
  hash: string;
  signature: string;
}

export interface VerifyResult {
  ok: boolean;
  count: number;
  public_key: string;
  broken_seq?: number;
  reason?: string;
}

// ── Endpoints ─────────────────────────────────────────────────────────────────────────────────

export const UI_VERSION = __APP_VERSION__;

export const api = {
  /** Public — used for the UI↔API drift check. */
  version: () => apiFetch<VersionInfo>("/api/version"),
  clusterStatus: () => apiFetch<NodeStatus[]>("/api/cluster/status"),
  decisionsVolume: () => apiFetch<DecisionVolume[]>("/api/decisions/volume"),
  decisionsSeries: (windowSeconds: number, bucketSeconds: number) =>
    apiFetch<SeriesPoint[]>(
      `/api/decisions/series?window_seconds=${windowSeconds}&bucket_seconds=${bucketSeconds}`,
    ),
  latency: () => apiFetch<LatencyStats[]>("/api/latency"),
  events: (params: {
    rule_id?: string;
    decision?: string;
    client_ip?: string;
    limit?: number;
  }) => {
    const q = new URLSearchParams();
    if (params.rule_id) q.set("rule_id", params.rule_id);
    if (params.decision) q.set("decision", params.decision);
    if (params.client_ip) q.set("client_ip", params.client_ip);
    if (params.limit) q.set("limit", String(params.limit));
    const qs = q.toString();
    return apiFetch<DecisionEvent[]>(`/api/events${qs ? `?${qs}` : ""}`);
  },
  event: (requestId: string) =>
    apiFetch<DecisionEvent>(`/api/events/${encodeURIComponent(requestId)}`),
  alerts: (limit = 100) => apiFetch<Alert[]>(`/api/alerts?limit=${limit}`),
  alertRules: () => apiFetch<AlertRule[]>("/api/alerts/rules"),

  // ── Rule management (§7 write-path) ──
  ruleVersions: () => apiFetch<RuleVersionMeta[]>("/api/rules/versions"),
  ruleVersion: (id: number) => apiFetch<RuleVersion>(`/api/rules/versions/${id}`),
  ruleCurrent: () => apiFetch<CurrentRule>("/api/rules/current"),
  publishRule: (content: string, note: string) =>
    apiSend<{ id: number }>("POST", "/api/rules/versions", { content, note }),
  rollbackRule: (version: number) => apiSend<string>("POST", "/api/rules/rollback", { version }),
  ruleNodes: () => apiFetch<NodeRuleStatus[]>("/api/rules/nodes"),

  // ── Governance (§8) ──
  /** Public — tells the UI which login flow to use. */
  authConfig: () => apiFetch<AuthConfigInfo>("/api/auth/config"),
  login: (username: string, password: string) => apiSend<Me>("POST", "/api/login", { username, password }),
  logout: () => apiSend<string>("POST", "/api/logout"),
  me: () => apiFetch<Me>("/api/me"),
  oidcLoginUrl: () => "/api/auth/oidc/login",

  users: () => apiFetch<GovUser[]>("/api/users"),
  createUser: (username: string, password: string, role: Role) =>
    apiSend<{ id: number }>("POST", "/api/users", { username, password, role }),
  updateUser: (id: number, patch: { role?: Role; disabled?: boolean }) =>
    apiSend<string>("PATCH", `/api/users/${id}`, patch),
  deleteUser: (id: number) => apiSend<string>("DELETE", `/api/users/${id}`),
  resetPassword: (id: number, new_password: string) =>
    apiSend<string>("POST", `/api/users/${id}/password`, { new_password }),

  tokens: () => apiFetch<ServiceTokenInfo[]>("/api/tokens"),
  createToken: (name: string, role: Role) => apiSend<CreatedToken>("POST", "/api/tokens", { name, role }),
  revokeToken: (id: number) => apiSend<string>("DELETE", `/api/tokens/${id}`),

  audit: (limit = 100) => apiFetch<AuditRecord[]>(`/api/audit?limit=${limit}`),
  verifyAudit: () => apiFetch<VerifyResult>("/api/audit/verify"),

  complianceReport: (from: string, to: string) =>
    apiFetch<ComplianceReport>(
      `/api/compliance/report?from=${encodeURIComponent(from)}&to=${encodeURIComponent(to)}`,
    ),
  verifyCompliance: (bundle: ComplianceReport) =>
    apiSend<{ ok: boolean }>("POST", "/api/compliance/verify", bundle),

  sessions: () => apiFetch<SessionInfo[]>("/api/sessions"),
  revokeSession: (id: string) => apiSend<string>("DELETE", `/api/sessions/${encodeURIComponent(id)}`),
  changePassword: (old_password: string, new_password: string) =>
    apiSend<string>("POST", "/api/me/password", { old_password, new_password }),
};

/// Verify a token by hitting a protected endpoint; returns true if accepted.
export async function verifyToken(): Promise<boolean> {
  try {
    await api.clusterStatus();
    return true;
  } catch (e) {
    if (e instanceof UnauthorizedError) return false;
    // A non-auth error (e.g. 500) means the token was accepted but the call failed — treat as
    // authenticated so the app can surface the real error rather than looping on the login screen.
    return true;
  }
}
