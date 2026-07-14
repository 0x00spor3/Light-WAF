// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: BUSL-1.1

import { useEffect, useState } from "react";
import { NavLink, Outlet, useLocation } from "react-router-dom";
import { api, UI_VERSION, UnauthorizedError } from "../api";
import { useAuth } from "../auth";

/// The brand mark is a miniature Verdict Meter — the signature motif: two "allowed" ticks, a
/// threshold notch (signal), and a "blocked" tick past it. Traffic accumulates to a verdict.
function BrandMark() {
  return (
    <svg className="brand-mark" width="22" height="22" viewBox="0 0 22 22" aria-hidden="true">
      <rect x="1.5" y="9" width="19" height="4" rx="2" fill="#0c0f16" stroke="#232a38" />
      <rect x="2.5" y="10" width="6" height="2" rx="1" fill="#2fce8e" />
      <rect x="9" y="10" width="3" height="2" rx="1" fill="#2fe0c0" />
      <rect x="13" y="10" width="6" height="2" rx="1" fill="#fb5468" />
      <rect x="11.4" y="6.5" width="1.2" height="9" rx="0.6" fill="#2fe0c0" />
    </svg>
  );
}

const TITLES: Record<string, string> = {
  "": "Overview",
  events: "Events",
  alerts: "Alerts",
  rules: "Rules",
  users: "Users",
  tokens: "Service tokens",
  audit: "Audit log",
  compliance: "Compliance",
  account: "Account",
};

/// App chrome: a grouped left rail (Monitor / Manage / Govern) + a slim context bar carrying the
/// current section, a UI↔API drift check, the signed-in actor, and sign out. The routed view
/// renders in <Outlet>.
export function Layout() {
  const { me, mode, role, logout } = useAuth();
  const location = useLocation();
  const [apiVersion, setApiVersion] = useState<string | null>(null);
  const session = mode === "session";
  const admin = session && role === "admin";
  // Rule management requires ManageRules (operator+). Token mode = the static bearer (admin-equivalent)
  // can manage too; the backend enforces RBAC either way — nav gating is only cosmetic.
  const canRules = mode === "token" || (session && (role === "admin" || role === "operator"));

  useEffect(() => {
    api
      .version()
      .then((v) => setApiVersion(v.version))
      .catch((e) => {
        if (!(e instanceof UnauthorizedError)) setApiVersion(null);
      });
  }, []);

  const drift = apiVersion !== null && apiVersion !== UI_VERSION;
  const section = location.pathname.split("/").filter(Boolean)[0] ?? "";
  const title = TITLES[section] ?? "Overview";

  return (
    <div className="app">
      <aside className="sidebar">
        <div className="brand">
          <BrandMark />
          <span className="brand-name">
            Light<b>WAF</b>
          </span>
        </div>

        <nav>
          <div className="nav-group">
            <span className="nav-eyebrow">Monitor</span>
            <NavLink to="/" end>
              Overview
            </NavLink>
            <NavLink to="/events">Events</NavLink>
            <NavLink to="/alerts">Alerts</NavLink>
          </div>

          {canRules && (
            <div className="nav-group">
              <span className="nav-eyebrow">Manage</span>
              <NavLink to="/rules">Rules</NavLink>
            </div>
          )}

          {admin && (
            <div className="nav-group">
              <span className="nav-eyebrow">Govern</span>
              <NavLink to="/users">Users</NavLink>
              <NavLink to="/tokens">Tokens</NavLink>
              <NavLink to="/audit">Audit</NavLink>
              <NavLink to="/compliance">Compliance</NavLink>
            </div>
          )}

          {session && (
            <div className="nav-group">
              <span className="nav-eyebrow">You</span>
              <NavLink to="/account">Account</NavLink>
            </div>
          )}
        </nav>

        <div className="sidebar-foot">
          <span className="version" title={`UI ${UI_VERSION} · API ${apiVersion ?? "?"}`}>
            v{UI_VERSION}
          </span>
        </div>
      </aside>

      <div className="main">
        <header className="context-bar">
          <span className="context-title">{title}</span>
          <span className="spacer" />
          {me && (
            <span className="whoami" title={`signed in via ${me.via}`}>
              {me.actor} <span className="role-chip">{me.role}</span>
            </span>
          )}
          <button className="link" onClick={logout}>
            Sign out
          </button>
        </header>
        {drift && (
          <div className="drift-banner">
            UI (v{UI_VERSION}) and API (v{apiVersion}) versions differ — reload after deploying a matching build.
          </div>
        )}
        <main className="content">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
