// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: BUSL-1.1

import { useEffect, useState } from "react";
import { NavLink, Outlet } from "react-router-dom";
import { api, UI_VERSION, UnauthorizedError } from "../api";
import { useAuth } from "../auth";

/// App chrome: nav + a UI↔API version-drift banner + the signed-in user + logout. The routed view
/// renders in <Outlet>.
export function Layout() {
  const { me, mode, role, logout } = useAuth();
  const [apiVersion, setApiVersion] = useState<string | null>(null);
  const session = mode === "session";
  const admin = session && role === "admin";

  useEffect(() => {
    api
      .version()
      .then((v) => setApiVersion(v.version))
      .catch((e) => {
        if (!(e instanceof UnauthorizedError)) setApiVersion(null);
      });
  }, []);

  const drift = apiVersion !== null && apiVersion !== UI_VERSION;

  return (
    <div className="app">
      <header className="topbar">
        <span className="brand">Light WAF</span>
        <nav>
          <NavLink to="/" end>
            Overview
          </NavLink>
          <NavLink to="/events">Events</NavLink>
          <NavLink to="/alerts">Alerts</NavLink>
          {admin && <NavLink to="/users">Users</NavLink>}
          {admin && <NavLink to="/tokens">Tokens</NavLink>}
          {admin && <NavLink to="/audit">Audit</NavLink>}
          {session && <NavLink to="/account">Account</NavLink>}
        </nav>
        <span className="spacer" />
        {me && (
          <span className="whoami" title={`signed in via ${me.via}`}>
            {me.actor} <span className="role-chip">{me.role}</span>
          </span>
        )}
        <span className="version" title={`UI ${UI_VERSION} · API ${apiVersion ?? "?"}`}>
          v{UI_VERSION}
        </span>
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
  );
}
