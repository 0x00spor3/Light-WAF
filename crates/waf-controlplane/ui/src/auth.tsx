// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

import { createContext, useContext, useEffect, useState, type ReactNode } from "react";
import { api, clearToken, getToken, setToken, UnauthorizedError, verifyToken, type Me, type Role } from "./api";

type Mode = "loading" | "token" | "session";

interface AuthState {
  mode: Mode;
  /** The signed-in user (session mode); `null` in token mode. */
  me: Me | null;
  role: Role | null;
  logout: () => void;
}

const AuthContext = createContext<AuthState>({ mode: "loading", me: null, role: null, logout: () => {} });

export function useAuth(): AuthState {
  return useContext(AuthContext);
}

/// Gates the app. At startup it reads `/api/auth/config`: with governance ON it shows a
/// username/password (+ SSO) login backed by a session cookie; with governance OFF it falls back to
/// the bearer-token prompt. Children render only once authenticated.
export function AuthGate({ children }: { children: ReactNode }) {
  const [mode, setMode] = useState<Mode>("loading");
  const [oidc, setOidc] = useState(false);
  const [me, setMe] = useState<Me | null>(null);
  const [authed, setAuthed] = useState(false);

  useEffect(() => {
    let live = true;
    api
      .authConfig()
      .then(async (cfg) => {
        if (!live) return;
        setOidc(cfg.oidc);
        if (cfg.governance) {
          setMode("session");
          // A session cookie may already be present (page reload / SSO redirect) — probe it.
          try {
            const who = await api.me();
            if (live) {
              setMe(who);
              setAuthed(true);
            }
          } catch {
            /* not signed in yet → show the login form */
          }
        } else {
          setMode("token");
          setAuthed(getToken() !== null);
        }
      })
      .catch(() => {
        // No auth-config endpoint (older backend) → assume token mode.
        if (live) {
          setMode("token");
          setAuthed(getToken() !== null);
        }
      });
    return () => {
      live = false;
    };
  }, []);

  function logout() {
    if (mode === "session") {
      void api.logout().catch(() => {});
      setMe(null);
    } else {
      clearToken();
    }
    setAuthed(false);
  }

  if (mode === "loading") {
    return (
      <div className="login">
        <div className="state">
          <span className="spinner" /> Loading…
        </div>
      </div>
    );
  }

  if (!authed) {
    return mode === "session" ? (
      <SessionLogin
        oidc={oidc}
        onAuthed={(who) => {
          setMe(who);
          setAuthed(true);
        }}
      />
    ) : (
      <TokenPrompt onAuthed={() => setAuthed(true)} />
    );
  }

  return (
    <AuthContext.Provider value={{ mode, me, role: me?.role ?? null, logout }}>{children}</AuthContext.Provider>
  );
}

function SessionLogin({ oidc, onAuthed }: { oidc: boolean; onAuthed: (me: Me) => void }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (!username.trim() || !password) return;
    setBusy(true);
    setError(null);
    try {
      const me = await api.login(username.trim(), password);
      onAuthed(me);
    } catch (err) {
      setError(err instanceof UnauthorizedError ? "Invalid credentials." : String(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="login">
      <form onSubmit={submit} className="login-card">
        <h1>Light WAF — Control Plane</h1>
        <p className="muted">Sign in to continue.</p>
        <input
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          placeholder="Username"
          autoFocus
          autoComplete="username"
        />
        <input
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          placeholder="Password"
          autoComplete="current-password"
        />
        <button type="submit" disabled={busy || !username.trim() || !password}>
          {busy ? "Signing in…" : "Sign in"}
        </button>
        {oidc && (
          <>
            <div className="or-sep">or</div>
            <a className="sso-btn" href={api.oidcLoginUrl()}>
              Sign in with SSO
            </a>
          </>
        )}
        {error && <p className="error">{error}</p>}
      </form>
    </div>
  );
}

function TokenPrompt({ onAuthed }: { onAuthed: () => void }) {
  const [token, setTokenInput] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (!token.trim()) return;
    setBusy(true);
    setError(null);
    setToken(token.trim());
    const ok = await verifyToken();
    setBusy(false);
    if (ok) {
      onAuthed();
    } else {
      clearToken();
      setError("Token rejected.");
    }
  }

  return (
    <div className="login">
      <form onSubmit={submit} className="login-card">
        <h1>Light WAF — Control Plane</h1>
        <p className="muted">Enter the API bearer token.</p>
        <input
          type="password"
          value={token}
          onChange={(e) => setTokenInput(e.target.value)}
          placeholder="API token"
          autoFocus
        />
        <button type="submit" disabled={busy || !token.trim()}>
          {busy ? "Checking…" : "Sign in"}
        </button>
        {error && <p className="error">{error}</p>}
      </form>
    </div>
  );
}
