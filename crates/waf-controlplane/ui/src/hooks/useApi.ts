// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

import { useCallback, useEffect, useRef, useState } from "react";

export interface AsyncState<T> {
  data: T | null;
  loading: boolean;
  error: string | null;
  reload: () => void;
  /// Silent refetch: refresh the data WITHOUT the loading spinner (keeps showing current data),
  /// for live updates driven by the SSE stream. Swallows transient errors like the poll path.
  refresh: () => void;
  /// Epoch-ms of the last SUCCESSFUL load (initial or a poll), or `null` before the first success.
  lastUpdated: number | null;
}

export interface UseApiOptions {
  /// When set, re-fetch silently every `pollMs` milliseconds so the view stays live without a page
  /// refresh. Background refreshes keep showing the current data (no spinner) and swallow transient
  /// errors (a blip does not wipe the dashboard); the initial load still surfaces loading/error.
  pollMs?: number;
}

/// Load data from an async source on mount (and when `deps` change), tracking loading/error state.
/// With `options.pollMs`, it also polls in the background: paused while the tab is hidden, never
/// overlapping in-flight requests, and refreshed immediately when the tab regains focus.
///
/// The 401 → login handoff is done inside `api.ts` (it clears the token); a re-render of the gate
/// then drops back to the prompt, so views only see real data errors here.
export function useApi<T>(
  fetcher: () => Promise<T>,
  deps: unknown[] = [],
  options: UseApiOptions = {},
): AsyncState<T> {
  const { pollMs } = options;
  const [data, setData] = useState<T | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [lastUpdated, setLastUpdated] = useState<number | null>(null);
  const [nonce, setNonce] = useState(0);

  // eslint-disable-next-line react-hooks/exhaustive-deps
  const memoFetcher = useCallback(fetcher, deps);

  // Keep the latest fetcher reachable from the stable `refresh` callback without re-subscribing.
  const fetcherRef = useRef(memoFetcher);
  fetcherRef.current = memoFetcher;
  const mountedRef = useRef(true);
  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
    };
  }, []);

  // Foreground load: on mount, on deps change, and on explicit reload(). Shows the spinner.
  useEffect(() => {
    let live = true;
    setLoading(true);
    setError(null);
    memoFetcher()
      .then((d) => {
        if (live) {
          setData(d);
          setLastUpdated(Date.now());
        }
      })
      .catch((e) => {
        if (live) setError(e instanceof Error ? e.message : String(e));
      })
      .finally(() => {
        if (live) setLoading(false);
      });
    return () => {
      live = false;
    };
  }, [memoFetcher, nonce]);

  // Background polling: silent refresh, no overlap, paused when the tab is hidden.
  useEffect(() => {
    if (!pollMs) return;
    let live = true;
    let inFlight = false;
    const tick = () => {
      if (!live || inFlight || document.hidden) return;
      inFlight = true;
      memoFetcher()
        .then((d) => {
          if (live) {
            setData(d);
            setError(null); // recovered — clear a stale error banner
            setLastUpdated(Date.now());
          }
        })
        .catch(() => {
          /* keep last-good data on a transient poll error */
        })
        .finally(() => {
          inFlight = false;
        });
    };
    const id = setInterval(tick, pollMs);
    const onVisible = () => {
      if (!document.hidden) tick();
    };
    document.addEventListener("visibilitychange", onVisible);
    return () => {
      live = false;
      clearInterval(id);
      document.removeEventListener("visibilitychange", onVisible);
    };
  }, [memoFetcher, pollMs]);

  const reload = useCallback(() => setNonce((n) => n + 1), []);

  // Silent refetch for SSE-driven live updates: no spinner, keep-last-good on a transient error.
  const refresh = useCallback(() => {
    fetcherRef.current()
      .then((d) => {
        if (mountedRef.current) {
          setData(d);
          setError(null);
          setLastUpdated(Date.now());
        }
      })
      .catch(() => {
        /* keep last-good data on a transient error */
      });
  }, []);

  return { data, loading, error, reload, refresh, lastUpdated };
}
