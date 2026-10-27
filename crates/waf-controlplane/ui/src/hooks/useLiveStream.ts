// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

import { useEffect, useRef } from "react";
import { subscribeStream } from "../api";

/// Subscribe to the control-plane SSE stream and run `onNotice` when a notice of `kind`
/// ("events" | "alerts") arrives. Coalesces bursts: at most one call per `debounceMs`, so a flood
/// of ingests under load triggers a single refresh rather than a reload storm. The subscription is
/// opened once and torn down on unmount; `onNotice` may change freely (read via a ref).
export function useLiveStream(kind: string, onNotice: () => void, debounceMs = 400): void {
  const cb = useRef(onNotice);
  cb.current = onNotice;

  useEffect(() => {
    let timer: ReturnType<typeof setTimeout> | null = null;
    const stop = subscribeStream((k) => {
      if (k !== kind || timer !== null) return;
      timer = setTimeout(() => {
        timer = null;
        cb.current();
      }, debounceMs);
    });
    return () => {
      stop();
      if (timer !== null) clearTimeout(timer);
    };
  }, [kind, debounceMs]);
}
