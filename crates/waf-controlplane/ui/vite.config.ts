// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: BUSL-1.1

import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { readFileSync } from "node:fs";

// The control plane serves the SPA at the site root (dev via `ui_dir`, prod via the embedded
// single-binary), so assets are referenced absolutely from `/`.
const pkg = JSON.parse(readFileSync(new URL("./package.json", import.meta.url), "utf-8"));

export default defineConfig({
  base: "/",
  plugins: [react()],
  // The UI's own version (build-time), so it can warn on a UI↔API drift against GET /api/version.
  define: {
    __APP_VERSION__: JSON.stringify(pkg.version),
  },
  server: {
    // Dev only: proxy the API to a locally running control plane so the SPA is same-origin.
    proxy: {
      "/api": { target: "http://127.0.0.1:9600", changeOrigin: true },
      "/healthz": { target: "http://127.0.0.1:9600", changeOrigin: true },
    },
  },
  build: {
    outDir: "dist",
    // Deterministic-ish, small tree; report on anything unusually large.
    chunkSizeWarningLimit: 900,
  },
});
