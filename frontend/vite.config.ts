/// <reference types="vitest/config" />
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// The UI is served by the Bytasm API itself (same origin) after `npm run build`.
// `npm run dev` proxies /api to a running `bytasm serve`. The proxy rewrites
// Host and Origin to the API's own, because the API refuses any other origin.
const api = process.env.BYTASM_API ?? "http://127.0.0.1:8000";

export default defineConfig({
  plugins: [react()],
  server: {
    host: "127.0.0.1",
    port: 5173,
    strictPort: true,
    proxy: {
      "/api": { target: api, changeOrigin: true, headers: { Origin: api } },
    },
  },
  build: { outDir: "dist", sourcemap: false },
  test: {
    environment: "jsdom",
    include: ["src/**/*.test.{ts,tsx}"],
    setupFiles: ["src/test-setup.ts"],
  },
});
