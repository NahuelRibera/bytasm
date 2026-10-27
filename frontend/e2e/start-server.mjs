// Start `bytasm serve` for the Playwright suite with a fresh, throwaway data
// directory. Usage: node e2e/start-server.mjs <fixtures|self_built> <port>
// The fixtures server is the real `bytasm serve` with default configuration.
import { spawn } from "node:child_process";
import { rmSync } from "node:fs";
import { resolve } from "node:path";

const [policy, port] = process.argv.slice(2);
const dataDir = resolve(import.meta.dirname, "..", ".e2e-data", policy);
rmSync(dataDir, { recursive: true, force: true });

// self_built is test-only here (a generated fixture copy); see backend/tests/serve_for_e2e.py.
const args =
  policy === "self_built"
    ? ["run", "--no-sync", "python", "tests/serve_for_e2e.py", dataDir, port]
    : ["run", "--no-sync", "bytasm", "serve"];
const child = spawn("uv", ["--directory", "../backend", ...args], {
  cwd: resolve(import.meta.dirname, ".."),
  stdio: "inherit",
  env: {
    ...process.env,
    BYTASM_DATA_DIR: dataDir,
    BYTASM_PORT: port,
    BYTASM_INPUT_POLICY: policy,
  },
});
for (const signal of ["SIGINT", "SIGTERM"]) process.on(signal, () => child.kill(signal));
child.on("exit", (code) => process.exit(code ?? 0));
