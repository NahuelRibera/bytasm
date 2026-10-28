// Start `bytasm serve` for the Playwright suite with a fresh, throwaway data
// directory. Usage: node e2e/start-server.mjs <fixtures|self_built> <port>
// The fixtures server is the real `bytasm serve` with default configuration,
// plus the real `bytasm worker` on the same data directory (v0.2 runs).
import { spawn } from "node:child_process";
import { rmSync } from "node:fs";
import { resolve } from "node:path";

const [policy, port] = process.argv.slice(2);
const dataDir = resolve(import.meta.dirname, "..", ".e2e-data", policy);
rmSync(dataDir, { recursive: true, force: true });

const start = (args) =>
  spawn("uv", ["--directory", "../backend", ...args], {
    cwd: resolve(import.meta.dirname, ".."),
    stdio: "inherit",
    env: {
      ...process.env,
      BYTASM_DATA_DIR: dataDir,
      BYTASM_PORT: port,
      BYTASM_INPUT_POLICY: policy,
    },
  });

// self_built is test-only here (a generated fixture copy); see backend/tests/serve_for_e2e.py.
// That server gets no worker: `bytasm worker` reads the same environment and,
// like `bytasm serve`, refuses self_built outside Linux.
const children = [
  policy === "self_built"
    ? start(["run", "--no-sync", "python", "tests/serve_for_e2e.py", dataDir, port])
    : start(["run", "--no-sync", "bytasm", "serve"]),
];
if (policy === "fixtures") children.push(start(["run", "--no-sync", "bytasm", "worker"]));

for (const signal of ["SIGINT", "SIGTERM"]) {
  process.on(signal, () => children.forEach((child) => child.kill(signal)));
}
children[0].on("exit", (code) => {
  children.slice(1).forEach((child) => child.kill("SIGTERM"));
  process.exit(code ?? 0);
});
