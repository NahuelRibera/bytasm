// Opt-in real browser/API/offline-worker lane. No fixture is executed.
// Caller supplies verified Linux Ghidra/JDK roots and a local dev runtime image.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdirSync, readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { createServer } from "node:net";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const require = createRequire(join(root, "frontend/package.json"));
const { chromium, expect } = require("@playwright/test");
const { default: AxeBuilder } = require("@axe-core/playwright");
const toolHome = process.env.BYTASM_GHIDRA_HOME;
const javaHome = process.env.BYTASM_GHIDRA_JAVA_HOME;
const image = process.env.BYTASM_GHIDRA_TEST_IMAGE;
assert(toolHome && javaHome && image, "Explicit verified caller tools and dev image are required");
assert(readFileSync(join(root, "frontend/dist/index.html")).length, "Build the UI first");
const artifacts = join(root, "backend/.pytest_cache/v06/browser-real");
mkdirSync(artifacts, { recursive: true });
const token = `bytasm-v06-browser-${randomBytes(5).toString("hex")}`;
const containers = [];
let volumeCreated = false;
let browser;
const docker = args => execFileSync("docker", args, { encoding: "utf8", timeout: 30000, stdio: ["ignore", "pipe", "pipe"] }).trim();
const pause = () => new Promise(done => setTimeout(done, 250));
const probe = createServer();
await new Promise(done => probe.listen(0, "127.0.0.1", done));
const port = probe.address().port;
await new Promise(done => probe.close(done));
const base = `http://127.0.0.1:${port}`;
const shared = ["--read-only", "--user", "10001:10001", "--cap-drop", "ALL",
  "--security-opt", "no-new-privileges", "--memory", "2g", "--memory-swap", "2g",
  "--cpus", "2", "--pids-limit", "128", "--init",
  "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=64m,mode=1777",
  "-v", `${token}:/data`, "-e", "BYTASM_INPUT_POLICY=fixtures", "-e", "BYTASM_DATA_DIR=/data",
  "-v", `${root}/backend/src/bytasm:/app/backend/src/bytasm:ro`,
  "-v", `${root}/fixtures/MANIFEST.sha256:/app/fixtures/MANIFEST.sha256:ro`,
];
const start = (name, args) => {
  const id = docker(["run", "--detach", "--name", name, ...shared, ...args]);
  containers.push(id);
};
try {
  docker(["volume", "create", token]);
  volumeCreated = true;
  start(`${token}-api`, ["-p", `127.0.0.1:${port}:${port}`,
    "-e", `BYTASM_PORT=${port}`, "-v", `${root}/frontend/dist:/app/frontend/dist:ro`,
    image, "python", "-m", "bytasm", "serve"]);
  let ready = false;
  const startupDeadline = Date.now() + 30000;
  while (!ready && Date.now() < startupDeadline) {
    try { ready = (await fetch(`${base}/api/v1/health`)).ok; } catch { /* Startup only. */ }
    if (!ready) await pause();
  }
  assert(ready, "The real API did not start");
  start(`${token}-worker`, ["--network", "none",
    "--tmpfs", "/data/tmp:rw,noexec,nosuid,nodev,size=256m,uid=10001,gid=10001,mode=0700",
    "-v", `${toolHome}:/tools/ghidra:ro`, "-v", `${javaHome}:/tools/jdk:ro`,
    "-e", "BYTASM_GHIDRA_HOME=/tools/ghidra", "-e", "BYTASM_GHIDRA_JAVA_HOME=/tools/jdk",
    image, "python", "-m", "bytasm", "worker"]);
  let available = false;
  const healthDeadline = Date.now() + 100000;
  while (!available && Date.now() < healthDeadline) {
    const tools = await (await fetch(`${base}/api/v1/tools`)).json();
    available = tools.profiles?.some(profile => profile.id === "ghidra-static");
    if (!available) await pause();
  }
  assert(available, "Real worker health did not enable Ghidra");
  browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({ viewport: { width: 1280, height: 900 }, acceptDownloads: true });
  const page = await context.newPage();
  await page.goto(base);
  await page.getByLabel("Name", { exact: true }).fill("Real offline Ghidra browser verification");
  await page.getByRole("button", { name: "Create project" }).click();
  await page.getByRole("link", { name: "Import a binary" }).first().click();
  await page.getByLabel("File", { exact: true }).setInputFiles(join(root, "fixtures/bin/inventory_many-x86_64.elf"));
  await page.getByLabel("Statement", { exact: true }).fill("I built this self-authored Bytasm test fixture and am authorized to inspect it statically.");
  await page.getByRole("button", { name: "Import", exact: true }).click();
  await expect(page.getByLabel("Analysis profile")).toBeVisible();
  await page.getByLabel("Analysis profile").selectOption("ghidra-static");
  await page.getByRole("button", { name: "Run Ghidra static analysis…" }).click();
  await page.getByRole("button", { name: "Start run", exact: true }).click();
  await expect(page.getByRole("button", { name: "Search functions", exact: true })).toBeVisible({ timeout: 200000 });
  const sourceRun = page.url().split("/runs/")[1];
  assert(sourceRun, "The source run must be visible");
  await page.getByLabel("Function name, namespace or address").fill("inventory_39_9");
  await page.getByRole("button", { name: "Search functions", exact: true }).click();
  const checkbox = page.getByRole("checkbox", { name: /^Select inventory_39_9 at / });
  await expect(checkbox).toBeVisible();
  await checkbox.focus();
  await page.keyboard.press("Space");
  const requestButton = page.getByRole("button", { name: "Request details (1/8 selected)" });
  await requestButton.focus();
  await page.keyboard.press("Enter");
  await page.getByRole("link", { name: "Open selected-function run" }).click();
  await expect(page.getByRole("button", { name: "Search functions", exact: true })).toBeVisible({ timeout: 200000 });
  const selectedRun = page.url().split("/runs/")[1];
  assert(selectedRun && selectedRun !== sourceRun);
  await page.getByLabel("Function name, namespace or address").fill("inventory_39_9");
  await page.getByRole("button", { name: "Search functions", exact: true }).click();
  await page.getByRole("button", { name: "Inspect inventory_39_9", exact: true }).click();
  const evidence = page.getByRole("region", { name: "Selected function evidence", exact: true });
  await expect(evidence.getByText(/Status: available/)).toBeVisible();
  await evidence.getByText(/Assembly and instruction bytes/).click();
  await expect(evidence.getByRole("table", { name: "Instructions returned by Ghidra" })).toBeVisible();
  await evidence.getByRole("button", { name: "Explore one-hop relationships" }).click();
  await expect(evidence.getByRole("region", { name: "One-hop static call relationships" })).toBeVisible();
  const references = evidence.getByRole("region", { name: "Function body and outgoing references" });
  await expect(references.getByText(/^Exact body address ranges \(1\)$/)).toBeVisible();
  await expect(references.getByText(/No outgoing string, data or external-symbol references were retained/)).toBeVisible();
  const citation = await evidence.getByRole("link", { name: "Original function record" }).getAttribute("href");
  const raw = await (await fetch(`${base}${citation.split("#")[0]}`)).json();
  assert.equal(raw.schema_version, "ghidra-3");
  const rawFunction = raw.functions.find(fn => fn.name === "inventory_39_9" && fn.pseudocode_status === "available");
  assert(rawFunction && rawFunction.body_ranges.length === 1 && rawFunction.references.length === 0);
  assert.equal(rawFunction.body_ranges[0].provenance, "ghidra_function_body");
  const downloadEvent = page.waitForEvent("download");
  await page.getByRole("link", { name: "Export Ghidra report (JSON)" }).click();
  const download = await downloadEvent;
  const reportPath = join(artifacts, "selected-report.json");
  await download.saveAs(reportPath);
  const report = JSON.parse(readFileSync(reportPath, "utf8"));
  assert.equal(report.schema_version, "bytasm-ghidra-report-2");
  assert.equal(report.overview.source_run_id, sourceRun);
  assert.equal(report.overview.run_id, selectedRun);
  assert.equal(report.overview.detailed_functions, 1);
  assert(report.overview.stored_functions > 400);
  const htmlEvent = page.waitForEvent("download");
  await page.getByRole("link", { name: "Export Ghidra report (HTML)" }).click();
  const htmlDownload = await htmlEvent;
  const htmlPath = join(artifacts, "selected-report.html");
  await htmlDownload.saveAs(htmlPath);
  const html = readFileSync(htmlPath, "utf8");
  assert(html.includes("Selected function dossiers") && html.includes("Function inventory"));
  assert(!html.includes("<script"));
  await page.setViewportSize({ width: 360, height: 740 });
  const axe = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag22aa"]).analyze();
  assert.deepEqual(axe.violations.map(item => item.id), []);
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth), 0);
  await page.screenshot({ path: join(artifacts, "workbench-360.png"), fullPage: true });
  console.log("Real browser/API/offline-worker flow passed: fixture import, inventory beyond 256, selected dossier, instructions, relationships, ghidra-3 body range/references, evidence, report, keyboard, 360px and axe.");
} finally {
  if (browser) await browser.close();
  for (const id of containers.reverse()) docker(["rm", "--force", id]);
  if (volumeCreated) docker(["volume", "rm", token]);
}
