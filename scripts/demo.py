"""Reproducible v0.1 + v0.2 demo (blueprint 13.8), as a script.

  make demo                                  # throwaway native server
  make demo DEMO_ARGS="--keep-running"       # ... and leave it up to browse
  make demo DEMO_ARGS="--url http://127.0.0.1:8000"   # a running `make compose-up`

Steps: check the server is in fixtures-only mode; create a project; import the
committed fixture bin/hello_v1-x86_64.exe (after checking its SHA-256 against
fixtures/MANIFEST.sha256 locally); show that bytes outside the manifest are
refused before parsing; print the metadata the UI shows; export the JSON
report, validate it against schemas/report.schema.json and check that a
second export differs only in `generated_at`; then (v0.2) start a YARA-X run
with Bytasm's bundled rules, wait for the worker to finish it, and check that
every reported byte range matches the fixture's bytes.

Nothing is executed: the fixture is read as bytes and uploaded. Only
127.0.0.1 is contacted; no external service is called.

Cleanup: by default the script starts its own `bytasm serve` and `bytasm
worker` on port 8765 with a new temporary data directory, and on exit stops
both and deletes that directory only. With --url it uses an existing server and deletes
nothing; the project it created ("Demo <timestamp>") stays in that server's
data, like any other project.
"""

import argparse
import base64
import hashlib
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import jsonschema

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = "bin/hello_v1-x86_64.exe"
SCHEMA = ROOT / "schemas" / "report.schema.json"
DEMO_PORT = 8765
ATTESTATION = "I built this file from source code I wrote (Bytasm demo fixture)."
FORBIDDEN_KEYS = {"verdict", "risk", "risk_score", "score", "severity", "malicious"}


class DemoError(Exception):
    pass


class Client:
    def __init__(self, base_url: str) -> None:
        parts = urlsplit(base_url)
        if parts.scheme != "http" or parts.hostname not in ("127.0.0.1", "localhost"):
            raise DemoError("the demo only talks to a local Bytasm on http://127.0.0.1")
        self.base_url = base_url.rstrip("/")

    def request(
        self,
        method: str,
        path: str,
        body: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, dict[str, str], bytes]:
        all_headers = dict(headers or {})
        if method not in ("GET", "HEAD"):
            all_headers["X-Bytasm-Request"] = "1"
        request = urllib.request.Request(  # noqa: S310 - http://127.0.0.1 only, checked above
            self.base_url + path, data=body, method=method, headers=all_headers
        )
        try:
            with urllib.request.urlopen(request, timeout=60) as response:  # noqa: S310
                return response.status, dict(response.headers), response.read()
        except urllib.error.HTTPError as error:
            return error.code, dict(error.headers), error.read()

    def json(self, method: str, path: str, document: Any = None) -> Any:
        body = None if document is None else json.dumps(document).encode()
        headers = {} if body is None else {"Content-Type": "application/json"}
        status, _, raw = self.request(method, path, body, headers)
        if status >= 400:
            raise DemoError(f"{method} {path} failed with {status}: {raw[:300]!r}")
        return json.loads(raw)


def step(text: str) -> None:
    print(f"\n== {text}")


def manifest_hash(entry: str) -> str:
    for line in (ROOT / "fixtures" / "MANIFEST.sha256").read_text().splitlines():
        digest, _, path = line.partition("  ")
        if path == entry:
            return digest
    raise DemoError(f"{entry} is not in fixtures/MANIFEST.sha256")


def import_header(sample_name: str, filename: str) -> str:
    document = {
        "sample_name": sample_name,
        "version_label": "v1",
        "declared_filename": filename,
        "authorization": {"basis": "owned_or_built", "statement": ATTESTATION},
    }
    raw = json.dumps(document, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def upload(client: Client, project_id: str, data: bytes, name: str) -> tuple[int, Any]:
    status, _, raw = client.request(
        "POST",
        f"/api/v1/projects/{project_id}/imports",
        data,
        {"X-Bytasm-Import": import_header(name, name), "Content-Type": "application/octet-stream"},
    )
    return status, json.loads(raw)


def without_generated_at(report: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in report.items() if key != "generated_at"}


def all_keys(value: Any) -> set[str]:
    if isinstance(value, dict):
        return set(value) | {key for item in value.values() for key in all_keys(item)}
    if isinstance(value, list):
        return {key for item in value for key in all_keys(item)}
    return set()


def export_report(client: Client, version_id: str) -> tuple[dict[str, Any], str]:
    created = client.json("POST", f"/api/v1/sample-versions/{version_id}/reports")
    status, headers, raw = client.request("GET", created["download_url"])
    if status != 200:
        raise DemoError(f"report download failed with {status}")
    digest = hashlib.sha256(raw).hexdigest()
    lowered = {key.lower(): value for key, value in headers.items()}
    if digest != created["sha256"] or lowered.get("x-bytasm-report-sha256") != digest:
        raise DemoError("downloaded report does not match its recorded SHA-256")
    return json.loads(raw), digest


def run_demo(client: Client) -> str:
    step("1. Server health and input policy")
    health = client.json("GET", "/api/v1/health")
    print(
        f"   input policy: {health['input_policy']['mode']}, platform: {health['platform']}, "
        f"parser memory limit enforced: {health['parser_memory_limit_enforced']}"
    )
    if health["input_policy"]["mode"] != "fixtures":
        raise DemoError("the demo expects the default fixtures-only mode")

    step("2. Create a project")
    name = f"Demo {datetime.now(UTC).strftime('%Y-%m-%d %H:%M:%S')}"
    project = client.json("POST", "/api/v1/projects", {"name": name})
    print(f"   project: {project['name']} ({project['id']})")

    step(f"3. Import the committed fixture {FIXTURE} (read as bytes, never run)")
    data = (ROOT / "fixtures" / FIXTURE).read_bytes()
    expected = manifest_hash(FIXTURE)
    if hashlib.sha256(data).hexdigest() != expected:
        raise DemoError(f"{FIXTURE} does not match MANIFEST.sha256; refusing to upload it")
    status, body = upload(client, project["id"], data, "hello_v1.exe")
    if status != 201:
        raise DemoError(f"fixture import failed with {status}: {body}")
    version = body["sample_version"]
    print(f"   sha256: {version['sha256']}  size: {version['size_bytes']} bytes")
    print(
        f"   format: {version['detected_format']}  admitted under: {version['admitted_under']} "
        f"({version['manifest_entry']})"
    )
    print(
        f"   authorization: {version['authorization']['basis']} (a self-attestation, "
        "not proof of permission)"
    )

    step("4. Files outside the manifest are refused before parsing")
    # A copy of the fixture with its last byte changed: still a PE file, but its
    # SHA-256 is not in the manifest. Text or other non-PE/ELF bytes are refused
    # even earlier, by the signature check while streaming (415).
    modified = data[:-1] + bytes([data[-1] ^ 0xFF])
    status, refusal = upload(client, project["id"], modified, "hello_v1-modified.exe")
    print(f"   HTTP {status}: {refusal.get('code')} - {refusal.get('detail')}")
    if status != 403:
        raise DemoError("a file outside the manifest was not refused")
    status, refusal = upload(client, project["id"], b"PK\x03\x04 not a binary", "renamed.exe")
    print(f"   HTTP {status}: {refusal.get('code')} - {refusal.get('detail')}")
    if status < 400:
        raise DemoError("a non-PE/ELF file was not refused")

    step("5. Metadata shown on the sample-version page")
    version_id = version["id"]
    sections = client.json("GET", f"/api/v1/sample-versions/{version_id}/sections")
    imports = client.json("GET", f"/api/v1/sample-versions/{version_id}/imports")
    for section in sections["sections"]:
        entropy = section["entropy"]
        shown = "n/a" if entropy is None else f"{entropy:.3f} bits/byte (measurement)"
        print(f"   section {section['name']!r:12} size {section['raw_size']:>6}  entropy {shown}")
    print(f"   imported libraries: {', '.join(imports['libraries']) or '(none)'}")
    print(f"   imported functions: {len(imports['functions'])}")

    step("6. Export the JSON report and validate it")
    report, digest = export_report(client, version_id)
    jsonschema.validate(report, json.loads(SCHEMA.read_text()))
    forbidden = all_keys(report) & FORBIDDEN_KEYS
    if forbidden:
        raise DemoError(f"report contains verdict-like fields: {sorted(forbidden)}")
    tool = report["analysis"]["tool_invocations"][0]
    print(f"   report sha256: {digest}")
    print(
        f"   valid against {SCHEMA.relative_to(ROOT)} (schema_version {report['schema_version']})"
    )
    print(
        f"   generator: {report['generator']['name']} {report['generator']['version']} "
        f"({report['generator']['source_revision']}); LIEF {tool['tool_version']}"
    )
    print(
        f"   admitted_under: {report['input_policy']['admitted_under']}; "
        f"authorization: {report['authorization']['type']}"
    )
    print(f"   limitations: {len(report['limitations'])} stated, no verdict or score fields")

    second, _ = export_report(client, version_id)
    if without_generated_at(second) != without_generated_at(report):
        raise DemoError("two exports differ in more than generated_at")
    print("   a second export differs only in generated_at")

    step("7. Analysis run (v0.2): strings, then YARA-X with Bytasm's bundled rules")
    run = client.json(
        "POST", f"/api/v1/sample-versions/{version_id}/runs", {"profile_id": "default-static"}
    )
    print(f"   run {run['id']} queued with {run['rule_set']['label']}")
    deadline = time.monotonic() + 60
    while run["status"] in ("queued", "running"):
        if time.monotonic() > deadline:
            raise DemoError("the run did not finish within 60 s; is `bytasm worker` running?")
        time.sleep(0.5)
        run = client.json("GET", f"/api/v1/runs/{run['id']}")
    if run["status"] != "succeeded":
        raise DemoError(f"the run ended {run['status']}: {run['failure_message']}")
    findings = client.json("GET", f"/api/v1/runs/{run['id']}/findings")
    by_tool = {item["tool"]: item for item in run["steps"]}
    print(f"   steps: {', '.join(f'{s['tool']} {s['status']}' for s in run['steps'])}")
    strings = client.json(
        "GET", f"/api/v1/sample-versions/{version_id}/strings?query=example.invalid"
    )
    for item in strings["items"]:
        raw = data[item["offset"] : item["offset"] + item["byte_length"]]
        if raw.decode("latin-1")[: len(item["value"])] != item["value"]:
            raise DemoError("an extracted string does not match the fixture's bytes")
    print(
        f"   strings: {run['counts']['strings']} recorded; "
        f"{strings['matched']} contain 'example.invalid', offsets checked against the fixture"
    )
    print(
        f"   YARA-X {by_tool['yara-x']['tool_version']}, "
        f"rule set sha256 {run['rule_set']['sha256']}"
    )
    for finding in findings["findings"]:
        for item in finding["evidence"]:
            start = item["file_offset"]
            if data[start : start + min(item["length"], 32)].hex() != item["excerpt_hex"]:
                raise DemoError("an evidence excerpt does not match the fixture's bytes")
            print(
                f"   matched {finding['rule_id']} {item['pattern_id']} at offset "
                f"{start:#x}, {item['length']} bytes"
            )
    if all_keys(findings) & FORBIDDEN_KEYS:
        raise DemoError("findings contain verdict-like fields")
    print("   every byte range matches the fixture; a match is an observation, not a verdict")

    step("8. JSON report with the run's findings (schema version 2)")
    report, _ = export_report(client, version_id)
    analysis = report["pattern_analysis"]
    if analysis is None or analysis["run"]["id"] != run["id"]:
        raise DemoError("the report does not include the analysis run")
    print(
        f"   pattern_analysis: run {analysis['run']['status']}, "
        f"{len(analysis['findings'])} findings, string counts only (values not exported)"
    )
    return f"{client.base_url}/runs/{run['id']}"


def wait_for_health(client: Client, process: subprocess.Popen[bytes]) -> None:
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise DemoError("bytasm serve exited during start-up")
        try:
            if client.request("GET", "/api/v1/health")[0] == 200:
                return
        except OSError:
            pass
        time.sleep(0.25)
    raise DemoError("bytasm serve did not become healthy within 60 s")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--url", help="use this already-running local Bytasm instead")
    parser.add_argument(
        "--keep-running",
        action="store_true",
        help="keep the throwaway server up until Enter is pressed",
    )
    args = parser.parse_args()

    if args.url:
        try:
            page = run_demo(Client(args.url))
        except (DemoError, jsonschema.ValidationError, OSError) as error:
            print(f"\nDEMO FAILED: {error}", file=sys.stderr)
            return 1
        print(f"\nOpen {page} to see the run and its findings in the UI.")
        print("Nothing was deleted. The demo project stays in this server's data.")
        return 0

    if not (ROOT / "frontend" / "dist" / "index.html").exists():
        print("frontend/dist is missing: run `make web-build` first.", file=sys.stderr)
        return 1
    with socket.socket() as probe:
        if probe.connect_ex(("127.0.0.1", DEMO_PORT)) == 0:
            print(f"Port {DEMO_PORT} is already in use; stop that process first.", file=sys.stderr)
            return 1
    data_dir = Path(tempfile.mkdtemp(prefix="bytasm-demo-"))
    env = {
        **os.environ,
        "BYTASM_DATA_DIR": str(data_dir),
        "BYTASM_PORT": str(DEMO_PORT),
        "BYTASM_INPUT_POLICY": "fixtures",
    }
    env.pop("BYTASM_HOST", None)
    client = Client(f"http://127.0.0.1:{DEMO_PORT}")
    server: subprocess.Popen[bytes] | None = None
    worker: subprocess.Popen[bytes] | None = None
    try:
        server = subprocess.Popen(  # noqa: S603 - fixed argv, no shell
            [sys.executable, "-m", "bytasm", "serve"],
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        wait_for_health(client, server)
        worker = subprocess.Popen(  # noqa: S603 - fixed argv, no shell
            [sys.executable, "-m", "bytasm", "worker"],
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        print(f"Started a throwaway bytasm serve on {client.base_url} (data: {data_dir})")
        page = run_demo(client)
        print(f"\nThe UI shows this run and its findings at {page}")
        if args.keep_running:
            input("Open it in a browser, then press Enter to stop the demo server... ")
        return 0
    except (DemoError, jsonschema.ValidationError, OSError) as error:
        print(f"\nDEMO FAILED: {error}", file=sys.stderr)
        return 1
    finally:
        for process in (worker, server):
            if process is None:
                continue
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        # Delete only the directory this run created.
        shutil.rmtree(data_dir, ignore_errors=True)
        print(f"Stopped the demo server and worker and deleted {data_dir}.")


if __name__ == "__main__":
    sys.exit(main())
