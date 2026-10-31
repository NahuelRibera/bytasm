# Optional Ghidra provider setup

Ghidra is optional. Existing imports, strings, YARA-X and capa work without it.
Bytasm never installs Ghidra or Java at application startup. Use only trusted
caller-installed tools and the existing admitted fixtures. Arbitrary third-party
input remains refused, even if you have permission to inspect it.

The fixed profile targets Ghidra 12.2 with 64-bit JDK 25, as required by the
[official versioned installation documentation](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.2_build/GhidraDocs/GettingStarted.md).
Native executables and JDK must match the **worker host**, not the binary's CPU.
The official archive may require native components to be built for your host;
see its included GettingStarted.md. Do not use a macOS JDK inside Linux Compose.

## Configure an offline worker

Install/extract tools outside the checkout. Set absolute roots containing
Ghidra/application.properties and JDK release/bin/java respectively. The optional
[Compose example](../compose.ghidra.example.yaml) mounts only those installation
roots read-only, with a 256 MiB noexec project workspace. It does not mount your
home directory, samples, Ghidra projects/preferences, or Docker socket.

```sh
export BYTASM_GHIDRA_HOME=/absolute/path/to/ghidra_12.2_PUBLIC
export BYTASM_GHIDRA_JAVA_HOME=/absolute/path/to/linux-jdk25
make web-build
COMPOSE_FILE=compose.yaml:compose.ghidra.example.yaml \
  uv --directory backend run --no-sync python ../scripts/check_compose.py --ghidra-installations
BYTASM_SOURCE_REVISION=local docker compose -f compose.yaml -f compose.ghidra.example.yaml build
BYTASM_SOURCE_REVISION=local docker compose -f compose.yaml -f compose.ghidra.example.yaml up -d

docker compose -f compose.yaml -f compose.ghidra.example.yaml exec worker python -m bytasm doctor
```

The default Compose checker continues to reject host mounts. The explicit
--ghidra-installations verification mode permits only the two supplied exact
read-only installation roots on the offline worker, with fixed container targets.
It does not permit API mounts, writable tools, arbitrary targets or other roots.

The tool roots must contain all libraries/native executables needed by that
installation. Doctor is the operational check; metadata and file presence do
not establish it. No binary distribution is included in the image. An absent
native decompiler or loader/compiler dependency must be fixed in the caller's
installation/environment, not bypassed with a fake health result.

The worker must run as non-root, no effective capabilities, no-new-privileges,
no active non-loopback interfaces or IPv4/IPv6 routes, cgroup v2 memory 1–4 GiB,
pids 32–256, CPU quota at most 2 CPUs, and a dedicated 32–512 MiB tmpfs workspace.
Default Compose supplies network-none, 2 GiB memory, 128 pids and 2 CPUs. The optional
override adds the Ghidra workspace. These are resource/offline controls, not a
complete sandbox. The application data volume remains shared with the API.

The API uses the worker's bounded no-sample health record only while its
heartbeat is fresh (30s). An unavailable worker does not expose a run profile.
If you change tool configuration, restart the worker. Every run rechecks its
current admission, hash, profile/script identity and execution controls.

## Doctor and Tools semantics

- not_configured/installation_invalid/unsupported_version: fixed metadata
  locations or reviewed Ghidra version did not pass preflight; no launch.
- java_missing/java_incompatible/unsupported_host: missing JDK 25, incompatible
  declared architecture or unreviewed host; no analysis.
- self_check_failed: bounded Headless/native empty-program health test failed.
  It imported no sample. No raw tool errors or personal paths are disclosed.
- available=true,health_check=passed: the actual no-sample health test passed.
- analysis_enabled=false with isolation_unavailable/resource_constraint: health
  can pass while the worker lacks required controls. Do not bypass this state.
- analysis_enabled=true: health and worker controls passed; Tools exposes the
  Ghidra function review profile. A subsequent sample run can still fail.

Doctor exits0 after actual health success,1 otherwise; it does not create an
application database. Tools separates health from analysis availability.
Native macOS/Windows sample analysis is unavailable. There is no native fallback
that silently sends samples through a network-capable worker.

## Review an admitted fixture

Import a committed fixture and enter its authorization statement. Choose
**Ghidra function review** when Tools reports a functioning offline worker.
The run page shows queued/running/failure/cancellation states. Completed results
show an evidence-led count summary, exact run/version identity and limits.
Search/page the function inventory, open a function, inspect available pseudocode,
instructions and direct static call relationships. Details are limited to the
first 16 functions on the initial run. Inventory is bounded at 1024 entries.
Inventory-only functions say so. Select up to eight entries and request a new
selected-function run for bounded pseudocode, instructions and direct calls.
That explicit action repeats the bounded import/analysis; it may take three
minutes. Search and opening stored evidence never start a parser. Exact matching
requests reuse an active/completed job. Cancel through the selected run page. The static-call view has a source/target address table.

Export the separate JSON or self-contained HTML report from that run. Exports
include sample-derived pseudocode and names: review them before sharing.
Exports are generated from the hash-verified canonical Ghidra document and do
not enter the existing report library/history. Existing schema 2/3/4 reports and
baseline comparisons continue to use their original profiles. Ghidra comparison,
advanced reference/data extraction and report-library integration remain future
work. One-hop call exploration uses retained direct-call windows only; it does
not promise complete incoming references. See the v0.6 milestone for new results.

## Opt-in verification lanes

With verified external Linux tools and a local locked-dependency dev image:

```sh
BYTASM_GHIDRA_TEST_IMAGE=your-local-dev-image ./scripts/check-ghidra-real.sh
make web-build
BYTASM_GHIDRA_TEST_IMAGE=your-local-dev-image node scripts/check-ghidra-browser.mjs
```

Both also require the exported absolute BYTASM_GHIDRA_HOME and
BYTASM_GHIDRA_JAVA_HOME roots. The browser lane requires the existing frontend
Playwright Chromium installation. It creates disposable API/offline-worker
containers and a uniquely named data volume, binds only a random localhost port,
uses manifest-admitted fixtures and removes its own containers/volume in finally.
It imports nothing from the user's projects and never executes a sample.
Screenshots and the selected report stay in backend/.pytest_cache/v06/browser-real
for local review. This is a development verification helper, not deployment or
third-party intake. Worker scratch uses a separate noexec tmpfs, so the lane also
checks publication of verified output onto a different persistent filesystem.
