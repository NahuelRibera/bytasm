# v0.1 demo

Two ways to show v0.1: a script that checks every step, and the 2-minute
walkthrough of blueprint §13.8 for a recording. Both use only the committed
fixture `fixtures/bin/hello_v1-x86_64.exe`, whose SHA-256 is in
`fixtures/MANIFEST.sha256`. The fixture is uploaded as bytes and parsed
statically. It is never executed, and nothing contacts a service outside
`127.0.0.1`.

## Scripted demo (`make demo`)

```sh
make install
make demo                       # throwaway native server on 127.0.0.1:8765
```

[`scripts/demo.py`](../scripts/demo.py):

1. checks `/api/v1/health` reports the default `fixtures` mode;
2. creates a project "Demo <UTC time>";
3. checks the fixture's SHA-256 against the manifest locally, then imports it;
4. shows two refusals: a one-byte-modified copy of the fixture (403, input
   policy: not parsed or stored) and bytes starting with a ZIP signature (415,
   refused by content);
5. prints what the sample-version page shows (identity, provenance,
   self-attestation, sections with entropy, imports) and the page's URL;
6. exports the JSON report, checks the downloaded file's SHA-256, validates it
   against [`schemas/report.schema.json`](../schemas/report.schema.json), checks
   that it has no verdict or score fields, and checks that a second export
   differs only in `generated_at`;
7. (v0.2) starts an analysis run (strings, then YARA-X with Bytasm's bundled
   rules), waits for the worker to finish both steps, checks a searched string
   and every reported byte range against the fixture's bytes. The throwaway
   mode starts its own `bytasm worker`; with `--url`, the server needs one
   (`make serve` and `make compose-up` start it);
8. (v0.2) exports the report again and checks that `pattern_analysis`
   (schema version 3) holds that run's findings.

It exits non-zero if any step does not behave as described.

### Cleanup

- **Default (throwaway server):** the script starts `bytasm serve` with a new
  temporary data directory (`bytasm-demo-*` under the system temp directory)
  on port 8765. On exit, including on failure or Ctrl+C, it stops that server
  and deletes that directory, and nothing else. Your `./data/` and the
  `bytasm-data` volume are not touched.
- **`--keep-running`:** the same, but it waits for Enter before cleaning up, so
  you can open the printed URL in a browser.
- **`DEMO_ARGS="--url http://127.0.0.1:8000"`:** runs against a server you
  started (`make compose-up` or `make serve`). The script deletes nothing: the
  demo project stays in that server's data like any project you created. Bytasm
  v0.1 has no delete endpoint. To remove *all* Compose data, including anything
  else you imported, run `docker compose down --volumes` yourself.

## 2-minute walkthrough (blueprint §13.8)

1. `make compose-up`, open http://127.0.0.1:8000/, create project "Demo".
2. **Import a binary** → `fixtures/bin/hello_v1-x86_64.exe`. Point out:
   - the input-policy disclosure: self-authored only, not for downloaded or
     suspicious files; Bytasm never runs them;
   - the `owned_or_built` basis and its "self-attestation, not proof of
     permission" notice.

   Show SHA-256, format, and architecture.
3. Import a file that is not in the manifest (a copy of the fixture with one
   byte changed) and show the refusal: "not parsed or stored". Then a renamed
   ZIP, refused by its content.
4. Sample overview: admitted-under policy, sections with entropy (the
   "measurement" label), imports.
5. **Export JSON report**: show the generator version and source revision, the
   LIEF version, the self-attestation block, `admitted_under`, and the
   limitations.
6. Show the tests for the input policy, upload rejection and timeout, and the
   Compose checks. Say plainly: "The subprocess limits handle parser bugs. They
   are not a sandbox, and neither is the container. That's why v0.1 only parses
   self-authored files, and accepting other files needs an isolation gate."
7. (v0.2) **Run pattern matching…** → confirm → both steps succeed. Inspect
   `url_reference`: offset, length, the bytes `https://`, and the rule text.
   Say: "A match is an observation, not a verdict; no match would not mean
   safe." Open **Search the strings**, search `example.invalid`, and point at
   the offset.
8. `make compose-down`.

The recording itself is not in the repository yet (a release-gate item).

## v0.3 walkthrough

`make demo` now also creates a cited conclusion, revises it, checks that both
revisions remain intact, imports the self-authored hello_v2 ELF fixture as another
version of the same sample, and exports a schema 3 comparison report. Its
unanalysed second version deliberately demonstrates unavailable tool results.
The script checks both manifest hashes and uses only its temporary data folder.

For the full UI flow, import and analyse both versions. Choose **Compare
versions**, switch categories and inspect source links. On the version page or
inside a finding's evidence panel, open **Add note / View annotations**. Create
a Conclusion with confidence and a selected citation, revise it, then open
**Revision history**. Return to the project to see the two annotation events.
Export the comparison JSON from the comparison screen. The Playwright
`compare-annotate.spec.ts` test performs this flow at 360 px with axe checks.


## v0.4 extension

The scripted demo now also imports the self-authored
`capa_environment-x86_64.exe`, selects Full static review, waits for all three
steps, verifies the positive environment-query observation and downloads the
schema 4 standalone HTML with its CSP. No fixture is executed. The native demo
uses its own temporary database and stops/deletes only its own resources.

For a manual review: open **Tools**, inspect actual versions and two-rule scope;
create a project and import the positive PE fixture; select **Full static
review**; inspect capa's function virtual address and limitations; add a cited
conclusion; return to the version's **Reports**, choose **Preview new report**
and download JSON/HTML. For comparisons, use two versions of the same sample,
review the capabilities compatibility state, then preview the comparison report.
HTML can be opened offline and printed without scripts or remote assets.

## Post-PR6 evidence-led journey

`make demo` now includes a twelfth check: the exact run's reviewed explanations,
the immutable report's explanatory view and bounded length-sorted strings from
that same run. It prints scope/count verification, not extracted string values.

For the UI: import an allowed fixture, inspect **Section sizes and entropy
measurements**, run Quick/Full, read **Why these observations appear**, follow
**Inspect exact finding and evidence**, and open **Search the strings**. The
link pins the source run. Filter by a heuristic prefix category, choose sorting
or page-local grouping, and explicitly reveal path-like values only when useful.
A section link returns to the exact source row. Preview a report to inspect the
same canonical source records and download escaped standalone HTML. Comparison
remains available for two authorized versions of the same sample, with explicit
missing/incompatible categories and signed counts. No file is executed.

## Optional Ghidra preflight

Run `uv --directory backend run --no-sync bytasm doctor` to inspect optional
metadata configuration without importing a sample or starting a worker. Exit 1
means the optional provider is unavailable; it does not indicate that Quick/Full
are broken. Open **Tools and profiles** for the same bounded diagnostic. Ghidra
analysis and a function-detail demo are not shipped in this increment. The
existing 12-step fixture demo remains the actual supported analysis workflow.

## Optional Ghidra review

Follow docs/ghidra-setup.md to supply trusted Linux Ghidra12.2/JDK25 roots to
the offline worker. The standard demo still works with no optional provider.
Run worker doctor and confirm an actual passed health check and enabled analysis;
installation metadata alone is insufficient.

Import hello_v1-x86_64.elf from the committed fixtures, enter its authorization,
select Ghidra function review, and wait for the recorded worker result. Open its
run: read verified observations and limits, search/page the function inventory,
inspect a detailed function's pseudocode/instructions and static call table,
then download the run's separate JSON/HTML exports. Inventory-only functions
remain explicitly unavailable for detailed analysis. Do not execute the fixture.

The real opt-in verification command is scripts/check-ghidra-real.sh with
BYTASM_GHIDRA_HOME, BYTASM_GHIDRA_JAVA_HOME and BYTASM_GHIDRA_TEST_IMAGE set to
verified local tools/a test image. It runs real health, admitted-fixture extraction,
API-to-worker export and bounded cancellation/timeout tests in an offline,
non-root container. It performs no downloads. The frontend accessibility test
uses explicitly synthetic API records and is separate from real-tool evidence.
