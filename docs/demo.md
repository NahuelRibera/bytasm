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
   differs only in `generated_at`.

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
7. `make compose-down`.

The recording itself is not in the repository yet (a release-gate item).
