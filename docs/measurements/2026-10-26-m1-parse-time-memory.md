# M1 measurement: LIEF parse time and peak memory

- **Date:** 2026-10-26
- **Why:** blueprint §12 (M1 acceptance) and ADR-0001 D4 ask for parse time and
  peak memory to be measured on the fixtures and on a synthetic file at the
  size limit, and for the §5.4.1 provisional limits to be reviewed afterwards.
- **Outcome:** the measurements support the provisional limits. **No limit is
  changed.** Recommendation and rationale are in [§4](#4-recommendation).

## 1. Method

Script: [`scripts/measure_parse.py`](../../scripts/measure_parse.py).

| Item | How |
|---|---|
| Inputs | All 8 fixtures in `fixtures/MANIFEST.sha256`, plus 3 synthetic files of **exactly 64 MiB** (the upload size limit). The synthetic files are built in memory from fixture bytes and seeded random data. They are test-authored, never written to disk, and not in the manifest. As blueprint §9.2 allows for M1, they go straight to the adapter, like the generated inputs in the tests. `bytasm inspect` refuses them. |
| Synthetic cases | (a) x86-64 ELF fixture + zero padding to 64 MiB (an overlay no section covers). (b) The same ELF with `.comment` redirected to cover ~64 MiB of appended random bytes: one huge section to measure entropy on. (c) A hand-assembled PE32+ with one ~64 MiB `.text` section of random bytes. |
| Isolation | Each case runs in a **fresh child interpreter**, so its peak memory is its own. |
| Timed region | `identify_format` + `extract_metadata` (LIEF parse + per-section entropy) on bytes already in memory, as `bytasm inspect` does. LIEF's parse alone is timed separately. Fixtures: 5 repetitions. Synthetic: 3. The median and the maximum are reported. |
| Memory | `ru_maxrss` of the child (peak resident memory, the whole interpreter included). On Linux, also `VmPeak` from `/proc/self/status`: the peak **virtual** size, which is what `RLIMIT_AS` limits. |
| Limit check | On Linux the child sets `RLIMIT_AS` = 1 GiB (the provisional value) **before importing LIEF**. Every case must still complete. Then the worst case is repeated at lower limits to find the headroom. |
| Execution | Nothing is executed. Files are only read and parsed as data. |

Commands:

```sh
# macOS host (Apple M-series, macOS 27.0.1, Python 3.14.8, LIEF 1.0.0)
make measure
# linux/arm64 container (Python 3.12.15, LIEF 1.0.0, Docker Desktop 29.8.1, 8 vCPU / 3.8 GiB VM)
./scripts/check-linux.sh linux/arm64 3.12 measure
```

Caveats:

- The peak memory of a synthetic case includes building the input itself (random bytes plus concatenation copies). It therefore *overstates* what `bytasm inspect` needs for a 64 MiB file, which reads it once.
- One machine, a quiet but not idle laptop. Times are indicative, not benchmarks.
- **linux/amd64 was not measured.** This Docker Desktop has no x86-64 emulation (`exec format error`), see [§5](#5-not-verified).

## 2. Results: fixtures

Median time per inspection. Sizes in bytes. Memory in MiB.

| Fixture | Size | macOS total | macOS peak RSS | Linux arm64 total | Linux peak RSS | Linux VmPeak |
|---|---:|---:|---:|---:|---:|---:|
| `entropy_blob-aarch64.elf` | 13,672 | 0.5 ms | 73 | 0.4 ms | 69 | 77 |
| `exports_v1-x86_64.dll` | 11,776 | 0.3 ms | 73 | 0.3 ms | 68 | 76 |
| `hello_v1-aarch64-stripped.elf` | 6,168 | 0.3 ms | 73 | 0.2 ms | 68 | 76 |
| `hello_v1-aarch64.elf` | 9,360 | 0.3 ms | 73 | 0.3 ms | 68 | 76 |
| `hello_v1-x86_64-stripped.elf` | 14,544 | 0.2 ms | 73 | 0.2 ms | 68 | 76 |
| `hello_v1-x86_64.elf` | 16,032 | 0.3 ms | 74 | 0.3 ms | 68 | 76 |
| `hello_v1-x86_64.exe` | 14,336 | 0.4 ms | 73 | 0.4 ms | 68 | 76 |
| `hello_v1-x86_64.o` | 1,304 | 0.1 ms | 73 | 0.1 ms | 68 | 76 |

Worst single repetition for any fixture: 2.9 ms (macOS, first run). Peak memory
for fixtures is the interpreter plus LIEF. The parse itself adds ≤ 1 MiB.

## 3. Results: synthetic 64 MiB inputs

| Case | macOS total (max) | macOS LIEF parse | macOS peak RSS | Linux total (max) | Linux LIEF parse | Linux peak RSS | Linux VmPeak |
|---|---:|---:|---:|---:|---:|---:|---:|
| (a) ELF + 64 MiB overlay | 5 ms (22 ms) | 5 ms | 265 | 37 ms (326 ms) | 37 ms | 260 | 268 |
| (b) ELF, one 64 MiB section | 1.26 s (1.33 s) | 14 ms | 269 | 1.75 s (1.80 s) | 40 ms | 260 | 268 |
| (c) PE, one 64 MiB section | 1.24 s (1.24 s) | 4 ms | 269 | 2.03 s (2.05 s) | 19 ms | 260 | 268 |

All 11 Linux cases completed with `RLIMIT_AS` = 1 GiB.

`RLIMIT_AS` headroom, worst case (c), linux/arm64, one run each:

| `RLIMIT_AS` | Result |
|---:|---|
| 512 MiB | completed (1.84 s) |
| 384 MiB | completed (2.09 s) |
| 320 MiB | completed (2.03 s) |
| 256 MiB | **failed**: Python `MemoryError` (a controlled failure, no crash) |

Observations:

- **LIEF's parse is fast** even at 64 MiB (≤ 40 ms). Time grows with the bytes
  covered by sections, and that cost is **Bytasm's own entropy calculation**
  (`collections.Counter` over the section bytes), not LIEF.
- Memory at 64 MiB is about **3–4× the file size plus a ~70 MiB interpreter
  baseline**. The copies are the input bytes, the copy LIEF makes, and the
  slice taken for entropy (plus, in this harness, the generation buffers).

## 4. Recommendation

**Keep all provisional limits unchanged** (blueprint §5.4.1, ADR-0001 D4). Evidence:

| Limit | Provisional | Measured worst case | Headroom | Recommendation |
|---|---|---|---|---|
| Upload size | 64 MiB | 64 MiB inputs parse in ≤ 2.1 s | — | Keep. Nothing measured argues for a different size. |
| Wall-clock timeout | 30 s | 2.05 s (Linux arm64) | ~14× | Keep. The margin also covers slower hosts, emulated amd64 (unmeasured), and structure-heavy files that the simple fixtures do not represent. |
| `RLIMIT_CPU` | 25 s | CPU time not measured separately. The work is single-threaded Python, so expected ≈ wall time (≤ ~2.1 s) | ~12× (estimated) | Keep. |
| `RLIMIT_AS` | 1 GiB | VmPeak 268 MiB. Fails at 256 MiB, passes at 320 MiB | ~3–4× | Keep. Lowering it to ~512 MiB would also pass today, but the margin over real, complex binaries is unknown, and LIEF's allocation pattern on inputs with many sections, symbols, or relocations was not measured. |
| Concurrent parsers | 1 | — | — | Keep. Nothing here measures contention, and one parser at ~270 MiB fits easily. |
| Other derived values | — | Not exercised by this measurement | — | Keep. They are tested in M2/M3. |

Rationale for not tightening yet: the fixtures are tiny, simple programs, and
the synthetic inputs mostly stress size, not structural complexity. A limit
tuned to them could fail on legitimate `self_built` programs later. The
measured numbers show the current values are **not too tight** for v0.1 inputs.
That is what this review needs to establish.

Suggested follow-ups (not done, outside M1 scope):

- Re-run this measurement under the real M2 subprocess runner. Its rlimits are
  self-applied, so the numbers should match, but that is the configuration
  that matters.
- Re-measure on linux/amd64 (CI runner, or a host with emulation) before v0.1.
- If entropy time ever matters, it is the part to optimise (for example,
  `bytes.count` per value, or NumPy), not LIEF.

## 5. Not verified

- **linux/amd64.** It could not be run on this machine: Docker Desktop
  registers no x86-64 binfmt handler (`exec /usr/bin/sh: exec format error`).
  Enabling it (Rosetta or QEMU binfmt) is a system-wide Docker VM change and
  was out of scope. The locked `manylinux_2_28_x86_64` LIEF wheel exists in
  `uv.lock`, and the CI workflow (`ubuntu-latest`, amd64) runs the same suite,
  but CI has not run yet (no remote).
- `RLIMIT_AS` enforcement on macOS. It is not enforced there, as ADR-0001 §5
  expects: limits are meant to hold only in the Linux container.
