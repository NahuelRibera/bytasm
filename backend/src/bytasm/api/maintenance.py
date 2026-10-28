"""Start-up sweep (blueprint 5.4.1 limitations, first row).

The filesystem and the database are not one atomic unit: a crash between
placing a blob and committing can leave an unreferenced blob, and a crash
mid-request can leave a temp directory. On start-up, before serving, Bytasm
deletes temp directories and unreferenced stored files older than the sweep
age (1 h).
"""

import shutil
import time
from dataclasses import dataclass

from sqlalchemy import select

from bytasm.api.context import AppContext
from bytasm.db.models import Report, RuleSet, SampleVersion, ToolInvocation


@dataclass(frozen=True)
class SweepResult:
    temp_dirs: int
    blobs: int
    outputs: int
    reports: int


def startup_sweep(ctx: AppContext) -> SweepResult:
    max_age = ctx.settings.sweep_age_seconds
    now = time.time()
    temp_dirs = 0
    if ctx.tmp_dir.is_dir():
        for entry in ctx.tmp_dir.iterdir():
            if now - entry.lstat().st_mtime > max_age:
                if entry.is_dir() and not entry.is_symlink():
                    shutil.rmtree(entry, ignore_errors=True)
                else:
                    entry.unlink(missing_ok=True)
                temp_dirs += 1

    with ctx.sessions() as session:
        outputs = {
            sha
            for sha in session.scalars(select(ToolInvocation.raw_output_sha256))
            if sha is not None
        }
        # Rule-set snapshots live in the outputs store too (bytasm.rules).
        outputs |= set(session.scalars(select(RuleSet.sha256)))
        referenced: dict[str, set[str]] = {
            "blobs": set(session.scalars(select(SampleVersion.sha256))),
            "outputs": outputs,
            "reports": set(session.scalars(select(Report.sha256))),
        }
    removed = {}
    for name, store in (("blobs", ctx.blobs), ("outputs", ctx.outputs), ("reports", ctx.reports)):
        count = 0
        for sha256, age in list(store.stored_hashes()):
            if sha256 not in referenced[name] and age > max_age:
                store.remove(sha256)
                count += 1
        removed[name] = count
    return SweepResult(temp_dirs, removed["blobs"], removed["outputs"], removed["reports"])
