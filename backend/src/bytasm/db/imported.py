"""Typed access to the v0.1 import record of a sample version.

Every sample version has exactly one `kind = "import"` run with one LIEF
invocation, written by its import. From v0.2 the same tables also hold
analysis runs, whose invocations leave the LIEF-only columns empty, so those
columns are nullable in the schema. This module selects the import run
explicitly and checks that its values are present, so callers (the overview
API and the JSON report) never read an analysis run by accident.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from bytasm.db.models import AnalysisRun, SampleVersion, ToolInvocation


class ImportRecordMissing(Exception):
    """The database does not hold a complete import record for this version."""


@dataclass(frozen=True)
class ImportRecord:
    run: AnalysisRun
    invocation: ToolInvocation
    started_at: datetime
    finished_at: datetime
    exit_code: int
    raw_output_sha256: str
    entropy_method: str
    header: dict[str, Any]


def import_record(version: SampleVersion) -> ImportRecord:
    runs = [run for run in version.runs if run.kind == "import"]
    if len(runs) != 1 or not runs[0].invocations:
        raise ImportRecordMissing(version.id)
    run = runs[0]
    invocation = run.invocations[0]
    if (
        run.started_at is None
        or run.finished_at is None
        or invocation.exit_code is None
        or invocation.raw_output_sha256 is None
        or invocation.entropy_method is None
        or invocation.header is None
    ):
        raise ImportRecordMissing(version.id)
    return ImportRecord(
        run=run,
        invocation=invocation,
        started_at=run.started_at,
        finished_at=run.finished_at,
        exit_code=invocation.exit_code,
        raw_output_sha256=invocation.raw_output_sha256,
        entropy_method=invocation.entropy_method,
        header=invocation.header,
    )
