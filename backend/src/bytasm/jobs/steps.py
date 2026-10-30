"""What the worker's analysis steps share: dependencies, input, and outcome.

A step runner (bytasm.jobs.strings_step, bytasm.jobs.scan) receives bytes the
pipeline has just verified (admission and SHA-256), runs its tool in a
resource-limited child process inside the step's private work directory, and
validates the child's result against those bytes. It returns a `StepOutcome`
and writes nothing to the database: the pipeline (bytasm.jobs.pipeline)
records every outcome, in its own transaction.
"""

from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session, sessionmaker

from bytasm.db.models import Base
from bytasm.ghidra import GhidraConfiguration
from bytasm.intake.policy import InputPolicy
from bytasm.runner.limits import ParserLimits
from bytasm.runner.supervisor import adapter_command, strings_adapter_command
from bytasm.storage import ContentStore


@dataclass(frozen=True)
class ScanDeps:
    sessions: sessionmaker[Session]
    blobs: ContentStore
    outputs: ContentStore
    policy: InputPolicy
    limits: ParserLimits
    tmp_dir: Path
    ghidra: GhidraConfiguration = field(default_factory=GhidraConfiguration, kw_only=True)
    # The YARA-X adapter child (tests substitute a fake).
    adapter_command: list[str]
    strings_command: list[str] = field(default_factory=strings_adapter_command)
    capa_command: list[str] = field(
        default_factory=lambda: adapter_command("bytasm.adapters.capa_scan")
    )


@dataclass(frozen=True)
class StepInput:
    run_id: str
    index: int
    step: dict[str, Any]  # this step of the run's profile snapshot
    sample_sha256: str
    data: bytes  # verified against sample_sha256 just before the step
    workdir: Path  # private (0700); holds upload.bin (0400)
    should_stop: Callable[[], bool]  # cancel requested, or the worker is stopping


@dataclass
class StepOutcome:
    """How one step ended. Only a `succeeded` outcome carries results."""

    status: str  # succeeded | failed | timed_out | cancelled
    reason: str | None
    # tool_invocation columns other than run_id, step_index, status, times and raw output.
    invocation: dict[str, Any]
    raw_output: bytes | None = None
    # Given the new invocation's ID, the rows that hold this step's results.
    rows: Callable[[str], list[Base]] | None = None
    # Fields for the worker's structured log line (IDs, hashes, counts only).
    log_fields: dict[str, Any] = field(default_factory=dict)
