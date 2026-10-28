"""Execute one claimed analysis run, step by step (blueprint J5, 5.4.2).

For a run the worker has moved to `running`, in this order:

1. If a cancel was already requested, end the run as `cancelled`.
2. For each step of the run's profile snapshot (v0.2: strings, then YARA-X):
   a. Stop if the worker is stopping or a cancel was requested.
   b. Admission, immediately before the step: re-check the input policy for
      the sample's SHA-256, read the stored blob, and verify its SHA-256 and
      size against the sample_version row. On failure no tool sees the bytes
      and no further step runs.
   c. Write the verified bytes to a private work directory (0700, file 0400)
      and run the step (a resource-limited child process, polled for cancel).
   d. Record the step in its own transaction. A succeeded step stores its raw
      output, its invocation, and its result rows (strings, or findings with
      evidence) only if the run is still running and not cancelled; that
      check is the transaction's first statement (runs.claim_step_commit).
      Files stored by a transaction that does not commit are removed.
   A failed or timed-out step does not stop the run: the next step is
   independent of it. A cancelled step does.
3. Finish the run with the status that follows from its steps
   (runs.final_status): `succeeded`, `partial`, `failed`, or `cancelled`.

Results of steps that finished stay valid when a later step fails: they were
validated against the same verified bytes and committed on their own.

The work directory is deleted and the child's process group is gone on every
exit path (bytasm.runner). Log lines carry IDs, hashes, statuses and counts,
never sample bytes, strings, matched bytes, or rule text.
"""

import hashlib
import json
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Final

from sqlalchemy import select
from sqlalchemy.orm import Session

from bytasm.db.models import AnalysisRun, SampleVersion, ToolInvocation, utcnow
from bytasm.jobs import runs
from bytasm.jobs.scan import run_yara_step
from bytasm.jobs.steps import ScanDeps, StepInput, StepOutcome
from bytasm.jobs.strings_step import run_strings_step
from bytasm.runner import workspace
from bytasm.storage import IntegrityError

log = logging.getLogger("bytasm.worker")

StepRunner = Callable[[ScanDeps, StepInput], Awaitable[StepOutcome]]
STEP_RUNNERS: Final[dict[str, StepRunner]] = {
    runs.STRINGS_TOOL: run_strings_step,
    runs.YARA_TOOL: run_yara_step,
}


@dataclass(frozen=True)
class _Loaded:
    sample_sha256: str
    size_bytes: int
    steps: list[dict[str, Any]]
    cancel_requested: bool


def _load(deps: ScanDeps, run_id: str) -> _Loaded:
    with deps.sessions() as session:
        run = session.get_one(AnalysisRun, run_id)
        version = session.get_one(SampleVersion, run.sample_version_id)
        return _Loaded(
            sample_sha256=version.sha256,
            size_bytes=version.size_bytes,
            steps=runs.profile_steps(run.profile_snapshot),
            cancel_requested=run.cancel_requested,
        )


def _admit(deps: ScanDeps, loaded: _Loaded) -> tuple[str | None, bytes]:
    """(failure reason or None, verified bytes)."""
    if deps.policy.admit(loaded.sample_sha256) is None:
        return "input_policy", b""
    try:
        data = deps.blobs.read_verified(loaded.sample_sha256)
    except IntegrityError:
        return "sample_integrity", b""
    if len(data) != loaded.size_bytes:
        return "sample_integrity", b""
    return None, data


def _record(
    deps: ScanDeps,
    run_id: str,
    index: int,
    started_at: datetime,
    outcome: StepOutcome,
    scratch: Path,
) -> str:
    """Record one step's outcome. Returns the step status actually recorded.

    A succeeded step whose run was cancelled meanwhile is recorded as
    `cancelled`, without its results. Nothing is recorded for a run that is
    no longer running.
    """
    finished_at = utcnow()
    session = deps.sessions()
    created: str | None = None
    try:
        if outcome.status == "succeeded" and outcome.raw_output is not None:
            if runs.claim_step_commit(session, run_id):
                raw_sha = hashlib.sha256(outcome.raw_output).hexdigest()
                invocation = ToolInvocation(
                    run_id=run_id,
                    step_index=index,
                    status="succeeded",
                    failure_reason=None,
                    started_at=started_at,
                    finished_at=finished_at,
                    raw_output_path=deps.outputs.relative_path(raw_sha),
                    raw_output_sha256=raw_sha,
                    **outcome.invocation,
                )
                session.add(invocation)
                session.flush()
                if outcome.rows is not None:
                    session.add_all(outcome.rows(invocation.id))
                    session.flush()
                if deps.outputs.put_bytes(outcome.raw_output, raw_sha, scratch):
                    created = raw_sha
                session.commit()
                return "succeeded"
            session.rollback()
            status: str = "cancelled"
            reason: str | None = "cancel_requested"
        else:
            status, reason = outcome.status, outcome.reason
        if not runs.still_running(session, run_id):
            session.rollback()
            return "cancelled"
        fields = {k: v for k, v in outcome.invocation.items() if k != "summary"}
        session.add(
            ToolInvocation(
                run_id=run_id,
                step_index=index,
                status=status,
                failure_reason=reason,
                started_at=started_at,
                finished_at=finished_at,
                summary=None,
                **fields,
            )
        )
        session.commit()
        return status
    except BaseException:
        session.rollback()
        if created is not None:
            deps.outputs.remove(created)
        raise
    finally:
        session.close()


def _finish(deps: ScanDeps, run_id: str, step_count: int, reason: str | None) -> str:
    """Move the run to its final status. Returns it ("" if it was not running)."""
    with deps.sessions() as session:
        statuses = runs.step_statuses(session, run_id, step_count)
        target = runs.final_status(statuses, cancelled=False)
        if target != "succeeded" and reason is None:
            reason = _first_step_reason(session, run_id) or "internal_error"
        if runs.transition(
            session,
            run_id,
            "running",
            target,
            unless_cancel_requested=True,
            failure_reason=None if target == "succeeded" else reason,
        ):
            session.commit()
            return target
        if runs.transition(session, run_id, "running", "cancelled", failure_reason=None):
            session.commit()
            return "cancelled"
        session.rollback()
        return ""


def _first_step_reason(session: Session, run_id: str) -> str | None:
    return session.scalar(
        select(ToolInvocation.failure_reason)
        .where(ToolInvocation.run_id == run_id, ToolInvocation.status != "succeeded")
        .order_by(ToolInvocation.step_index)
        .limit(1)
    )


def finish_after_error(deps: ScanDeps, run_id: str) -> str:
    """End a run whose execution raised: steps already committed keep their results."""
    with deps.sessions() as session:
        run = session.get(AnalysisRun, run_id)
        step_count = len(runs.profile_steps(run.profile_snapshot)) if run else 0
    return _finish(deps, run_id, step_count, "internal_error")


def _log(run_id: str, event: str, **fields: object) -> None:
    log.info(json.dumps({"event": event, "run_id": run_id, **fields}, sort_keys=True))


async def execute_run(
    deps: ScanDeps, run_id: str, stopping: Callable[[], bool] = lambda: False
) -> str:
    """Process one claimed run to a terminal state. Returns that state."""
    loaded = _load(deps, run_id)
    step_count = len(loaded.steps)
    if loaded.cancel_requested:
        status = _finish(deps, run_id, step_count, None)
        _log(run_id, "run", status=status, reason="before_start")
        return status

    def cancel_requested() -> bool:
        with deps.sessions() as session:
            return runs.cancel_was_requested(session, run_id)

    def should_stop() -> bool:
        return stopping() or cancel_requested()

    reason: str | None = None
    for index, step in enumerate(loaded.steps):
        if stopping():
            reason = "worker_interrupted"
            break
        if cancel_requested():
            break
        failure, data = _admit(deps, loaded)
        if failure is not None:
            reason = failure
            _log(run_id, "step", index=index, status="not_run", reason=failure)
            break
        runner = STEP_RUNNERS.get(str(step.get("tool")))
        if runner is None:
            reason = "internal_error"
            break
        workdir = workspace.create_workdir(deps.tmp_dir)
        try:
            workspace.write_input(workdir, data)
            started_at = utcnow()
            outcome = await runner(
                deps,
                StepInput(run_id, index, step, loaded.sample_sha256, data, workdir, should_stop),
            )
            if outcome.status == "cancelled" and stopping() and not cancel_requested():
                outcome.reason = "worker_interrupted"
            recorded = _record(deps, run_id, index, started_at, outcome, workdir)
        finally:
            workspace.remove_workdir(workdir)
        _log(
            run_id,
            "step",
            index=index,
            tool=step.get("tool"),
            status=recorded,
            reason=outcome.reason if recorded != "succeeded" else None,
            sample_sha256=loaded.sample_sha256,
            **(outcome.log_fields if recorded == "succeeded" else {}),
        )
        if recorded == "cancelled":
            if outcome.reason == "worker_interrupted":
                reason = "worker_interrupted"
            break

    status = _finish(deps, run_id, step_count, reason)
    _log(run_id, "run", status=status, reason=reason)
    return status
