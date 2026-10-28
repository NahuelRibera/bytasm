"""Analysis-run lifecycle: the allowed states and transitions (blueprint J5, 5.4.2).

    queued ──claim──► running ──► succeeded | partial | failed | cancelled
       │
       └──cancel──► cancelled

A run executes the steps of its profile snapshot in order (v0.2: strings,
then YARA-X). Each step that ends is recorded as a `tool_invocation` row with
the step's own status (`succeeded`, `failed`, `timed_out`, `cancelled`); a
step with no row was not run ("skipped"). The run's final status follows from
its steps (`final_status`):

- `succeeded`: every step succeeded.
- `partial`: at least one step succeeded and kept its results, and at least
  one did not (it failed, timed out, or was not run because the worker
  stopped or the sample stopped passing its admission checks).
- `failed`: no step kept any results.
- `cancelled`: a cancel was requested before the run finished. Steps that
  had already finished keep their results (blueprint 7.3, "Cancelled").

Every transition is one conditional UPDATE (`WHERE status = <from>`), so the
API (which creates and cancels runs) and the worker (which claims and
finishes them) can never both move a run: whichever commits first wins, and
the other sees that no row changed. Terminal states never change again.

A cancel request on a *running* run only sets `cancel_requested`. The worker
polls it while a step's child runs and between steps. A step's results are
stored only by a transaction whose first statement is a conditional UPDATE
requiring `cancel_requested` to be false (`claim_step_commit`); in SQLite
that statement also takes the database's write lock, so a cancel committed
before it makes the step `cancelled` (nothing kept), and a cancel arriving
after it waits for the step's commit and then applies to the rest of the run.
"""

from collections.abc import Iterable
from datetime import datetime
from typing import Any, Final, Literal

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from bytasm import __version__
from bytasm.adapters import strings_result
from bytasm.db.models import AnalysisRun, RuleSet, ToolInvocation, utcnow

RunStatus = Literal["queued", "running", "succeeded", "partial", "failed", "cancelled"]
ACTIVE: Final = frozenset({"queued", "running"})
TERMINAL: Final = frozenset({"succeeded", "partial", "failed", "cancelled"})
# Runs whose results the report uses (blueprint J8: "successful or partial").
WITH_RESULTS: Final = frozenset({"succeeded", "partial"})
TRANSITIONS: Final[dict[str, frozenset[str]]] = {
    "queued": frozenset({"running", "cancelled"}),
    "running": frozenset({"succeeded", "partial", "failed", "cancelled"}),
    "succeeded": frozenset(),
    "partial": frozenset(),
    "failed": frozenset(),
    "cancelled": frozenset(),
}

PROFILE_ID: Final = "default-static"
PROFILE_VERSION: Final = 2
STRINGS_TOOL: Final = "strings"
STRINGS_ADAPTER: Final = "strings_extract"
YARA_TOOL: Final = "yara-x"
YARA_ADAPTER: Final = "yara_x_scan"


class InvalidTransition(Exception):
    """A transition the lifecycle does not allow (a programming error)."""


def check_transition(current: str, target: str) -> None:
    if target not in TRANSITIONS.get(current, frozenset()):
        raise InvalidTransition(f"{current} -> {target}")


def transition(
    session: Session,
    run_id: str,
    current: str,
    target: str,
    *,
    unless_cancel_requested: bool = False,
    **values: Any,
) -> bool:
    """Move run `run_id` from `current` to `target` if it is still `current`.

    With `unless_cancel_requested`, also only if no cancel was requested.
    Returns False (and changes nothing) otherwise. The caller commits.
    """
    check_transition(current, target)
    if target in TERMINAL:
        values.setdefault("finished_at", utcnow())
    conditions = [
        AnalysisRun.id == run_id,
        AnalysisRun.kind == "analysis",
        AnalysisRun.status == current,
    ]
    if unless_cancel_requested:
        conditions.append(AnalysisRun.cancel_requested.is_(False))
    result = session.execute(
        update(AnalysisRun)
        .where(*conditions)
        .values(status=target, **values)
        .execution_options(synchronize_session=False)
    )
    return bool(result.rowcount == 1)  # type: ignore[attr-defined]


def claim_step_commit(session: Session, run_id: str) -> bool:
    """First statement of a step's result transaction.

    True if the run is still running and no cancel was requested. In SQLite
    the UPDATE also takes the write lock, so that stays true until commit.
    """
    result = session.execute(
        update(AnalysisRun)
        .where(
            AnalysisRun.id == run_id,
            AnalysisRun.kind == "analysis",
            AnalysisRun.status == "running",
            AnalysisRun.cancel_requested.is_(False),
        )
        .values(status="running")
        .execution_options(synchronize_session=False)
    )
    return bool(result.rowcount == 1)  # type: ignore[attr-defined]


def still_running(session: Session, run_id: str) -> bool:
    """Like claim_step_commit, but a requested cancel does not matter."""
    result = session.execute(
        update(AnalysisRun)
        .where(
            AnalysisRun.id == run_id,
            AnalysisRun.kind == "analysis",
            AnalysisRun.status == "running",
        )
        .values(status="running")
        .execution_options(synchronize_session=False)
    )
    return bool(result.rowcount == 1)  # type: ignore[attr-defined]


def profile_snapshot(rule_set: RuleSet, timeout_seconds: float) -> dict[str, Any]:
    """What the run will do, frozen at creation (blueprint J5)."""
    return {
        "id": PROFILE_ID,
        "version": PROFILE_VERSION,
        "name": "Default static profile (v0.2): strings, then YARA-X with Bytasm's bundled rules",
        # Header metadata (LIEF) is read once, by the import (v0.1). It is not
        # repeated as a step of the analysis run.
        "metadata_from": "import",
        "steps": [
            {
                "tool": STRINGS_TOOL,
                "adapter": STRINGS_ADAPTER,
                "params": {
                    "encodings": list(strings_result.ENCODINGS),
                    "min_length": strings_result.MIN_LENGTH,
                    "max_strings": strings_result.MAX_STRINGS,
                    "max_chars": strings_result.MAX_CHARS,
                },
                "timeout_seconds": timeout_seconds,
            },
            {
                "tool": YARA_TOOL,
                "adapter": YARA_ADAPTER,
                "rule_set": {
                    "id": rule_set.id,
                    "label": f"{rule_set.name}@{rule_set.version}",
                    "sha256": rule_set.sha256,
                },
                "timeout_seconds": timeout_seconds,
            },
        ],
    }


def profile_steps(snapshot: dict[str, Any]) -> list[dict[str, Any]]:
    steps: list[dict[str, Any]] = snapshot.get("steps", [])
    return steps


def rule_set_step(snapshot: dict[str, Any]) -> dict[str, Any] | None:
    """The YARA-X step of a snapshot (runs recorded before 0003 have only this step)."""
    return next((s for s in profile_steps(snapshot) if s.get("tool") == YARA_TOOL), None)


def final_status(step_statuses: Iterable[str | None], cancelled: bool) -> str:
    """The run's status from its steps' statuses (None: not run). See the module docstring."""
    statuses = list(step_statuses)
    if cancelled:
        return "cancelled"
    if statuses and all(status == "succeeded" for status in statuses):
        return "succeeded"
    if any(status == "succeeded" for status in statuses):
        return "partial"
    return "failed"


def active_run_id(session: Session, version_id: str) -> str | None:
    return session.scalar(
        select(AnalysisRun.id).where(
            AnalysisRun.sample_version_id == version_id,
            AnalysisRun.kind == "analysis",
            AnalysisRun.status.in_(ACTIVE),
        )
    )


def new_queued_run(version_id: str, snapshot: dict[str, Any], now: datetime) -> AnalysisRun:
    return AnalysisRun(
        sample_version_id=version_id,
        kind="analysis",
        profile_snapshot=snapshot,
        status="queued",
        queued_at=now,
        cancel_requested=False,
        bytasm_version=__version__,
        image_digest=None,
    )


CancelOutcome = Literal["cancelled", "requested", "already_requested", "finished", "not_found"]


def request_cancel(session: Session, run_id: str) -> CancelOutcome:
    """Cancel a queued run at once, or ask the worker to stop a running one.

    Commits. Repeating the request is harmless.
    """
    run = session.get(AnalysisRun, run_id)
    if run is None or run.kind != "analysis":
        return "not_found"
    now = utcnow()
    if run.status == "queued" and transition(
        session,
        run_id,
        "queued",
        "cancelled",
        cancel_requested=True,
        cancel_requested_at=now,
        failure_reason=None,
    ):
        session.commit()
        return "cancelled"
    session.refresh(run)
    if run.status == "running":
        if run.cancel_requested:
            return "already_requested"
        session.execute(
            update(AnalysisRun)
            .where(AnalysisRun.id == run_id, AnalysisRun.status == "running")
            .values(cancel_requested=True, cancel_requested_at=now)
            .execution_options(synchronize_session=False)
        )
        session.commit()
        return "requested"
    return "finished"


def claim_next(session: Session) -> str | None:
    """Claim the oldest queued run for this worker. Commits."""
    candidates = session.scalars(
        select(AnalysisRun.id)
        .where(AnalysisRun.kind == "analysis", AnalysisRun.status == "queued")
        .order_by(AnalysisRun.queued_at, AnalysisRun.id)
        .limit(5)
    ).all()
    for run_id in candidates:
        if transition(session, run_id, "queued", "running", started_at=utcnow()):
            session.commit()
            return run_id
    session.rollback()
    return None


def cancel_was_requested(session: Session, run_id: str) -> bool:
    return bool(
        session.scalar(select(AnalysisRun.cancel_requested).where(AnalysisRun.id == run_id))
    )


def step_statuses(session: Session, run_id: str, step_count: int) -> list[str | None]:
    """The recorded status of each step (None: no invocation, so not run)."""
    recorded: dict[int, str] = {
        index: status
        for index, status in session.execute(
            select(ToolInvocation.step_index, ToolInvocation.status).where(
                ToolInvocation.run_id == run_id
            )
        ).all()
    }
    return [recorded.get(index) for index in range(step_count)]


def fail_interrupted_runs(session: Session) -> int:
    """At worker start-up: finish runs left `running` by a worker that stopped. Commits.

    Steps that had committed their results keep them, so such a run becomes
    `partial` (or `cancelled`, if a cancel had been requested); with no
    finished step it becomes `failed`. The reason is `worker_interrupted`,
    and the run never stays `running`.
    """
    stale = session.scalars(
        select(AnalysisRun).where(AnalysisRun.kind == "analysis", AnalysisRun.status == "running")
    ).all()
    count = 0
    for run in stale:
        statuses = step_statuses(session, run.id, len(profile_steps(run.profile_snapshot)))
        target = final_status(statuses, run.cancel_requested)
        # Every step finished and only the final update was lost: nothing is missing.
        reason = None if target in ("succeeded", "cancelled") else "worker_interrupted"
        if transition(session, run.id, "running", target, failure_reason=reason):
            count += 1
    session.commit()
    return count
