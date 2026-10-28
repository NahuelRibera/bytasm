"""Step-by-step view of an analysis run, shared by the API and the report.

A step's status comes from its tool_invocation row. A step without a row
was not run: it is `queued` (or `running`, for the next one) while the run is
active, and `skipped` once the run has finished.
"""

from dataclasses import dataclass
from typing import Any

from bytasm.db.models import AnalysisRun, ToolInvocation
from bytasm.jobs import messages, runs


@dataclass(frozen=True)
class StepView:
    index: int
    tool: str
    adapter: str
    step: dict[str, Any]
    invocation: ToolInvocation | None
    status: str
    message: str | None


def step_views(run: AnalysisRun) -> list[StepView]:
    by_index = {inv.step_index: inv for inv in run.invocations}
    steps = runs.profile_steps(run.profile_snapshot)
    first_missing = next((i for i in range(len(steps)) if i not in by_index), None)
    skip_reason = "cancelled" if run.status == "cancelled" else run.failure_reason
    views = []
    for index, step in enumerate(steps):
        tool = str(step.get("tool", ""))
        invocation = by_index.get(index)
        if invocation is not None:
            status, reason = invocation.status, invocation.failure_reason
        elif run.status == "running" and index == first_missing:
            status, reason = "running", None
        elif run.status in runs.ACTIVE:
            status, reason = "queued", None
        else:
            status, reason = "skipped", skip_reason
        views.append(
            StepView(
                index=index,
                tool=tool,
                adapter=str(step.get("adapter", "")),
                step=step,
                invocation=invocation,
                status=status,
                message=messages.step_message(tool, status, reason),
            )
        )
    return views


def run_message(run: AnalysisRun, views: list[StepView]) -> str | None:
    return messages.run_message(
        run.status, run.failure_reason, [(view.tool, view.status) for view in views]
    )


def strings_invocation(run: AnalysisRun) -> ToolInvocation | None:
    """The run's succeeded strings step, if any."""
    return next(
        (
            inv
            for inv in run.invocations
            if inv.tool_name == runs.STRINGS_TOOL and inv.status == "succeeded"
        ),
        None,
    )
