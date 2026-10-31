"""Explicit selected-function jobs reuse the existing transactional run lifecycle."""

import hashlib
import json
from datetime import UTC, datetime

from sqlalchemy import select

from bytasm.api.context import AppContext
from bytasm.db.models import AnalysisRun
from bytasm.ghidra_protocol import Address
from bytasm.ghidra_provider import profile_snapshot
from bytasm.jobs import runs
from bytasm.storage import IntegrityError


class SelectionRefused(Exception):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def queue_selection(ctx: AppContext, source_id: str, indices: list[int]) -> tuple[str, bool]:
    # Lazy import keeps verified storage reading in one place.
    from bytasm.api.ghidra import _invocation, _read, _run

    with ctx.sessions() as session:
        session.connection().exec_driver_sql("BEGIN IMMEDIATE")
        source = _run(session, source_id)
        inv = _invocation(source) if source else None
        if source is None or inv is None or inv.status != "succeeded":
            raise SelectionRefused("not_found")
        try:
            result = _read(ctx, source, inv)
        except IntegrityError as exc:
            raise SelectionRefused("integrity_error") from exc
        original_selection = inv.args.get("options", {}).get("selected_entries")
        current = profile_snapshot(
            [Address.model_validate(a) for a in original_selection]
            if original_selection is not None
            else None
        )["steps"][0]
        if (
            result.script_sha256 != current["script_sha256"]
            or result.profile_sha256 != current["profile_sha256"]
            or result.analysis_timed_out
        ):
            raise SelectionRefused("ghidra_incompatible")
        if not 1 <= len(indices) <= 8 or len(set(indices)) != len(indices):
            raise SelectionRefused("invalid_request")
        if any(type(i) is not int or not 0 <= i < len(result.functions) for i in indices):
            raise SelectionRefused("invalid_request")
        entries = [result.functions[i].entry for i in sorted(indices)]
        snapshot = profile_snapshot(entries)
        key = hashlib.sha256(
            json.dumps(
                [
                    source.sample_version.sample.project_id,
                    source.sample_version_id,
                    result.input_sha256,
                    source.id,
                    inv.id,
                    inv.raw_output_sha256,
                    snapshot,
                ],
                sort_keys=True,
            ).encode()
        ).hexdigest()
        if ctx.policy.admit(result.input_sha256) is None:
            raise SelectionRefused("input_policy")
        try:
            ctx.blobs.verify(result.input_sha256)
        except IntegrityError as exc:
            raise SelectionRefused("integrity_error") from exc
        cached = session.scalar(
            select(AnalysisRun)
            .where(
                AnalysisRun.sample_version_id == source.sample_version_id,
                AnalysisRun.profile_snapshot["selection_key"].as_string() == key,
                AnalysisRun.status.in_(["queued", "running", "succeeded"]),
                AnalysisRun.cancel_requested.is_(False),
            )
            .order_by(AnalysisRun.queued_at.desc())
            .limit(1)
        )
        if cached is not None:
            if cached.status == "succeeded":
                cached_inv = _invocation(cached)
                if cached_inv is None:
                    raise SelectionRefused("integrity_error")
                try:
                    _read(ctx, cached, cached_inv)
                except IntegrityError as exc:
                    raise SelectionRefused("integrity_error") from exc
            return cached.id, True
        if runs.active_run_id(session, source.sample_version_id) is not None:
            raise SelectionRefused("run_active")
        snapshot.update(
            selection_key=key,
            source_run_id=source.id,
            source_output_sha256=inv.raw_output_sha256,
            selected_indices=sorted(indices),
        )
        queued = runs.new_queued_run(source.sample_version_id, snapshot, datetime.now(UTC))
        session.add(queued)
        session.flush()
        runs.record_activity(session, queued.id, "queued")
        session.commit()
        return queued.id, False
