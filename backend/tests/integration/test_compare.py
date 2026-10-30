"""Comparison uses real persisted observations and preserves missing-step semantics."""

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from bytasm.compare import CompareError, compare_versions
from bytasm.db.models import (
    AnalysisRun,
    Base,
    Project,
    Sample,
    SampleVersion,
    StringOccurrence,
    ToolInvocation,
)


@pytest.fixture
def db() -> Iterator[Session]:
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        session.add(Project(id="p", name="P"))
        session.add(Sample(id="s", project_id="p", name="S"))
        for i in ("a", "b"):
            session.add(
                SampleVersion(
                    id=i,
                    sample_id="s",
                    sha256=i * 64,
                    size_bytes=10,
                    detected_format="ELF",
                    blob_path="private/path",
                    admitted_under="fixture_manifest",
                )
            )
        session.flush()
        yield session


def run(
    db: Session,
    version: str,
    *,
    status: str = "succeeded",
    tool_version: str = "1",
    seconds: int = 0,
) -> str:
    rid = version + str(seconds)
    db.add(
        AnalysisRun(
            id=rid,
            sample_version_id=version,
            kind="analysis",
            profile_snapshot={},
            status=status,
            bytasm_version="1",
            queued_at=datetime(2026, 1, 1, tzinfo=UTC) + timedelta(seconds=seconds),
        )
    )
    db.flush()
    if status in ("succeeded", "partial"):
        db.add(
            ToolInvocation(
                id=rid,
                run_id=rid,
                step_index=0,
                tool_name="strings",
                tool_version=tool_version,
                adapter_name="strings_extract",
                adapter_version="1",
                args={},
                status="succeeded",
                duration_ms=1,
                warnings=[],
            )
        )
        db.flush()
    return rid


def string(db: Session, inv: str, value: str, offset: int) -> None:
    db.add(
        StringOccurrence(
            invocation_id=inv,
            value=value,
            file_offset=offset,
            encoding="ascii",
            length_chars=len(value),
            byte_length=len(value),
            value_truncated=False,
        )
    )
    db.flush()


def test_diff_counts_paging_and_partial_results(db: Session) -> None:
    a = run(db, "a", status="partial")
    b = run(db, "b")
    string(db, a, "shared", 1)
    string(db, b, "shared", 2)
    string(db, b, "newaaa", 3)
    string(db, b, "newbbb", 4)
    result = compare_versions(db, "a", "b", category="strings", limit=1)
    diff = result.categories["strings"]
    assert (diff.added, diff.removed, diff.changed, diff.total_rows) == (2, 0, 1, 3)
    assert diff.next_offset == 1
    assert len(diff.rows) == 1
    assert "private/path" not in result.model_dump_json()
    assert result.a.run_status == "partial"


def test_missing_is_unavailable_and_cancelled_is_context(db: Session) -> None:
    run(db, "b", status="cancelled")
    result = compare_versions(db, "a", "b")
    assert result.b.run_status == "cancelled"
    assert result.categories["strings"].status == "unavailable"
    assert result.categories["strings"].rows == []


def test_incompatible_provenance_warns(db: Session) -> None:
    run(db, "a")
    run(db, "b", tool_version="2")
    result = compare_versions(db, "a", "b")
    assert result.warnings
    assert result.categories["strings"].status == "incompatible"


def test_self_empty_and_latest_success_beats_newer_failure(db: Session) -> None:
    run(db, "a")
    run(db, "a", status="failed", seconds=1)
    result = compare_versions(db, "a", "a")
    assert result.identical_content
    assert result.a.run_id == "a0"
    assert result.categories["strings"].total_rows == 0


def test_invalid_inputs(db: Session) -> None:
    with pytest.raises(CompareError):
        compare_versions(db, "missing", "b")
    with pytest.raises(CompareError):
        compare_versions(db, "a", "b", limit=201)


def test_structural_and_evidence_matching_ignore_database_ids(db: Session) -> None:
    from bytasm.db.models import Evidence, Finding, RuleSet, Section, Symbol

    db.add(
        RuleSet(
            id="rules",
            tool="yara-x",
            name="rules",
            version="1",
            sha256="0" * 64,
            source="bytasm-repo",
            snapshot_path="private/rules",
            rule_count=1,
        )
    )
    for version in ("a", "b"):
        rid = run(db, version)
        db.add(
            AnalysisRun(
                id="import-" + version,
                sample_version_id=version,
                kind="import",
                profile_snapshot={},
                status="succeeded",
                bytasm_version="1",
            )
        )
        db.flush()
        db.add(
            ToolInvocation(
                id="lief-" + version,
                run_id="import-" + version,
                step_index=0,
                tool_name="lief",
                tool_version="1",
                adapter_name="metadata_lief",
                adapter_version="1",
                args={},
                status="succeeded",
                duration_ms=1,
                warnings=[],
                header={"architecture": "x86", "entry_point": 1 if version == "a" else 2},
            )
        )
        db.add(
            ToolInvocation(
                id="yara-" + version,
                run_id=rid,
                step_index=1,
                tool_name="yara-x",
                tool_version="1",
                adapter_name="yara_x_scan",
                adapter_version="1",
                args={},
                status="succeeded",
                duration_ms=1,
                warnings=[],
                rule_set_id="rules",
            )
        )
        db.flush()
        db.add(
            Section(
                invocation_id="lief-" + version,
                index=0,
                name=".text",
                file_offset=0,
                raw_size=1 if version == "a" else 2,
                virtual_address=0,
                virtual_size=4,
                flags=["READ", "EXECUTE"] if version == "a" else ["EXECUTE", "READ"],
            )
        )
        db.add(
            Symbol(
                invocation_id="lief-" + version, direction="import", library="lib", name="shared"
            )
        )
        db.add(
            Finding(
                id="finding-" + version,
                run_id=rid,
                invocation_id="yara-" + version,
                kind="yara_match",
                title="Match",
                rule_id="rule",
                rule_namespace="default",
                rule_set_id="rules",
                tool_reported_attributes={},
                fingerprint="0" * 64,
                match_count=1,
                evidence_truncated=False,
            )
        )
        db.flush()
        db.add(
            Evidence(
                finding_id="finding-" + version,
                kind="byte_range",
                pattern_id="$x",
                file_offset=0,
                length=1,
                excerpt_hex="61" if version == "a" else "62",
                raw_json_pointer="/matches/0",
            )
        )
    db.flush()
    result = compare_versions(db, "a", "b")
    assert result.categories["metadata"].changed == 2
    assert result.categories["sections"].changed == 1
    assert result.categories["imports"].total_rows == 0
    assert result.categories["findings"].total_rows == 0
    assert result.categories["evidence"].changed == 1
    evidence_row = result.categories["evidence"].rows[0]
    assert evidence_row.before_ref is not None
    assert evidence_row.before_ref.finding_id == "finding-a"
    assert evidence_row.before_ref.evidence_id is not None
    assert evidence_row.after_ref is not None
    assert evidence_row.after_ref.finding_id == "finding-b"
    assert "private/" not in result.model_dump_json()


def test_truncated_strings_do_not_establish_equality_except_self(db: Session) -> None:
    a = run(db, "a")
    run(db, "b")
    string(db, a, "prefix", 0)
    occurrence = db.scalar(select(StringOccurrence))
    assert occurrence is not None
    occurrence.value_truncated = True
    db.flush()
    assert compare_versions(db, "a", "b").categories["strings"].status == "unavailable"
    assert compare_versions(db, "a", "a").categories["strings"].total_rows == 0
    assert compare_versions(db, "a", "a").categories["strings"].status == "comparable"


def test_capped_strings_and_step_context(db: Session) -> None:
    a = run(db, "a")
    run(db, "b", status="cancelled")
    invocation = db.get_one(ToolInvocation, a)
    invocation.summary = {"truncated": True}
    result = compare_versions(db, "a", "b")
    assert result.categories["strings"].a_status == "succeeded"
    assert result.categories["strings"].b_status == "cancelled"
    run(db, "b", seconds=1)
    assert compare_versions(db, "a", "b").categories["strings"].status == "unavailable"


def test_duplicate_occurrence_display_bounded_without_hiding_change(db: Session) -> None:
    a = run(db, "a")
    b = run(db, "b")
    for i in range(25):
        string(db, a, "shared", i)
        string(db, b, "shared", i if i < 24 else 99)
    diff = compare_versions(db, "a", "b", category="strings").categories["strings"]
    assert diff.changed == 1
    assert diff.rows[0].before is not None
    assert len(diff.rows[0].before["occurrences"]) == 20
    assert diff.rows[0].before["occurrences_total"] == 25
    assert diff.rows[0].before["occurrences_truncated"] is True


def test_different_samples_are_refused(db: Session) -> None:
    db.add(Sample(id="other", project_id="p", name="other"))
    db.flush()
    db.get_one(SampleVersion, "b").sample_id = "other"
    with pytest.raises(CompareError, match="same sample"):
        compare_versions(db, "a", "b")


def test_missing_partial_step_exposes_timeout_without_zero_claim(db: Session) -> None:
    run(db, "a", status="partial")
    run(db, "b", status="partial")
    db.add(
        ToolInvocation(
            id="failed-yara",
            run_id="a0",
            step_index=1,
            tool_name="yara-x",
            tool_version="1",
            adapter_name="yara_x_scan",
            adapter_version="1",
            args={},
            status="timed_out",
            duration_ms=1,
            warnings=[],
        )
    )
    db.flush()
    result = compare_versions(db, "a", "b")
    assert result.categories["strings"].status == "comparable"
    assert result.categories["findings"].status == "unavailable"
    assert result.categories["findings"].a_status == "timed_out"
    assert result.categories["findings"].b_status == "not_run"


def test_latest_run_orders_mixed_timestamp_precision_chronologically(db: Session) -> None:
    from datetime import datetime

    first = run(db, "a", seconds=0)
    later = run(db, "a", seconds=1)
    other = run(db, "b")
    db.get_one(AnalysisRun, first).queued_at = datetime.fromisoformat("2026-01-01T00:00:00Z")
    db.get_one(AnalysisRun, later).queued_at = datetime.fromisoformat("2026-01-01T00:00:00.000001Z")
    string(db, first, "older result", 0)
    string(db, later, "current result", 0)
    string(db, other, "current result", 0)
    compared = compare_versions(db, "a", "b", category="strings")
    assert compared.a.run_id == later
    assert compared.categories["strings"].total_rows == 0


@pytest.mark.parametrize("difference", [None, "tool", "adapter", "rules", "args"])
def test_capa_comparison_requires_exact_provenance(db: Session, difference: str | None) -> None:
    from bytasm.db.models import Evidence, Finding, RuleSet

    for index, version in enumerate(("a", "b")):
        rid = run(db, version)
        rules = RuleSet(
            id="capa-rules-" + version,
            tool="capa",
            name="subset",
            version="10.0.0",
            sha256=("1" if difference == "rules" and index else "0") * 64,
            source="upstream",
            snapshot_path="outputs/hash",
            rule_count=2,
        )
        existing = db.scalar(select(RuleSet).where(RuleSet.sha256 == rules.sha256))
        if existing is None:
            db.add(rules)
            db.flush()
        else:
            rules = existing
        inv = ToolInvocation(
            id="capa-" + version,
            run_id=rid,
            step_index=2,
            tool_name="capa",
            tool_version="other" if difference == "tool" and index else "10.0.0",
            adapter_name="capa_scan",
            adapter_version="other" if difference == "adapter" and index else "0.1.0",
            args={"backend": "other" if difference == "args" and index else "vivisect"},
            status="succeeded",
            duration_ms=1,
            warnings=[],
            rule_set_id=rules.id,
        )
        db.add(inv)
        db.flush()
        db.add(
            Finding(
                id="finding-" + version,
                run_id=rid,
                invocation_id=inv.id,
                kind="capability",
                title="query environment variable",
                rule_id="query environment variable",
                rule_namespace="host-interaction/environment-variable",
                rule_set_id=rules.id,
                tool_reported_attributes={},
                fingerprint="f" * 64,
                match_count=1,
                evidence_truncated=False,
                evidence=[
                    Evidence(
                        kind="virtual_address",
                        pattern_id="function",
                        file_offset=None,
                        length=None,
                        virtual_address=0xFFFFF80000001234 + index,
                        excerpt_hex="",
                        raw_json_pointer="/rules/query environment variable/matches/0/0",
                    )
                ],
            )
        )
    db.flush()
    category = compare_versions(db, "a", "b", category="capabilities").categories["capabilities"]
    assert category.status == ("incompatible" if difference else "comparable")
    if difference:
        assert category.rows == []
    else:
        assert (category.added, category.removed, category.changed) == (0, 0, 1)
        assert '"0xfffff80000001234"' in category.model_dump_json()
        assert '"0xfffff80000001235"' in category.model_dump_json()
