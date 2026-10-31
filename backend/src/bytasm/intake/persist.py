"""Persist a successful import, all or nothing (blueprint 5.4.1 step 10).

1. Re-hash the admitted file and compare with the streaming hash.
2. In one transaction, insert the sample (if new), sample_version,
   authorization_record, analysis_run, tool_invocation, sections, symbols and
   the sample_version.imported activity event.
3. Place the file and the adapter's raw result in their content-addressed
   stores (atomic rename on the same filesystem).
4. Commit. If anything fails, roll back and delete every stored file this
   call created, so no orphan blob is left.

The re-hash catches accidental modification. It is not a defence against a
compromised parser, which runs as the same user (see SECURITY.md).
"""

import hashlib
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session, sessionmaker

from bytasm import __version__
from bytasm.adapters.result import AdapterResult
from bytasm.db.models import (
    ActivityEvent,
    AnalysisRun,
    AuthorizationRecord,
    Sample,
    SampleVersion,
    Section,
    Symbol,
    ToolInvocation,
)
from bytasm.intake.import_metadata import ImportMetadata
from bytasm.intake.policy import Admission
from bytasm.storage import ContentStore, IntegrityError, sha256_file

# v0.1 has a single, constant analysis step (blueprint section 6).
PROFILE_SNAPSHOT: dict[str, Any] = {
    "name": "v0.1-import",
    "steps": [{"tool": "lief", "adapter": "metadata_lief", "when": "import"}],
}


@dataclass(frozen=True)
class SuccessfulParse:
    sha256: str
    size_bytes: int
    input_path: Path
    admission: Admission
    result: AdapterResult
    result_bytes: bytes
    exit_code: int
    duration_ms: int
    started_at: datetime
    finished_at: datetime
    limits: dict[str, Any]
    isolation: dict[str, Any] | None = None


def persist_import(
    sessions: sessionmaker[Session],
    blobs: ContentStore,
    outputs: ContentStore,
    scratch_dir: Path,
    project_id: str,
    meta: ImportMetadata,
    parsed: SuccessfulParse,
) -> str:
    """Write everything for one import and return the new sample_version id."""
    if sha256_file(parsed.input_path) != parsed.sha256:
        raise IntegrityError("the admitted file changed after it was hashed")
    result_sha256 = hashlib.sha256(parsed.result_bytes).hexdigest()

    created: list[tuple[ContentStore, str]] = []
    session = sessions()
    try:
        if meta.sample_id is not None:
            sample = session.get_one(Sample, meta.sample_id)
        else:
            assert meta.sample_name is not None  # noqa: S101 - enforced by ImportMetadata
            sample = Sample(project_id=project_id, name=meta.sample_name)
            session.add(sample)

        metadata = parsed.result.metadata
        version = SampleVersion(
            sample=sample,
            version_label=meta.version_label or None,
            sha256=parsed.sha256,
            size_bytes=parsed.size_bytes,
            declared_filename=meta.declared_filename,
            detected_format=metadata.format,
            blob_path=blobs.relative_path(parsed.sha256),
            admitted_under=parsed.admission.admitted_under,
            manifest_entry=parsed.admission.manifest_entry,
        )
        session.add(version)
        session.add(
            AuthorizationRecord(
                sample_version=version,
                basis=meta.authorization.basis,
                statement=meta.authorization.statement,
                terms_reference=None,
            )
        )
        run = AnalysisRun(
            sample_version=version,
            profile_snapshot=PROFILE_SNAPSHOT,
            status="succeeded",
            started_at=parsed.started_at,
            finished_at=parsed.finished_at,
            bytasm_version=__version__,
            image_digest=None,
        )
        session.add(run)
        invocation = ToolInvocation(
            run=run,
            step_index=0,
            tool_name=parsed.result.tool,
            tool_version=parsed.result.tool_version,
            adapter_name=parsed.result.adapter,
            adapter_version=parsed.result.adapter_version,
            args={
                "limits": parsed.limits,
                **({"isolation": parsed.isolation} if parsed.isolation else {}),
            },
            status="succeeded",
            exit_code=parsed.exit_code,
            duration_ms=parsed.duration_ms,
            raw_output_path=outputs.relative_path(result_sha256),
            raw_output_sha256=result_sha256,
            entropy_method=parsed.result.entropy_method,
            header={
                "format": metadata.format,
                "architecture": metadata.architecture,
                "bitness": metadata.bitness,
                "endianness": metadata.endianness,
                "entry_point": metadata.entry_point,
                "declared_header": dict(metadata.declared_header),
                "imported_libraries": list(metadata.imports.libraries),
                **(
                    {"structure": metadata.structure.model_dump(mode="json")}
                    if metadata.structure is not None
                    else {}
                ),
            },
            warnings=list(metadata.warnings),
        )
        session.add(invocation)
        session.flush()  # assigns invocation.id

        for index, section in enumerate(metadata.sections):
            session.add(
                Section(
                    invocation_id=invocation.id,
                    index=index,
                    name=section.name,
                    section_type=section.type,
                    file_offset=section.file_offset,
                    raw_size=section.file_size,
                    virtual_address=section.virtual_address,
                    virtual_size=section.declared_size,
                    flags=list(section.flags),
                    entropy=section.entropy,
                    entropy_note=section.entropy_note,
                )
            )
        for name in metadata.imports.functions:
            session.add(Symbol(invocation_id=invocation.id, direction="import", name=name))
        for name in metadata.exports:
            session.add(Symbol(invocation_id=invocation.id, direction="export", name=name))
        session.add(
            ActivityEvent(
                project_id=project_id,
                actor_id="local",
                type="sample_version.imported",
                payload={"sample_id": sample.id, "sample_version_id": version.id},
                at=version.imported_at,
            )
        )
        session.flush()

        if outputs.put_bytes(parsed.result_bytes, result_sha256, scratch_dir):
            created.append((outputs, result_sha256))
        if blobs.place(parsed.input_path, parsed.sha256):
            created.append((blobs, parsed.sha256))

        session.commit()
        return version.id
    except BaseException:
        session.rollback()
        for store, sha in created:
            store.remove(sha)
        raise
    finally:
        session.close()
