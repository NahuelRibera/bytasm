"""Integrity checks shared by live analyst overlays and pinned review snapshots."""

import hashlib
from typing import Any

from bytasm.db.models import FunctionReviewRevision
from bytasm.reports.generate import canonical_json
from bytasm.storage import IntegrityError


def validated_overlay(row: FunctionReviewRevision) -> dict[str, Any]:
    doc = row.document
    raw = canonical_json(doc)
    identity = doc.get("identity", {})
    if (
        len(raw) > 32 * 1024
        or hashlib.sha256(raw).hexdigest() != row.document_sha256
        or doc.get("id") != row.id
        or doc.get("revision") != row.revision
        or identity.get("version_id") != row.version_id
        or identity.get("invocation_id") != row.invocation_id
        or hashlib.sha256(canonical_json(identity)).hexdigest() != row.scope_sha256
    ):
        raise IntegrityError("Function review revision changed")
    return doc
