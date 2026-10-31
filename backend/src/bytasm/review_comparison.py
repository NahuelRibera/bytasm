"""Compare immutable reviews, never infer program evolution from tool output drift."""

from typing import Any

from bytasm.review_snapshot import Snapshot


def compare_reviews(left: Snapshot, right: Snapshot) -> dict[str, Any]:
    incompatible = []
    if (
        left.sample.sample_id != right.sample.sample_id
        and left.sample.sha256 != right.sample.sha256
    ):
        incompatible.append("Reviews belong to different samples and different file identities.")
    if left.sample.format != right.sample.format:
        incompatible.append("File formats differ; structural coordinates are not comparable.")
    changes = []
    old_sources = {s.tool: s.selected for s in left.sources}
    new_sources = {s.tool: s.selected for s in right.sources}
    for tool in sorted(old_sources.keys() | new_sources.keys()):
        a, b = old_sources.get(tool), new_sources.get(tool)
        fields = []
        if a and b:
            fields = [
                key
                for key in (
                    "run_id",
                    "invocation_id",
                    "adapter",
                    "output_sha256",
                    "tool_version",
                    "adapter_version",
                    "rule_sha256",
                    "profile",
                    "parameters",
                    "limits",
                    "retention",
                    "warnings",
                )
                if getattr(a, key) != getattr(b, key)
            ]
        old_source = next((s for s in left.sources if s.tool == tool), None)
        new_source = next((s for s in right.sources if s.tool == tool), None)
        if old_source and new_source:
            for field in ("latest_attempt", "unavailable_reason"):
                if getattr(old_source, field) != getattr(new_source, field):
                    fields.append(field)
        change = (
            "added"
            if b and not a
            else "removed"
            if a and not b
            else "changed"
            if fields
            else "unchanged"
        )
        changes.append(
            {
                "tool": tool,
                "change": change,
                "changed_fields": fields,
                "interpretation": (
                    "New result, not proof of a new program capability. Tool, "
                    "adapter, rules, parameters and retained limits can explain differences."
                )
                if change != "unchanged"
                else "No retained source difference.",
            }
        )

    def observations(review: Snapshot) -> set[str]:
        return {f"{o.tool}:{o.rule_id}" for o in review.observations}

    def imports(review: Snapshot) -> set[str]:
        return (
            set(review.import_inventory)
            if review.import_inventory is not None
            else {name for o in review.import_observations for name in o.supporting_names}
        )

    old_observations, new_observations = observations(left), observations(right)
    import_comparable = left.import_inventory is not None and right.import_inventory is not None
    ia, ib = imports(left), imports(right)
    # Incompatible reviews expose provenance only, not misleading result deltas.
    compatible = not incompatible
    return {
        "schema_version": "bytasm-review-comparison-1",
        "left_id": left.id,
        "right_id": right.id,
        "compatible": compatible,
        "incompatibilities": incompatible,
        "source_changes": changes,
        "observation_changes": {
            "added": sorted(new_observations - old_observations) if compatible else [],
            "removed": sorted(old_observations - new_observations) if compatible else [],
            "unchanged": sorted(old_observations & new_observations) if compatible else [],
        },
        "import_changes": {
            "added": sorted(ib - ia) if compatible and import_comparable else [],
            "removed": sorted(ia - ib) if compatible and import_comparable else [],
        },
        "limit_changes": {"left": left.unknowns, "right": right.unknowns},
        "cautions": [
            *(
                []
                if import_comparable
                else [
                    "Import deltas unavailable: at least one historical review lacks "
                    "a complete pinned inventory."
                ]
            ),
            "Static results do not establish observed runtime behavior; the file was not executed.",
            (
                "Import changes compare exact pinned inventories where available; "
                "historical reviews may contain only categorized names."
            ),
            (
                "An absent result may reflect missing sources, capped evidence or "
                "changed coverage. No absence-of-behavior claim follows."
            ),
            *(
                ["Interpretation catalog versions differ."]
                if left.catalog_version != right.catalog_version
                else []
            ),
            *(
                ["Source selection scope or run window differs."]
                if (left.scope, left.source_run_offset) != (right.scope, right.source_run_offset)
                else []
            ),
        ],
    }
