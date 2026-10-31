"""Synthetic exact-reference evidence pinned through real persistence and export APIs."""

import hashlib
import json
from pathlib import Path

from api_support import api_client, ctx_of, make_settings
from sqlalchemy import select
from test_ghidra_api import seed_document

from bytasm.db.models import ToolInvocation


def test_ghidra3_references_are_pinned_and_export_privacy_omits_values(tmp_path: Path) -> None:
    with api_client(make_settings(tmp_path)) as client:
        run, digest = seed_document(client)
        ctx = ctx_of(client)
        raw = ctx.outputs.read_verified(digest)
        value = json.loads(raw)
        value["schema_version"] = "ghidra-3"
        fn = value["functions"][0]
        fn["body_ranges"] = [{"start": fn["entry"], "end": fn["entry"]}]
        fn["references"] = [
            {
                "source": fn["entry"],
                "target": {"space": "ram", "address": "00402000"},
                "kind": "string",
                "reference_type": "DATA",
                "provenance": "ghidra_instruction_reference",
                "target_name": "private_symbol",
                "preview": "private string payload",
            }
        ]
        from bytasm.ghidra_protocol import GhidraResult

        updated = GhidraResult.model_validate(value).model_dump_json().encode()
        updated_digest = hashlib.sha256(updated).hexdigest()
        ctx.outputs.put_bytes(updated, updated_digest, ctx.tmp_dir)
        with ctx.sessions() as session, session.begin():
            invocation = session.scalars(
                select(ToolInvocation).where(ToolInvocation.run_id == run)
            ).one()
            invocation.raw_output_sha256 = updated_digest
            invocation.raw_output_path = ctx.outputs.relative_path(updated_digest)
        version = client.get(f"/api/v1/runs/{run}").json()["sample"]["version_id"]
        response = client.post(f"/api/v1/sample-versions/{version}/reviews", json={})
        assert response.status_code == 201, response.text
        pinned = response.json()
        evidence = pinned["function_evidence"][0]
        assert evidence["references"][0]["target"]["space"] == "ram"
        assert evidence["references"][0]["preview"] == "private string payload"
        assert evidence["body_ranges"][0]["provenance"] == "ghidra_function_body"
        export = f"/api/v1/reviews/{pinned['id']}/export/json"
        minimized = client.post(export, json={})
        assert minimized.status_code == 200, minimized.text
        assert "private string payload" not in minimized.text
        assert "private_symbol" not in minimized.text
        included = client.post(export, json={"string_values": True})
        assert "private string payload" in included.text
        assert "private_symbol" not in included.text
        assert (
            client.post(export, json={"technical_details": False}).json()["function_evidence"] == []
        )
        assert client.get(f"/api/v1/reviews/{pinned['id']}").json() == pinned
        # ghidra-3 keeps the selected-function report contract and its dossier.
        analysis_export = client.get(f"/api/v1/runs/{run}/ghidra/export?format=json").json()
        assert analysis_export["schema_version"] == "bytasm-ghidra-report-2"
        assert analysis_export["analysis"]["schema_version"] == "ghidra-3"
