"""Deep structural tables through the API: verified reads, pagination, honesty."""

from pathlib import Path

from api_support import api_client, create_project, ctx_of, do_import, make_settings
from conftest import ELF_AARCH64, PE_X86_64_EXE
from sqlalchemy import select

from bytasm.db.models import ToolInvocation


def test_structure_tables_are_paginated_and_verified(tmp_path: Path) -> None:
    with api_client(make_settings(tmp_path)) as client:
        project = create_project(client)
        pe = do_import(client, project, PE_X86_64_EXE.read_bytes()).json()["sample_version"]
        response = client.get(f"/api/v1/sample-versions/{pe['id']}/structure")
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["state"] == "available" and body["adapter_version"] == "0.3.0"
        assert body["format"] == "PE" and body["header"]["image_base"] == 0x140000000
        tables = {t["name"]: t for t in body["tables"]}
        slots = tables["import_slots"]
        assert slots["count"] > 5 and "PE import address table" in slots["provenance"]
        page = client.get(
            f"/api/v1/sample-versions/{pe['id']}/structure",
            params={"table": "import_slots", "offset": 2, "limit": 3},
        ).json()
        [only] = page["tables"]
        assert only["rows"] == slots["rows"][2:5] and only["next_offset"] == 5
        assert (
            client.get(
                f"/api/v1/sample-versions/{pe['id']}/structure", params={"table": "elf.notes"}
            ).status_code
            == 404
        )
        assert (
            client.get(
                f"/api/v1/sample-versions/{pe['id']}/structure", params={"table": "nope"}
            ).status_code
            == 422
        )
        elf = do_import(client, project, ELF_AARCH64.read_bytes(), sample_name="aarch64").json()[
            "sample_version"
        ]
        notes = client.get(
            f"/api/v1/sample-versions/{elf['id']}/structure", params={"table": "elf.notes"}
        ).json()
        assert any(n["type"] == "GNU_BUILD_ID" for n in notes["tables"][0]["rows"])
        assert client.get(f"/api/v1/sample-versions/{'0' * 32}/structure").status_code == 404
        # A tampered output digest is refused, never served.
        with ctx_of(client).sessions() as session, session.begin():
            inv = session.scalars(
                select(ToolInvocation).where(ToolInvocation.tool_name == "lief")
            ).first()
            assert inv is not None
            inv.raw_output_sha256 = "f" * 64
        from bytasm import structure_source

        structure_source._cache.clear()
        broken = [
            client.get(f"/api/v1/sample-versions/{v}/structure").status_code
            for v in (pe["id"], elf["id"])
        ]
        assert 409 in broken
