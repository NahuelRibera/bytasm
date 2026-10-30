"""Known v1→v2 fixture changes, through real import and worker subprocesses.

Fixtures are parsed as data and never executed. The unchanged bundled rules
produce the same finding keys; evidence relocation is a separate observation.
"""

import asyncio
from pathlib import Path

from api_support import api_client, create_project, ctx_of, do_import, make_settings
from conftest import ELF_X86_64, ELF_X86_64_V2

from bytasm.compare import compare_versions
from bytasm.jobs.steps import ScanDeps
from bytasm.jobs.worker import Worker
from bytasm.runner.supervisor import yara_adapter_command


def test_known_build_changes_and_deterministic_self_comparison(tmp_path: Path) -> None:
    with api_client(make_settings(tmp_path)) as client:
        project = create_project(client)
        first = do_import(client, project, ELF_X86_64.read_bytes(), sample_name="builds")
        assert first.status_code == 201, first.text
        first_body = first.json()
        second = do_import(
            client,
            project,
            ELF_X86_64_V2.read_bytes(),
            sample_id=first_body["sample_version"]["sample_id"],
        )
        assert second.status_code == 201, second.text
        a = first_body["sample_version"]["id"]
        b = second.json()["sample_version"]["id"]
        ctx = ctx_of(client)
        deps = ScanDeps(
            sessions=ctx.sessions,
            blobs=ctx.blobs,
            outputs=ctx.outputs,
            policy=ctx.policy,
            limits=ctx.settings.limits,
            tmp_dir=ctx.tmp_dir,
            adapter_command=yara_adapter_command(),
        )
        worker = Worker(deps, ctx.settings.data_dir, asyncio.Event())
        for version in (a, b):
            response = client.post(
                f"/api/v1/sample-versions/{version}/runs", json={"profile_id": "default-static"}
            )
            assert response.status_code == 202, response.text
            assert asyncio.run(worker.process_next()) == "succeeded"
        with ctx.sessions() as session:
            result = compare_versions(session, a, b, limit=200)
            imports = result.categories["imports"]
            assert imports.status == "comparable"
            assert imports.added == 1
            assert imports.removed == 0
            added_imports = [row.key for row in imports.rows if row.change == "added"]
            assert added_imports == ['[null,"getenv"]']
            strings = result.categories["strings"]
            assert strings.status == "comparable"
            assert {row.key for row in strings.rows if row.change == "added"} == {
                "/lib64/ld-linux-x86-64.so.2",
                "BYTASM_DEMO",
                "bytasm fixture v2: environment lookup",
                "getenv",
                "getenv@GLIBC_2.2.5",
                "hello_v2.c",
            }
            # Printable header bytes are observations too: the v1 loader path
            # happens to have a printable prefix in this pinned fixture.
            assert {row.key for row in strings.rows if row.change == "removed"} == {
                "g_/lib64/ld-linux-x86-64.so.2",
                "hello_v1.c",
            }
            assert (strings.added, strings.removed) == (6, 2)
            findings = result.categories["findings"]
            assert findings.status == "comparable"
            assert (findings.added, findings.removed) == (0, 0)
            assert findings.total_rows == 0
            self_diff = compare_versions(session, b, b)
            assert self_diff.identical_content
            assert all(category.total_rows == 0 for category in self_diff.categories.values())
            assert self_diff.model_dump() == compare_versions(session, b, b).model_dump()
            assert result.model_dump() == compare_versions(session, a, b, limit=200).model_dump()
