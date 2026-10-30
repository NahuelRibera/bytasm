"""Canonical JSON → inert standalone HTML, snapshot preview/history and integrity."""

from html.parser import HTMLParser
from pathlib import Path

from api_support import api_client, create_project, ctx_of, do_import, make_settings
from conftest import ELF_X86_64


class Tags(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.tags: list[str] = []
        self.attributes: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.tags.append(tag)
        self.attributes.extend(key for key, _ in attrs)


def test_html_snapshot_escaping_history_and_integrity(tmp_path: Path) -> None:
    hostile = '<img src=x onerror="alert(1)"><script>alert(2)</script>'
    with api_client(make_settings(tmp_path)) as client:
        project = create_project(client, hostile)
        version = do_import(
            client, project, ELF_X86_64.read_bytes(), declared_filename=hostile
        ).json()["sample_version"]
        annotation = client.post(
            "/api/v1/annotations",
            json={
                "target_type": "sample_version",
                "target_id": version["id"],
                "kind": "note",
                "body": hostile,
            },
        )
        assert annotation.status_code == 201
        exported = client.post(f"/api/v1/sample-versions/{version['id']}/reports")
        assert exported.status_code == 201, exported.text
        record = exported.json()
        document = client.get(record["download_url"]).json()
        assert document["schema_version"] == 4 and document["summary"]
        page = client.get(f"/api/v1/reports/{record['id']}/html?download=false")
        assert page.status_code == 200
        parser = Tags()
        parser.feed(page.text)
        assert not {"script", "img", "form", "iframe", "svg"} & set(parser.tags)
        assert not any(attr.startswith("on") for attr in parser.attributes)
        assert "&lt;script&gt;" in page.text
        assert "default-src 'none'" in page.headers["content-security-policy"]
        assert "inline" in page.headers["content-disposition"]
        assert (
            "attachment"
            in client.get(f"/api/v1/reports/{record['id']}/html").headers["content-disposition"]
        )
        history = client.get(f"/api/v1/sample-versions/{version['id']}/reports?limit=1").json()
        assert history["items"][0]["id"] == record["id"] and history["next_offset"] is None
        path = ctx_of(client).reports.path(record["sha256"])
        path.chmod(0o600)
        path.write_bytes(b"tampered")
        assert client.get(f"/api/v1/reports/{record['id']}/html").status_code == 409


def test_all_html_values_are_escaped_including_summaries_and_evidence(tmp_path: Path) -> None:
    from bytasm.reports.html import render
    from bytasm.reports.model import Report

    hostile = '<svg onload="alert(1)"><script>value</script>'
    with api_client(make_settings(tmp_path)) as client:
        project = create_project(client)
        version = do_import(client, project, ELF_X86_64.read_bytes()).json()["sample_version"]
        created = client.post(f"/api/v1/sample-versions/{version['id']}/reports").json()
        document = client.get(created["download_url"]).json()
        # Comparison values are intentionally JSON-typed: cover untrusted strings,
        # rule labels, citations and annotation text through the same recursive renderer.
        document["sample"]["project_name"] = hostile
        document["sample"]["declared_filename"]["value"] = hostile
        document["summary"] = [hostile]
        Report.model_validate(document)
        for field in ("rule label", "citation", "annotation", "string value"):
            document[field] = {hostile: [hostile]}
        html = render(document).decode()
        parser = Tags()
        parser.feed(html)
        assert not {"script", "svg", "img", "iframe", "form"} & set(parser.tags)
        assert not any(attr.startswith("on") for attr in parser.attributes)
        assert html.count("&lt;svg") >= 8
