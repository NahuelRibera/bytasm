"""M3: request guards (blueprint 9.1 "Cross-site request guard", Q8 at the HTTP level).

The browser-level CORS check (a page on another origin trying to POST) is in
the Playwright suite (frontend/e2e).
"""

from collections.abc import Iterator
from pathlib import Path

import pytest
from api_support import api_client, create_project, import_headers, make_settings
from conftest import ELF_AARCH64
from fastapi.testclient import TestClient


@pytest.fixture
def client(tmp_path: Path) -> Iterator[TestClient]:
    with api_client(make_settings(tmp_path)) as test_client:
        yield test_client


@pytest.mark.parametrize("host", ["127.0.0.1:8000", "localhost:8000", "[::1]:8000"])
def test_own_host_names_are_accepted(client: TestClient, host: str) -> None:
    assert client.get("/api/v1/health", headers={"Host": host}).status_code == 200


@pytest.mark.parametrize(
    "host",
    ["evil.example", "evil.example:8000", "127.0.0.1:9999", "127.0.0.1", "rebind.127.0.0.1.nip.io"],
)
def test_foreign_host_is_refused(client: TestClient, host: str) -> None:
    """Blocks DNS rebinding: the attacker's page sends its own host name."""
    response = client.get("/api/v1/health", headers={"Host": host})
    assert response.status_code == 400
    assert response.json()["code"] == "host_not_allowed"
    project = client.post("/api/v1/projects", json={"name": "x"}, headers={"Host": host})
    assert project.status_code == 400
    assert client.get("/api/v1/projects").json() == []


def test_foreign_origin_is_refused(client: TestClient) -> None:
    response = client.post(
        "/api/v1/projects", json={"name": "x"}, headers={"Origin": "http://evil.example"}
    )
    assert response.status_code == 403
    assert response.json()["code"] == "origin_not_allowed"
    assert client.get("/api/v1/projects").json() == []


@pytest.mark.parametrize("origin", ["null", "http://127.0.0.1:5173", "https://127.0.0.1:8000"])
def test_other_origins_are_refused(client: TestClient, origin: str) -> None:
    response = client.get("/api/v1/health", headers={"Origin": origin})
    assert response.status_code == 403


def test_own_origin_is_accepted(client: TestClient) -> None:
    response = client.post(
        "/api/v1/projects", json={"name": "x"}, headers={"Origin": "http://127.0.0.1:8000"}
    )
    assert response.status_code == 201


def test_cross_site_fetch_metadata_is_refused(client: TestClient) -> None:
    response = client.post(
        "/api/v1/projects", json={"name": "x"}, headers={"Sec-Fetch-Site": "cross-site"}
    )
    assert response.status_code == 403


def test_mutation_without_custom_header_is_refused(tmp_path: Path) -> None:
    with api_client(make_settings(tmp_path)) as client:
        project = create_project(client)
        client.headers.pop("X-Bytasm-Request")

        response = client.post("/api/v1/projects", json={"name": "x"})
        assert response.status_code == 403
        assert response.json()["code"] == "missing_request_header"

        # A "simple" cross-site form post would look like this: no custom header.
        response = client.post(
            f"/api/v1/projects/{project}/imports",
            content=ELF_AARCH64.read_bytes(),
            headers=import_headers(),
        )
        assert response.status_code == 403
        assert client.get(f"/api/v1/projects/{project}/samples").json() == []


def test_cors_preflight_gets_no_permission(client: TestClient) -> None:
    response = client.options(
        "/api/v1/projects",
        headers={
            "Origin": "http://evil.example",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "x-bytasm-request, content-type",
        },
    )
    assert response.status_code == 403
    assert not any(h.lower().startswith("access-control-") for h in response.headers)


def test_same_origin_preflight_is_also_not_granted(client: TestClient) -> None:
    client.headers.pop("X-Bytasm-Request")  # a preflight never carries custom headers
    response = client.options(
        "/api/v1/projects",
        headers={"Access-Control-Request-Method": "POST"},
    )
    assert response.status_code == 403
    assert "access-control-allow-origin" not in response.headers


def test_no_response_ever_carries_cors_permission(client: TestClient) -> None:
    for response in (
        client.get("/api/v1/health", headers={"Origin": "http://127.0.0.1:8000"}),
        client.get("/api/v1/health", headers={"Origin": "http://evil.example"}),
        client.get("/"),
    ):
        assert "access-control-allow-origin" not in response.headers


def test_security_headers_on_every_response(client: TestClient) -> None:
    for response in (client.get("/api/v1/health"), client.get("/api/v1/nope"), client.get("/")):
        assert response.headers["x-content-type-options"] == "nosniff"
        assert response.headers["x-frame-options"] == "DENY"
        assert "default-src 'self'" in response.headers["content-security-policy"]
        assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
        assert len(response.headers["x-request-id"]) == 32
    assert client.get("/api/v1/health").headers["cache-control"] == "no-store"


def test_non_loopback_connection_is_refused(tmp_path: Path) -> None:
    """Defence in depth if the app were ever served on another interface."""
    from fastapi.testclient import TestClient as Client

    from bytasm.api.app import create_app

    with Client(
        create_app(make_settings(tmp_path)),
        base_url="http://192.168.1.20:8000",
        headers={"Host": "127.0.0.1:8000"},
    ) as remote:
        response = remote.get("/api/v1/health")
        assert response.status_code == 403
        assert response.json()["code"] == "not_loopback"


def test_container_mode_skips_only_the_listener_check(tmp_path: Path) -> None:
    """In container mode the listener is the container's interface; the Host,
    Origin and request-header guards still apply."""
    from fastapi.testclient import TestClient as Client

    from bytasm.api.app import create_app

    settings = make_settings(tmp_path, host="0.0.0.0", container=True)  # noqa: S104
    with Client(
        create_app(settings),
        base_url="http://172.18.0.2:8000",
        headers={"Host": "127.0.0.1:8000"},
    ) as container:
        assert container.get("/api/v1/health").status_code == 200
        foreign_host = container.get("/api/v1/health", headers={"Host": "172.18.0.2:8000"})
        assert foreign_host.json()["code"] == "host_not_allowed"
        cross_site = container.post(
            "/api/v1/projects",
            json={"name": "x"},
            headers={"Origin": "http://evil.example", "X-Bytasm-Request": "1"},
        )
        assert cross_site.json()["code"] == "origin_not_allowed"
        no_header = container.post("/api/v1/projects", json={"name": "x"})
        assert no_header.json()["code"] == "missing_request_header"


def test_static_paths_never_leave_the_ui_bundle(tmp_path: Path) -> None:
    from fastapi.testclient import TestClient as Client

    from bytasm.api.app import create_app

    dist = tmp_path / "dist"
    (dist / "assets").mkdir(parents=True)
    (dist / "index.html").write_text("<!doctype html><title>Bytasm</title>")
    (dist / "assets" / "app.js").write_text("// bundle")
    (tmp_path / "secret.txt").write_text("outside the bundle")
    settings = make_settings(tmp_path, web_dist=dist)
    with Client(create_app(settings), base_url="http://127.0.0.1:8000") as web:
        assert web.get("/assets/app.js").text == "// bundle"
        for path in ("/../secret.txt", "/%2e%2e/secret.txt", "/assets/%2e%2e/%2e%2e/secret.txt"):
            response = web.get(path)
            assert response.status_code == 200
            assert "outside the bundle" not in response.text
        # An encoded NUL byte used to raise inside Path.resolve() (500).
        nul = web.get("/assets/%00app.js")
        assert nul.status_code == 200
        assert "<title>Bytasm</title>" in nul.text


def test_errors_use_problem_details(client: TestClient) -> None:
    response = client.get(f"/api/v1/sample-versions/{'0' * 32}")
    assert response.status_code == 404
    assert response.headers["content-type"] == "application/problem+json"
    body = response.json()
    assert body["type"] == "urn:bytasm:error:not_found"
    assert set(body) >= {"type", "code", "title", "status", "detail", "request_id"}
    invalid = client.post("/api/v1/projects", json={"name": ""})
    assert invalid.status_code == 422
    assert invalid.json()["code"] == "invalid_request"
