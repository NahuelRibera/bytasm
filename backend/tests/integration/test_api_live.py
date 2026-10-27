"""M3 against a real uvicorn server: interrupted uploads (Q1), disconnect during
parsing (Q2), and the streaming size limit, using raw sockets.

Pinned versions under test: see backend/uv.lock (uvicorn 0.54.x with h11,
Starlette 1.10.x). Re-run whenever those pins change (blueprint 5.4.1).
"""

import json
import socket
import time
from pathlib import Path

import httpx
from api_support import (
    assert_nothing_imported,
    fake_adapter,
    import_headers,
    live_server,
    row_counts,
    temp_entries,
    wait_until,
)
from conftest import ELF_AARCH64

from bytasm.config import Settings


def _project(settings: Settings) -> str:
    response = httpx.post(
        f"http://127.0.0.1:{settings.port}/api/v1/projects",
        json={"name": "Live"},
        headers={"X-Bytasm-Request": "1"},
    )
    assert response.status_code == 201
    project_id: str = response.json()["id"]
    return project_id


def _request_head(settings: Settings, project: str, extra: dict[str, str]) -> bytes:
    headers = {
        "Host": f"127.0.0.1:{settings.port}",
        "X-Bytasm-Request": "1",
        **import_headers(),
        **extra,
    }
    lines = [f"POST /api/v1/projects/{project}/imports HTTP/1.1"]
    lines += [f"{name}: {value}" for name, value in headers.items()]
    return ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1")


def _connect(settings: Settings) -> socket.socket:
    return socket.create_connection(("127.0.0.1", settings.port), timeout=10)


def _read_response(sock: socket.socket) -> bytes:
    """Read one HTTP response with a Content-Length body."""
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(65536)
        if not chunk:
            return data
        data += chunk
    head, body = data.split(b"\r\n\r\n", 1)
    length = 0
    for line in head.split(b"\r\n")[1:]:
        name, _, value = line.partition(b":")
        if name.strip().lower() == b"content-length":
            length = int(value.strip())
    while len(body) < length:
        chunk = sock.recv(65536)
        if not chunk:
            break
        body += chunk
    return head + b"\r\n\r\n" + body


def _import_ok(settings: Settings, project: str, name: str) -> int:
    response = httpx.post(
        f"http://127.0.0.1:{settings.port}/api/v1/projects/{project}/imports",
        content=ELF_AARCH64.read_bytes(),
        headers={"X-Bytasm-Request": "1", **import_headers(sample_name=name)},
        timeout=60,
    )
    return response.status_code


def test_q1_upload_interrupted_with_content_length(tmp_path: Path) -> None:
    data = ELF_AARCH64.read_bytes()
    with live_server(tmp_path) as (settings, ctx):
        project = _project(settings)
        sock = _connect(settings)
        sock.sendall(_request_head(settings, project, {"Content-Length": str(len(data))}))
        sock.sendall(data[: len(data) // 2])
        time.sleep(0.3)
        sock.close()  # abort mid-body

        assert wait_until(lambda: not ctx.parser_slot.busy)
        assert wait_until(lambda: temp_entries(ctx) == [])
        assert_nothing_imported(ctx)
        # The server keeps serving, and the slot was released.
        assert _import_ok(settings, project, "after") == 201


def test_q1_upload_interrupted_without_content_length(tmp_path: Path) -> None:
    data = ELF_AARCH64.read_bytes()
    with live_server(tmp_path) as (settings, ctx):
        project = _project(settings)
        sock = _connect(settings)
        sock.sendall(_request_head(settings, project, {"Transfer-Encoding": "chunked"}))
        chunk = data[:4096]
        sock.sendall(f"{len(chunk):x}\r\n".encode() + chunk + b"\r\n")
        time.sleep(0.3)
        sock.close()  # no terminating zero-length chunk: the body never completed

        assert wait_until(lambda: not ctx.parser_slot.busy)
        assert wait_until(lambda: temp_entries(ctx) == [])
        assert_nothing_imported(ctx)
        assert _import_ok(settings, project, "after") == 201


def test_q1_body_shorter_than_content_length_is_rejected(tmp_path: Path) -> None:
    data = ELF_AARCH64.read_bytes()
    with live_server(tmp_path) as (settings, ctx):
        project = _project(settings)
        sock = _connect(settings)
        sock.sendall(_request_head(settings, project, {"Content-Length": str(len(data) + 100)}))
        sock.sendall(data)
        sock.shutdown(socket.SHUT_WR)  # the client says it has finished sending
        reply = _read_response(sock)
        sock.close()
        # h11 sees the connection end before Content-Length bytes arrived. The
        # app gets http.disconnect, so the upload never counts as complete.
        assert b" 201 " not in reply.split(b"\r\n", 1)[0]
        assert wait_until(lambda: not ctx.parser_slot.busy)
        assert_nothing_imported(ctx)


def test_streamed_upload_stops_being_read_at_the_limit(tmp_path: Path) -> None:
    with live_server(tmp_path, max_upload_bytes=64 * 1024) as (settings, ctx):
        project = _project(settings)
        sock = _connect(settings)
        sock.settimeout(2)
        sock.sendall(_request_head(settings, project, {"Transfer-Encoding": "chunked"}))
        chunk = b"\x7fELF" + bytes(64 * 1024 - 4)
        sent = 0
        target = 64 * 1024 * 1024
        try:
            while sent < target:
                sock.sendall(f"{len(chunk):x}\r\n".encode() + chunk + b"\r\n")
                sent += len(chunk)
        except (TimeoutError, BrokenPipeError, ConnectionResetError):
            pass
        sock.settimeout(10)
        try:
            reply = sock.recv(65536)
        except ConnectionResetError:
            reply = b""
        sock.close()
        assert sent < target, "the server accepted the whole oversized body"
        if reply:
            status_line = reply.split(b"\r\n", 1)[0]
            assert b" 413 " in status_line, status_line
            assert b"connection: close" in reply.lower()
        assert wait_until(lambda: not ctx.parser_slot.busy)
        assert_nothing_imported(ctx)


def test_q2_disconnect_during_parsing_still_commits_and_cleans_up(tmp_path: Path) -> None:
    """Observed with the pinned uvicorn: the handler is not cancelled on disconnect.

    The parse runs to completion and the import is committed although the
    client has gone (a deliberate trade-off, blueprint 5.4.1). No child process
    or temp directory remains.
    """
    data = ELF_AARCH64.read_bytes()
    with live_server(tmp_path, fake_adapter("slow_real")) as (settings, ctx):
        project = _project(settings)
        sock = _connect(settings)
        sock.sendall(_request_head(settings, project, {"Content-Length": str(len(data))}))
        sock.sendall(data)
        time.sleep(0.5)  # the child is now parsing (it sleeps 1.5 s first)
        assert ctx.parser_slot.busy
        sock.close()

        assert wait_until(lambda: row_counts(ctx)["sample_version"] == 1, timeout=20)
        assert wait_until(lambda: not ctx.parser_slot.busy)
        assert wait_until(lambda: temp_entries(ctx) == [])
        # A re-upload is reported as a duplicate of the committed version.
        samples = httpx.get(f"http://127.0.0.1:{settings.port}/api/v1/projects/{project}/samples")
        sample_id = samples.json()[0]["id"]
        again = httpx.post(
            f"http://127.0.0.1:{settings.port}/api/v1/projects/{project}/imports",
            content=data,
            headers={"X-Bytasm-Request": "1", **import_headers(sample_id=sample_id)},
            timeout=60,
        )
        assert again.status_code == 409


def test_raw_requests_with_foreign_host_or_preflight_are_refused(tmp_path: Path) -> None:
    with live_server(tmp_path) as (settings, ctx):
        sock = _connect(settings)
        sock.sendall(b"GET /api/v1/health HTTP/1.1\r\nHost: attacker.example\r\n\r\n")
        reply = _read_response(sock)
        sock.close()
        assert reply.startswith(b"HTTP/1.1 400 ")

        sock = _connect(settings)
        sock.sendall(
            f"OPTIONS /api/v1/projects HTTP/1.1\r\nHost: 127.0.0.1:{settings.port}\r\n"
            "Origin: http://attacker.example\r\nAccess-Control-Request-Method: POST\r\n"
            "Access-Control-Request-Headers: x-bytasm-request\r\n\r\n".encode()
        )
        reply = _read_response(sock)
        sock.close()
        assert reply.startswith(b"HTTP/1.1 403 ")
        assert b"access-control-allow" not in reply.lower()
        body = json.loads(reply.split(b"\r\n\r\n", 1)[1])
        assert body["code"] == "origin_not_allowed"
        assert ctx.parser_slot.busy is False
