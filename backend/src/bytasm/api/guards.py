"""Request guards for an unauthenticated, local-only API (blueprint 5.4.1 step 1, 8.2).

A pure ASGI middleware, so it never touches the request body. For every HTTP
request it checks, in order:

1. The connection arrived on a loopback address (defence in depth: `bytasm
   serve` already refuses to bind anywhere else). Skipped only in container
   mode, where the server listens on the container's interface and Compose
   publishes the port on host 127.0.0.1 only (see `Settings.container`).
2. The `Host` header names 127.0.0.1, localhost or [::1] with Bytasm's port.
   This blocks DNS-rebinding pages, whose requests carry their own host name.
3. An `Origin` header, if present, is Bytasm's own origin, and
   `Sec-Fetch-Site`, if present, is not `cross-site`.
4. State-changing methods carry `X-Bytasm-Request: 1`. A web page on another
   origin cannot add a custom header without a CORS preflight, and Bytasm
   answers no preflight with CORS permission (it sends no
   Access-Control-Allow-* headers at all).

It also gives every request an ID and adds security headers to every response.
"""

import uuid
from collections.abc import MutableMapping
from typing import Any, Final

from starlette.types import ASGIApp, Message, Receive, Scope, Send

from bytasm.api.problems import problem
from bytasm.config import is_loopback

SAFE_METHODS: Final = frozenset({"GET", "HEAD"})
REQUEST_HEADER: Final = "x-bytasm-request"

# The SPA is a static bundle from the same origin with no inline scripts.
CONTENT_SECURITY_POLICY: Final = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; "
    "frame-ancestors 'none'"
)
SECURITY_HEADERS: Final = (
    (b"x-content-type-options", b"nosniff"),
    (b"referrer-policy", b"no-referrer"),
    (b"x-frame-options", b"DENY"),
    (b"cross-origin-opener-policy", b"same-origin"),
    (b"cross-origin-resource-policy", b"same-origin"),
    (b"content-security-policy", CONTENT_SECURITY_POLICY.encode()),
)


def _header(scope: Scope, name: bytes) -> str | None:
    for key, value in scope.get("headers", []):
        if key == name:
            return str(value.decode("latin-1"))
    return None


class LocalOnlyGuard:
    def __init__(
        self,
        app: ASGIApp,
        allowed_hosts: frozenset[str],
        allowed_origins: frozenset[str],
        require_loopback_listener: bool = True,
    ) -> None:
        self.app = app
        self.allowed_hosts = allowed_hosts
        self.allowed_origins = allowed_origins
        self.require_loopback_listener = require_loopback_listener

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request_id = uuid.uuid4().hex
        state: MutableMapping[str, Any] = scope.setdefault("state", {})
        state["request_id"] = request_id

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                headers.extend(SECURITY_HEADERS)
                headers.append((b"x-request-id", request_id.encode()))
                if scope["path"].startswith("/api/"):
                    headers.append((b"cache-control", b"no-store"))
                message["headers"] = headers
            await send(message)

        code = self._refusal(scope)
        if code is not None:
            response = problem(code, request_id=request_id)
            await response(scope, receive, send_with_headers)
            return
        await self.app(scope, receive, send_with_headers)

    def _refusal(self, scope: Scope) -> str | None:
        server = scope.get("server")
        if (
            self.require_loopback_listener
            and server is not None
            and not is_loopback(str(server[0]))
        ):
            return "not_loopback"
        if _header(scope, b"host") not in self.allowed_hosts:
            return "host_not_allowed"
        origin = _header(scope, b"origin")
        if origin is not None and origin not in self.allowed_origins:
            return "origin_not_allowed"
        if _header(scope, b"sec-fetch-site") == "cross-site":
            return "origin_not_allowed"
        if scope["method"] not in SAFE_METHODS and _header(scope, REQUEST_HEADER.encode()) != "1":
            return "missing_request_header"
        return None
