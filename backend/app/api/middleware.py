"""Pure-ASGI middleware: request ids, security headers, body-size limit.

Written as raw ASGI (not BaseHTTPMiddleware) so the size limit applies while the
body streams in - before any JSON parsing - including chunked uploads that send
no Content-Length.
"""

from __future__ import annotations

import json
import logging
import uuid
from typing import Any

from starlette.types import ASGIApp, Message, Receive, Scope, Send

logger = logging.getLogger("guardrail.api")

SECURITY_HEADERS = [
    (b"x-content-type-options", b"nosniff"),
    (b"x-frame-options", b"DENY"),
    (b"referrer-policy", b"no-referrer"),
    (b"cache-control", b"no-store"),
    (b"content-security-policy", b"default-src 'none'; frame-ancestors 'none'"),
    (b"cross-origin-resource-policy", b"same-site"),
]
# Interactive API docs need scripts and styles; they are disabled in production.
_DOCS_PATHS = frozenset({"/docs", "/docs/oauth2-redirect", "/openapi.json"})


def _error_body(request_id: str, status: int, kind: str, message: str) -> bytes:
    return json.dumps(
        {"error": {"type": kind, "message": message, "request_id": request_id}}
    ).encode()


class GatewayMiddleware:
    def __init__(self, app: ASGIApp, *, max_body_bytes: int) -> None:
        self.app = app
        self.max_body_bytes = max_body_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        # Always generated server-side: a client-chosen id could collide with or
        # impersonate another request in the audit log.
        request_id = uuid.uuid4().hex
        scope.setdefault("state", {})["request_id"] = request_id
        path: str = scope.get("path", "")
        response_started = False
        rejected = False  # we already answered 413; swallow the app's own response

        async def send_wrapper(message: Message) -> None:
            nonlocal response_started
            if rejected:
                return
            if message["type"] == "http.response.start":
                response_started = True
                headers: list[tuple[bytes, bytes]] = list(message.get("headers", []))
                headers.append((b"x-request-id", request_id.encode()))
                existing = {k.lower() for k, _ in headers}
                for name, value in SECURITY_HEADERS:
                    if name == b"content-security-policy" and path in _DOCS_PATHS:
                        continue
                    if name not in existing:
                        headers.append((name, value))
                message["headers"] = headers
            await send(message)

        async def reject(status: int, kind: str, msg: str) -> None:
            body = _error_body(request_id, status, kind, msg)
            await send_wrapper(
                {
                    "type": "http.response.start",
                    "status": status,
                    "headers": [
                        (b"content-type", b"application/json"),
                        (b"content-length", str(len(body)).encode()),
                    ],
                }
            )
            await send_wrapper({"type": "http.response.body", "body": body})

        declared = _content_length(scope)
        if declared is not None and declared > self.max_body_bytes:
            await reject(
                413, "payload_too_large", f"request body exceeds {self.max_body_bytes} bytes"
            )
            return

        received = 0

        async def receive_wrapper() -> Message:
            # Streaming bodies (no Content-Length): answer 413 ourselves as soon as
            # the limit is crossed, then tell the app the client went away. Raising
            # instead would be turned into a 400 by FastAPI's body parsing.
            nonlocal received, rejected
            if rejected:
                return {"type": "http.disconnect"}
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_body_bytes:
                    if not response_started:
                        await reject(
                            413,
                            "payload_too_large",
                            f"request body exceeds {self.max_body_bytes} bytes",
                        )
                    rejected = True
                    return {"type": "http.disconnect"}
            return message

        try:
            await self.app(scope, receive_wrapper, send_wrapper)
        except Exception as exc:
            if rejected:
                return
            # Contain everything here, inside the security-header wrapper: letting
            # it reach Starlette's ServerErrorMiddleware would drop our headers and
            # make the server log the exception message (which may contain data).
            logger.error(
                "unhandled %s on %s %s (request %s)",
                type(exc).__name__,
                scope.get("method"),
                path,
                request_id,
            )
            if not response_started:
                await reject(500, "internal_error", "internal server error")


def _content_length(scope: Scope) -> int | None:
    for name, value in scope.get("headers", []):
        if name.lower() == b"content-length":
            try:
                return int(value)
            except ValueError:
                return None
    return None


def request_id_of(scope_state: Any) -> str:
    return str(getattr(scope_state, "request_id", "") or "")
