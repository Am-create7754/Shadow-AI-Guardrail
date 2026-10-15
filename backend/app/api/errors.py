"""Structured errors that never echo request content.

FastAPI's default 422 body includes the offending ``input`` value - for a
security gateway that could be the very secret being protected - so validation
errors are re-rendered with location, type and message only.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.detection.engine import InputTooLargeError
from app.providers.base import ProviderError

logger = logging.getLogger("guardrail.api")

_PROVIDER_STATUS = {
    "timeout": 504,
    "rate_limited": 503,
    "unavailable": 502,
    "bad_response": 502,
    "bad_request": 400,  # e.g. the provider does not know the model
    "quota_exhausted": 503,  # the gateway's provider account is out of credit
}
_HTTP_TYPES = {
    400: "bad_request",
    401: "unauthorized",
    403: "forbidden",
    404: "not_found",
    405: "method_not_allowed",
    409: "conflict",
    413: "payload_too_large",
    415: "unsupported_media_type",
    429: "rate_limited",
}


class ApiError(Exception):
    def __init__(
        self,
        status: int,
        kind: str,
        message: str,
        *,
        details: Any = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        super().__init__(message)
        self.status, self.kind, self.message = status, kind, message
        self.details, self.headers = details, headers


def request_id(request: Request) -> str:
    return str(getattr(request.state, "request_id", ""))


def error_response(
    request: Request,
    status: int,
    kind: str,
    message: str,
    *,
    details: Any = None,
    headers: dict[str, str] | None = None,
) -> JSONResponse:
    body: dict[str, Any] = {"type": kind, "message": message, "request_id": request_id(request)}
    if details is not None:
        body["details"] = details
    return JSONResponse({"error": body}, status_code=status, headers=headers)


def install_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(ApiError)
    async def _api_error(request: Request, exc: ApiError) -> JSONResponse:
        return error_response(
            request, exc.status, exc.kind, exc.message, details=exc.details, headers=exc.headers
        )

    @app.exception_handler(RequestValidationError)
    async def _validation(request: Request, exc: RequestValidationError) -> JSONResponse:
        errors = []
        for e in exc.errors():
            loc = list(e.get("loc", ()))
            if e.get("type") == "extra_forbidden" and loc:
                loc[-1] = "<unknown field>"  # the name itself may be sensitive text
            errors.append({"loc": loc, "type": e.get("type"), "msg": e.get("msg")})
        return error_response(
            request, 422, "validation_error", "request validation failed", details=errors
        )

    @app.exception_handler(StarletteHTTPException)
    async def _http(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        kind = _HTTP_TYPES.get(exc.status_code, "http_error")
        message = exc.detail if isinstance(exc.detail, str) else kind.replace("_", " ")
        return error_response(
            request, exc.status_code, kind, message, headers=getattr(exc, "headers", None)
        )

    @app.exception_handler(InputTooLargeError)
    async def _too_large(request: Request, exc: InputTooLargeError) -> JSONResponse:
        return error_response(request, 413, "input_too_large", str(exc))

    @app.exception_handler(ProviderError)
    async def _provider(request: Request, exc: ProviderError) -> JSONResponse:
        status = _PROVIDER_STATUS.get(exc.kind, 502)
        return error_response(request, status, f"provider_{exc.kind}", exc.detail)
