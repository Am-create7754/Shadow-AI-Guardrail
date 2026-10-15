"""Liveness / readiness (unauthenticated, reveal nothing about configuration)."""

from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse, Response
from sqlalchemy import text

from app.api.deps import ServicesDep
from app.api.errors import ApiError

router = APIRouter(tags=["health"])


@router.get("/favicon.ico", include_in_schema=False)
async def favicon() -> Response:
    """Browsers ask for this automatically; answer quietly instead of logging a 404."""
    return Response(status_code=204)


@router.api_route("/", methods=["GET", "HEAD"], include_in_schema=False)
async def root(request: Request) -> Response:
    """Send browsers to the interactive docs (when enabled, i.e. outside production)."""
    if request.app.docs_url:
        return RedirectResponse(request.app.docs_url)
    return Response(status_code=404)


@router.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/ready")
async def ready(services: ServicesDep) -> dict[str, str]:
    try:
        async with services.audit.engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
    except Exception as exc:
        raise ApiError(503, "not_ready", "database unavailable") from exc
    return {"status": "ready"}
