"""Liveness / readiness (unauthenticated, reveal nothing about configuration)."""

from __future__ import annotations

from fastapi import APIRouter
from sqlalchemy import text

from app.api.deps import ServicesDep
from app.api.errors import ApiError

router = APIRouter(tags=["health"])


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
