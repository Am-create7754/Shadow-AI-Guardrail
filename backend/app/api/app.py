"""FastAPI application factory.

Run (PowerShell, from backend/)::

    .venv\\Scripts\\uvicorn --factory app.api.app:create_app --port 8000

Startup applies database migrations, loads keys and the policy, and creates the
provider. Interactive docs (/docs) are served outside production only.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from alembic import command
from alembic.config import Config
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.deps import Services
from app.api.errors import install_error_handlers
from app.api.middleware import GatewayMiddleware
from app.api.ratelimit import RateLimiter
from app.api.routes import admin, auth, gateway, health
from app.approvals.service import ApprovalService
from app.audit.service import AuditLog
from app.auth.service import AuthService
from app.core.config import BACKEND_DIR, Environment, Settings, get_settings
from app.core.secrets import resolve_key
from app.crypto.aead import Aead
from app.db.engine import create_engine
from app.guardrail import Guardrail
from app.providers.base import Provider
from app.providers.factory import build_provider

logger = logging.getLogger("guardrail.api")


def migrate(database_url: str) -> None:
    cfg = Config(str(BACKEND_DIR / "alembic.ini"))
    cfg.set_main_option("sqlalchemy.url", database_url)
    command.upgrade(cfg, "head")


def create_app(settings: Settings | None = None, *, provider: Provider | None = None) -> FastAPI:
    settings = settings or get_settings()
    production = settings.environment is Environment.PRODUCTION

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        await asyncio.to_thread(migrate, settings.database_url)
        engine = create_engine(settings.database_url)
        active_provider = provider or build_provider(settings)
        app.state.services = Services(
            settings=settings,
            guard=Guardrail.from_settings(settings),
            audit=AuditLog.from_settings(settings, engine),
            auth=AuthService(
                engine,
                jwt_key=resolve_key(settings, settings.jwt_secret, "jwt_secret"),
                pepper=resolve_key(settings, settings.api_key_pepper, "api_key_pepper"),
                token_ttl_minutes=settings.jwt_ttl_minutes,
            ),
            approvals=ApprovalService(
                engine,
                Aead(resolve_key(settings, settings.data_key, "data_key"), "approvals"),
                ttl_minutes=settings.approval_ttl_minutes,
            ),
            provider=active_provider,
            limiter=RateLimiter(settings.rate_limit_per_minute),
            login_limiter=RateLimiter(settings.login_rate_limit_per_minute),
        )
        logger.info("guardrail gateway started (provider=%s)", active_provider.name)
        try:
            yield
        finally:
            await active_provider.aclose()
            await engine.dispose()

    app = FastAPI(
        title="Shadow AI Guardrail",
        version="0.3.0",
        lifespan=lifespan,
        docs_url=None if production else "/docs",
        redoc_url=None,
        openapi_url=None if production else "/openapi.json",
    )
    install_error_handlers(app)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origin_list,
        allow_credentials=False,  # bearer tokens, no cookies
        allow_methods=["GET", "POST", "PATCH", "DELETE"],
        allow_headers=["Authorization", "Content-Type"],
        expose_headers=["X-Request-ID", "Retry-After"],
        max_age=600,
    )
    # Added last = outermost: size limit and request id apply to everything.
    app.add_middleware(GatewayMiddleware, max_body_bytes=settings.max_body_bytes)
    for module in (health, auth, gateway, admin):
        app.include_router(module.router)
    return app
