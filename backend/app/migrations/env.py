"""Alembic environment (async engine, URL from application settings)."""

from __future__ import annotations

import asyncio
from pathlib import Path

from alembic import context
from sqlalchemy.engine import Connection

import app.approvals.models
import app.audit.models
import app.auth.models  # noqa: F401
from app.core.config import get_settings
from app.db.base import Base
from app.db.engine import create_engine, is_sqlite

config = context.config
target_metadata = Base.metadata


def _url() -> str:
    # Tests and tools may pass an explicit URL; otherwise use application settings.
    return config.get_main_option("sqlalchemy.url") or get_settings().database_url


def run_migrations_offline() -> None:
    context.configure(url=_url(), target_metadata=target_metadata, literal_binds=True,
                      render_as_batch=True)  # fmt: skip
    with context.begin_transaction():
        context.run_migrations()


def _run(connection: Connection) -> None:
    context.configure(connection=connection, target_metadata=target_metadata,
                      render_as_batch=is_sqlite(_url()))  # fmt: skip
    with context.begin_transaction():
        context.run_migrations()


async def run_migrations_online() -> None:
    url = _url()
    if is_sqlite(url) and ":///" in url:
        Path(url.split(":///", 1)[1]).parent.mkdir(parents=True, exist_ok=True)
    engine = create_engine(url)
    async with engine.connect() as connection:
        await connection.run_sync(_run)
        await connection.commit()
    await engine.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    asyncio.run(run_migrations_online())
