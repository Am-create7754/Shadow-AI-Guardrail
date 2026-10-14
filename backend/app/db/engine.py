"""Async database engine factory.

SQLite specifics
----------------
* WAL journal: readers (dashboard, verifier) never block the single writer.
* ``busy_timeout``: concurrent writers wait for the lock instead of failing.
* Transactions normally start with plain ``BEGIN`` (deferred). A connection
  carrying the execution option ``sqlite_begin="IMMEDIATE"`` starts with
  ``BEGIN IMMEDIATE`` instead, which takes the database write lock up front. The
  audit chain uses this so that "read chain head -> append next event" is atomic
  across connections *and* processes.

On PostgreSQL the same code path relies on ``SELECT ... FOR UPDATE`` of the
chain-head row (see ``app.audit.service``); the SQLite hooks are not installed.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import event
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker, create_async_engine

SQLITE_BUSY_TIMEOUT_MS = 15_000


def is_sqlite(url: str) -> bool:
    return url.startswith("sqlite")


def create_engine(url: str, *, echo: bool = False) -> AsyncEngine:
    kwargs: dict[str, Any] = {"echo": echo}
    if is_sqlite(url):
        kwargs["connect_args"] = {"timeout": SQLITE_BUSY_TIMEOUT_MS / 1000}
    engine = create_async_engine(url, **kwargs)
    if is_sqlite(url):
        _install_sqlite_hooks(engine)
    return engine


def _install_sqlite_hooks(engine: AsyncEngine) -> None:
    sync_engine = engine.sync_engine

    @event.listens_for(sync_engine, "connect")
    def _on_connect(dbapi_conn: Any, _record: Any) -> None:
        # Let SQLAlchemy (not the driver) emit BEGIN, so we control its mode.
        dbapi_conn.isolation_level = None
        cur = dbapi_conn.cursor()
        try:
            cur.execute("PRAGMA journal_mode=WAL")
            cur.execute(f"PRAGMA busy_timeout={SQLITE_BUSY_TIMEOUT_MS}")
            cur.execute("PRAGMA foreign_keys=ON")
            # Make REPLACE conflict-deletions fire DELETE triggers (append-only guard).
            cur.execute("PRAGMA recursive_triggers=ON")
            cur.execute("PRAGMA synchronous=FULL")  # audit data must survive power loss
        finally:
            cur.close()

    @event.listens_for(sync_engine, "begin")
    def _on_begin(conn: Connection) -> None:
        mode = conn.get_execution_options().get("sqlite_begin", "DEFERRED")
        if mode not in ("DEFERRED", "IMMEDIATE", "EXCLUSIVE"):
            raise ValueError(f"invalid sqlite_begin mode {mode!r}")
        conn.exec_driver_sql(f"BEGIN {mode}")


def session_factory(engine: AsyncEngine) -> async_sessionmaker[Any]:
    return async_sessionmaker(engine, expire_on_commit=False)
