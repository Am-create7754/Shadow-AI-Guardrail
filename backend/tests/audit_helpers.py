"""Shared fixtures/helpers for audit tests, including an 'attacker' with raw DB access."""

from __future__ import annotations

import sqlite3
from collections.abc import AsyncIterator, Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest_asyncio
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.audit.keys import AuditKeyring, CheckpointSigner
from app.audit.schemas import AuditEventIn
from app.audit.service import AuditLog
from app.db.engine import create_engine

AUDIT_KEY = b"A" * 32  # test-only key material, not a secret


def event(i: int = 0, **kw: object) -> AuditEventIn:
    data = kw.pop("data", {"action": "REDACT", "risk_score": 40 + i, "entities": ["PASSWORD"]})
    return AuditEventIn(
        event_type=str(kw.pop("event_type", "prompt.inspected")),
        actor=str(kw.pop("actor", "user-1")),
        request_id=kw.pop("request_id", f"req-{i}"),  # type: ignore[arg-type]
        data=data,  # type: ignore[arg-type]
    )


@pytest_asyncio.fixture
async def audit(tmp_path: Path) -> AsyncIterator[AuditLog]:
    engine = create_engine(f"sqlite+aiosqlite:///{(tmp_path / 'audit.db').as_posix()}")
    log = AuditLog(
        engine,
        AuditKeyring.from_keys(AUDIT_KEY),
        CheckpointSigner(Ed25519PrivateKey.generate()),
        checkpoint_interval=5,
        anchor_path=tmp_path / "anchor" / "audit_anchor.json",
    )
    await log.create_schema()
    try:
        yield log
    finally:
        await engine.dispose()


def db_path(log: AuditLog) -> str:
    database = log.engine.url.database
    assert database, "audit tests require a file-backed SQLite database"
    return database


@contextmanager
def attacker(log: AuditLog) -> Iterator[sqlite3.Connection]:
    """Direct file access, bypassing the application: drops the append-only triggers."""
    conn = sqlite3.connect(db_path(log), isolation_level=None)
    try:
        for (name,) in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='trigger'"
        ).fetchall():
            conn.execute(f"DROP TRIGGER {name}")
        yield conn
    finally:
        conn.close()
