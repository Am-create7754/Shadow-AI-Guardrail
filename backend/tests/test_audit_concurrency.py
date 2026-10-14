"""Concurrent writers must never fork, duplicate or skip chain positions."""

from __future__ import annotations

import asyncio
import subprocess
import sys
from collections import Counter
from pathlib import Path

import pytest

from app.audit.keys import AuditKeyring
from app.audit.schemas import AuditEventIn
from app.audit.service import AuditLog
from app.db.engine import create_engine
from tests.audit_helpers import AUDIT_KEY, audit, db_path

__all__ = ["audit"]

BACKEND = Path(__file__).resolve().parents[1]


async def test_concurrent_appends_across_connection_pools(audit: AuditLog) -> None:
    """4 independent engines (separate pools) x 25 concurrent appends each."""
    engines = [create_engine(f"sqlite+aiosqlite:///{db_path(audit)}") for _ in range(4)]
    logs = [AuditLog(e, AuditKeyring.from_keys(AUDIT_KEY), checkpoint_interval=0) for e in engines]
    try:
        await asyncio.gather(
            *(
                log.append(AuditEventIn(event_type="test.concurrent", actor=f"w{w}", data={"i": i}))
                for w, log in enumerate(logs)
                for i in range(25)
            )
        )
    finally:
        for e in engines:
            await e.dispose()
    report = await audit.verify()
    assert report.ok, report.issues
    assert report.events_checked == 100
    assert await audit.head() is not None
    assert (await audit.head())[0] == 100  # type: ignore[index]


@pytest.mark.slow
async def test_concurrent_appends_across_processes(audit: AuditLog) -> None:
    """4 OS processes append to the same SQLite file at the same time."""
    procs = [
        subprocess.Popen(  # noqa: S603 - fixed argv, test-only
            [sys.executable, "-m", "tests.audit_worker", db_path(audit), str(w), "25"],
            cwd=BACKEND,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        for w in range(4)
    ]
    for p in procs:
        _, err = p.communicate(timeout=120)
        assert p.returncode == 0, err.decode(errors="replace")[-2000:]
    report = await audit.verify()
    assert report.ok, report.issues
    assert report.events_checked == 100
    events = await audit.list_events(limit=500)
    assert Counter(e.actor for e in events) == {f"worker-{w}": 25 for w in range(4)}
