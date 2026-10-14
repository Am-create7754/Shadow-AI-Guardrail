"""Subprocess worker for the multi-process audit concurrency test.

Usage: python -m tests.audit_worker <sqlite_path> <worker_id> <count>
"""

from __future__ import annotations

import asyncio
import sys

from app.audit.keys import AuditKeyring
from app.audit.schemas import AuditEventIn
from app.audit.service import AuditLog
from app.db.engine import create_engine
from tests.audit_helpers import AUDIT_KEY


async def main(path: str, worker: int, count: int) -> None:
    engine = create_engine(f"sqlite+aiosqlite:///{path}")
    log = AuditLog(engine, AuditKeyring.from_keys(AUDIT_KEY), checkpoint_interval=0)
    try:
        for i in range(count):
            await log.append(
                AuditEventIn(event_type="test.concurrent", actor=f"worker-{worker}", data={"i": i})
            )
    finally:
        await engine.dispose()


if __name__ == "__main__":
    asyncio.run(main(sys.argv[1], int(sys.argv[2]), int(sys.argv[3])))
