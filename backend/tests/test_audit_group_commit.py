"""Group commit (Phase 7): concurrent appends share transactions, never results."""

from __future__ import annotations

import asyncio
from typing import Any

import pytest
from sqlalchemy.exc import OperationalError

from app.audit.schemas import AuditEventIn
from app.audit.service import AuditLog
from tests.audit_helpers import audit

__all__ = ["audit"]


def _ev(i: int) -> AuditEventIn:
    return AuditEventIn(event_type="test.group", actor=f"u{i}", data={"i": i})


async def test_concurrent_appends_are_batched_and_each_caller_gets_its_record(
    audit: AuditLog, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[int] = []
    original = audit._append_many

    async def counting(batch: Any) -> Any:
        calls.append(len(batch))
        await asyncio.sleep(0.01)  # a slow disk: others queue up meanwhile
        return await original(batch)

    monkeypatch.setattr(audit, "_append_many", counting)
    records = await asyncio.gather(*(audit.append(_ev(i)) for i in range(40)))

    assert sum(calls) == 40
    assert len(calls) < 40  # several events per transaction
    assert max(calls) > 1
    assert sorted(r.seq for r in records) == list(range(1, 41))
    for i, r in enumerate(records):  # each caller received its own event
        assert r.data == {"i": i}
        assert r.actor == f"u{i}"
    report = await audit.verify()
    assert report.ok, report.issues
    assert report.events_checked == 40


async def test_a_failed_batch_fails_every_caller_in_it(
    audit: AuditLog, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def broken(batch: Any) -> Any:
        await asyncio.sleep(0.01)
        raise OperationalError("INSERT", {}, Exception("disk I/O error"))

    monkeypatch.setattr(audit, "_append_many", broken)
    results = await asyncio.gather(
        *(audit.append(_ev(i)) for i in range(10)), return_exceptions=True
    )
    assert all(isinstance(r, OperationalError) for r in results)
    monkeypatch.undo()
    assert await audit.head() is None  # nothing was half-written
    assert (await audit.append(_ev(99))).seq == 1


async def test_cancelling_the_committing_caller_does_not_fail_the_others(
    audit: AuditLog, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = audit._append_many
    started = asyncio.Event()

    async def slow(batch: Any) -> Any:
        started.set()
        await asyncio.sleep(0.05)
        return await original(batch)

    monkeypatch.setattr(audit, "_append_many", slow)
    first = asyncio.create_task(audit.append(_ev(0)))  # becomes the committer
    await started.wait()
    others = [asyncio.create_task(audit.append(_ev(i))) for i in range(1, 6)]
    await asyncio.sleep(0)
    first.cancel()  # e.g. its client disconnected
    with pytest.raises(asyncio.CancelledError):
        await first
    records = await asyncio.gather(*others)
    assert [r.data["i"] for r in records] == [1, 2, 3, 4, 5]
    report = await audit.verify()
    assert report.ok, report.issues
    assert report.events_checked == 6  # the cancelled caller's event was committed too
