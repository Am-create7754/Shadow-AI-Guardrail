"""Approval workflow for REQUIRE_APPROVAL prompts.

State machine::

    pending --approve--> approved --execute (requester, once)--> executed
       |                    |
       +--deny--> denied    +--(ttl passes)--> expired
       +--(ttl passes)--> expired

Every transition is a single conditional UPDATE (``WHERE status = ...``), so two
admins deciding at once, or two execute calls racing, cannot both succeed.
Decryption happens only for an administrator reviewing the request or for the
one permitted execution; the ciphertext is erased on every terminal state.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, cast

from sqlalchemy import Table, insert, select, update
from sqlalchemy.ext.asyncio import AsyncEngine

from app.approvals.models import ApprovalRow, ApprovalStatus
from app.audit.chain import utc_timestamp
from app.crypto.aead import Aead

APPROVALS = cast(Table, ApprovalRow.__table__)


class ApprovalError(ValueError):
    """Operation not allowed in the current state (message is safe to show)."""


@dataclass(frozen=True)
class Approval:
    id: str
    requester_id: str
    status: ApprovalStatus
    created_at: str
    expires_at: str
    decided_at: str | None
    decided_by: str | None
    decision_note: str | None
    executed_at: str | None
    request_id: str
    model: str
    risk_score: int
    summary: dict[str, Any]

    def to_public(self) -> dict[str, Any]:
        return {**self.__dict__, "status": self.status.value}


def _row(r: Any) -> Approval:
    return Approval(
        id=r.id,
        requester_id=r.requester_id,
        status=ApprovalStatus(r.status),
        created_at=r.created_at,
        expires_at=r.expires_at,
        decided_at=r.decided_at,
        decided_by=r.decided_by,
        decision_note=r.decision_note,
        executed_at=r.executed_at,
        request_id=r.request_id,
        model=r.model,
        risk_score=r.risk_score,
        summary=json.loads(r.summary),
    )


class ApprovalService:
    def __init__(self, engine: AsyncEngine, aead: Aead, *, ttl_minutes: int) -> None:
        self.engine = engine
        self._aead = aead
        self._ttl = timedelta(minutes=ttl_minutes)

    def _seal(self, approval_id: str, messages: list[dict[str, str]]) -> bytes:
        return self._aead.encrypt(json.dumps(messages).encode(), approval_id.encode())

    def _open(self, approval_id: str, blob: bytes) -> list[dict[str, str]]:
        data = json.loads(self._aead.decrypt(blob, approval_id.encode()))
        return cast(list[dict[str, str]], data)

    async def create(
        self,
        *,
        requester_id: str,
        request_id: str,
        model: str,
        risk_score: int,
        summary: dict[str, Any],
        messages: list[dict[str, str]],
        approval_id: str | None = None,
    ) -> Approval:
        """Hold already-redacted ``messages`` for review. ``approval_id`` may be
        chosen by the caller so the audit event can be written first."""
        approval_id = approval_id or uuid.uuid4().hex
        now = datetime.now(UTC)
        async with self.engine.begin() as conn:
            await conn.execute(
                insert(APPROVALS).values(
                    id=approval_id,
                    requester_id=requester_id,
                    status=ApprovalStatus.PENDING.value,
                    created_at=utc_timestamp(now),
                    expires_at=utc_timestamp(now + self._ttl),
                    decided_at=None,
                    decided_by=None,
                    decision_note=None,
                    executed_at=None,
                    request_id=request_id,
                    model=model,
                    risk_score=risk_score,
                    summary=json.dumps(summary, sort_keys=True),
                    ciphertext=self._seal(approval_id, messages),
                )
            )
        approval = await self.get(approval_id)
        assert approval is not None  # noqa: S101 - just inserted in this function
        return approval

    async def expire_stale(self) -> int:
        """Mark overdue pending/approved requests expired and erase their content."""
        async with self.engine.begin() as conn:
            res = await conn.execute(
                update(APPROVALS)
                .where(
                    APPROVALS.c.status.in_([ApprovalStatus.PENDING, ApprovalStatus.APPROVED]),
                    APPROVALS.c.expires_at <= utc_timestamp(),
                )
                .values(status=ApprovalStatus.EXPIRED.value, ciphertext=None)
            )
        return int(res.rowcount)

    async def get(self, approval_id: str) -> Approval | None:
        async with self.engine.connect() as conn:
            row = (
                await conn.execute(select(APPROVALS).where(APPROVALS.c.id == approval_id))
            ).first()
        return _row(row) if row else None

    async def list_requests(
        self,
        *,
        requester_id: str | None = None,
        status: ApprovalStatus | None = None,
        limit: int = 100,
    ) -> list[Approval]:
        await self.expire_stale()
        stmt = select(APPROVALS).order_by(APPROVALS.c.created_at.desc()).limit(min(limit, 500))
        if requester_id is not None:
            stmt = stmt.where(APPROVALS.c.requester_id == requester_id)
        if status is not None:
            stmt = stmt.where(APPROVALS.c.status == status.value)
        async with self.engine.connect() as conn:
            rows = (await conn.execute(stmt)).all()
        return [_row(r) for r in rows]

    async def review_messages(self, approval_id: str) -> list[dict[str, str]] | None:
        """Decrypt the held (redacted) messages for an administrator's review.

        Only live requests (pending/approved, not past expiry) can be decrypted.
        """
        await self.expire_stale()
        async with self.engine.connect() as conn:
            row = (
                await conn.execute(
                    select(
                        APPROVALS.c.ciphertext, APPROVALS.c.status, APPROVALS.c.expires_at
                    ).where(APPROVALS.c.id == approval_id)
                )
            ).first()
        if row is None or row.ciphertext is None:
            return None
        live = (ApprovalStatus.PENDING.value, ApprovalStatus.APPROVED.value)
        if row.status not in live or row.expires_at <= utc_timestamp():
            return None
        return self._open(approval_id, row.ciphertext)

    async def decide(
        self, approval_id: str, *, admin_id: str, approve: bool, note: str | None = None
    ) -> Approval:
        await self.expire_stale()
        new_status = ApprovalStatus.APPROVED if approve else ApprovalStatus.DENIED
        values: dict[str, Any] = {
            "status": new_status.value,
            "decided_at": utc_timestamp(),
            "decided_by": admin_id,
            "decision_note": (note or None) and note[:500],
        }
        if not approve:
            values["ciphertext"] = None
        async with self.engine.begin() as conn:
            res = await conn.execute(
                update(APPROVALS)
                .where(
                    APPROVALS.c.id == approval_id,
                    APPROVALS.c.status == ApprovalStatus.PENDING.value,
                )
                .values(**values)
            )
        if res.rowcount != 1:
            raise ApprovalError("request is not pending (already decided, expired or unknown)")
        approval = await self.get(approval_id)
        assert approval is not None  # noqa: S101 - updated above
        return approval

    async def release(self, approval_id: str, messages: list[dict[str, str]]) -> bool:
        """Undo a claim whose forwarding failed (provider error, audit outage), so
        the requester can retry before expiry instead of losing the approval."""
        async with self.engine.begin() as conn:
            res = await conn.execute(
                update(APPROVALS)
                .where(
                    APPROVALS.c.id == approval_id,
                    APPROVALS.c.status == ApprovalStatus.EXECUTED.value,
                    APPROVALS.c.expires_at > utc_timestamp(),
                )
                .values(
                    status=ApprovalStatus.APPROVED.value,
                    executed_at=None,
                    ciphertext=self._seal(approval_id, messages),
                )
            )
        return bool(res.rowcount == 1)

    async def claim_for_execution(
        self, approval_id: str, *, requester_id: str
    ) -> tuple[Approval, list[dict[str, str]]]:
        """Single-use: atomically move approved -> executed and return the messages."""
        await self.expire_stale()
        async with self.engine.connect() as raw:
            conn = await raw.execution_options(sqlite_begin="IMMEDIATE")
            async with conn.begin():
                row = (
                    await conn.execute(
                        select(APPROVALS).where(APPROVALS.c.id == approval_id).with_for_update()
                    )
                ).first()
                if row is None or row.requester_id != requester_id:
                    raise ApprovalError("unknown approval request")
                if row.status != ApprovalStatus.APPROVED.value or row.ciphertext is None:
                    raise ApprovalError(f"request is {row.status}, not approved")
                messages = self._open(approval_id, row.ciphertext)
                res = await conn.execute(
                    update(APPROVALS)
                    .where(
                        APPROVALS.c.id == approval_id,
                        APPROVALS.c.status == ApprovalStatus.APPROVED.value,
                    )
                    .values(
                        status=ApprovalStatus.EXECUTED.value,
                        executed_at=utc_timestamp(),
                        ciphertext=None,
                    )
                )
                if res.rowcount != 1:  # pragma: no cover - guarded by the lock
                    raise ApprovalError("request was executed concurrently")
        approval = await self.get(approval_id)
        assert approval is not None  # noqa: S101
        return approval, messages
