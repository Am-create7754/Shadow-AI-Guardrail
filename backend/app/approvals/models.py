"""Requests held for administrator approval."""

from __future__ import annotations

from enum import StrEnum

from sqlalchemy import ForeignKey, Integer, LargeBinary, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class ApprovalStatus(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXECUTED = "executed"
    EXPIRED = "expired"


class ApprovalRow(Base):
    """A prompt that policy marked REQUIRE_APPROVAL.

    Only the *redacted* messages are kept - secrets were already replaced by
    placeholders - and even those are encrypted (AES-256-GCM, bound to the row
    id), because they may still contain confidential business content. The
    ciphertext is erased as soon as the request is executed, denied or expires.
    """

    __tablename__ = "approval_requests"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    requester_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    status: Mapped[str] = mapped_column(String(16), index=True)
    created_at: Mapped[str] = mapped_column(String(32))
    expires_at: Mapped[str] = mapped_column(String(32))
    decided_at: Mapped[str | None] = mapped_column(String(32))
    decided_by: Mapped[str | None] = mapped_column(ForeignKey("users.id"))
    decision_note: Mapped[str | None] = mapped_column(String(500))
    executed_at: Mapped[str | None] = mapped_column(String(32))
    request_id: Mapped[str] = mapped_column(String(64))
    model: Mapped[str] = mapped_column(String(128))
    risk_score: Mapped[int] = mapped_column(Integer)
    # Safe summary for reviewers: entity counts, reasons, placeholders (JSON).
    summary: Mapped[str] = mapped_column(Text)
    ciphertext: Mapped[bytes | None] = mapped_column(LargeBinary)
