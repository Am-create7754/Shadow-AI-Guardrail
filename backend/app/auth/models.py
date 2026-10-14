"""Users and API keys."""

from __future__ import annotations

from enum import StrEnum

from sqlalchemy import Boolean, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class Role(StrEnum):
    DEVELOPER = "developer"  # may inspect and send prompts, sees only their own data
    ADMIN = "admin"  # additionally: approvals, audit log, user management


class UserRow(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(16))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[str] = mapped_column(String(32))
    # Administrator who created this account (None for CLI-bootstrapped users).
    # Used for separation of duties: nobody approves requests of accounts they made.
    created_by: Mapped[str | None] = mapped_column(ForeignKey("users.id"))
    # Session tokens issued before this instant are invalid (logout, deactivation).
    sessions_valid_after: Mapped[str | None] = mapped_column(String(32))


class ApiKeyRow(Base):
    """API keys are stored only as HMAC-SHA256(pepper, key); the key itself is
    shown once at creation. ``prefix`` is a non-secret lookup handle."""

    __tablename__ = "api_keys"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    name: Mapped[str] = mapped_column(String(64))
    prefix: Mapped[str] = mapped_column(String(16), unique=True)
    key_hash: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[str] = mapped_column(String(32))
    last_used_at: Mapped[str | None] = mapped_column(String(32))
    revoked_at: Mapped[str | None] = mapped_column(String(32))
