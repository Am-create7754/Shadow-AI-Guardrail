"""Validated input and output shapes for audit events."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, JsonValue, field_validator

from app.audit.chain import canonical_json

MAX_DATA_BYTES = 16_384
MAX_DEPTH = 6


def _depth(value: Any, level: int = 0) -> int:
    if isinstance(value, dict):
        return max((_depth(v, level + 1) for v in value.values()), default=level + 1)
    if isinstance(value, list):
        return max((_depth(v, level + 1) for v in value), default=level + 1)
    return level


class AuditEventIn(BaseModel):
    """What callers submit. Must contain safe metadata only - never raw prompts,
    secrets or redaction mappings (enforced by a scan in ``AuditLog.append``)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    event_type: str = Field(pattern=r"^[a-z][a-z0-9_]{1,30}(\.[a-z][a-z0-9_]{1,30}){1,3}$")
    actor: str = Field(min_length=1, max_length=128, pattern=r"^[\w.@:\-]+$")
    request_id: str | None = Field(default=None, max_length=64, pattern=r"^[\w\-]+$")
    occurred_at: datetime | None = None
    data: dict[str, JsonValue] = Field(default_factory=dict)

    @field_validator("data")
    @classmethod
    def _bounded(cls, v: dict[str, JsonValue]) -> dict[str, JsonValue]:
        try:
            encoded = canonical_json(v).encode("utf-8")
        except ValueError as exc:  # NaN / Infinity
            raise ValueError(f"data is not canonical JSON: {exc}") from exc
        if len(encoded) > MAX_DATA_BYTES:
            raise ValueError(f"data exceeds {MAX_DATA_BYTES} bytes")
        if _depth(v) > MAX_DEPTH:
            raise ValueError(f"data nested deeper than {MAX_DEPTH} levels")
        return v

    @field_validator("occurred_at")
    @classmethod
    def _aware(cls, v: datetime | None) -> datetime | None:
        if v is not None and v.tzinfo is None:
            raise ValueError("occurred_at must be timezone-aware")
        return v


class AuditRecord(BaseModel):
    model_config = ConfigDict(frozen=True)

    seq: int
    event_id: str
    occurred_at: str
    recorded_at: str
    event_type: str
    actor: str
    request_id: str | None
    data: dict[str, Any]
    prev_hash: str
    hash: str
    key_id: str


class Checkpoint(BaseModel):
    """Signed snapshot of the chain head; safe to export and store elsewhere."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    seq: int = Field(ge=1)
    chain_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    genesis_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    created_at: str = Field(max_length=32)
    signer_key_id: str = Field(pattern=r"^[0-9a-f]{16}$")
    signature: str = Field(pattern=r"^[0-9a-f]{128}$")
