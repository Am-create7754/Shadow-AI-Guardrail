"""index audit_events.recorded_at (dashboard metrics windows)

Revision ID: 0003
Revises: 0002
Create Date: 2026-10-15 23:59:00
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # An index only: the append-only triggers forbid UPDATE/DELETE, not new indexes.
    op.create_index(
        op.f("ix_audit_events_recorded_at"), "audit_events", ["recorded_at"], unique=False
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_audit_events_recorded_at"), table_name="audit_events")
