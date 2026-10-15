"""Audit tables.

Integrity is layered:

1. HMAC chain over every event (``app.audit.chain``) - detects any change.
2. ``UNIQUE(prev_hash)`` - two writers can never both extend the same event,
   so the chain cannot silently fork; ``seq`` is the primary key.
3. Append-only triggers (SQLite; PostgreSQL variant provided) - stop UPDATE,
   DELETE and INSERT OR REPLACE through ordinary SQL. They are a guard against
   mistakes, not attackers: anyone with direct database access can drop them;
   layers 1 and 4 are what detect that.
4. Ed25519-signed checkpoints of the chain head, stored in the database, written
   to an anchor file outside it, and exportable off-host.
"""

from __future__ import annotations

from typing import cast

from sqlalchemy import DDL, CheckConstraint, Integer, String, Table, Text, event
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class AuditEventRow(Base):
    __tablename__ = "audit_events"
    __table_args__ = (CheckConstraint("seq >= 1", name="seq_positive"),)

    seq: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=False)
    event_id: Mapped[str] = mapped_column(String(32), unique=True)
    occurred_at: Mapped[str] = mapped_column(String(32), index=True)
    recorded_at: Mapped[str] = mapped_column(String(32), index=True)  # dashboard windows
    event_type: Mapped[str] = mapped_column(String(64), index=True)
    actor: Mapped[str] = mapped_column(String(128), index=True)
    request_id: Mapped[str | None] = mapped_column(String(64), index=True)
    data: Mapped[str] = mapped_column(Text)  # canonical JSON, exactly as MAC'd
    prev_hash: Mapped[str] = mapped_column(String(64), unique=True)
    hash: Mapped[str] = mapped_column(String(64), unique=True)
    key_id: Mapped[str] = mapped_column(String(16))


class AuditChainHead(Base):
    """Single row (id=1) holding the latest sequence number and hash.

    Appends lock this row (``FOR UPDATE`` on PostgreSQL, ``BEGIN IMMEDIATE`` on
    SQLite); it also lets the verifier detect deletion of the newest events.
    """

    __tablename__ = "audit_chain_head"
    __table_args__ = (CheckConstraint("id = 1", name="single_row"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=False)
    seq: Mapped[int] = mapped_column(Integer)
    hash: Mapped[str] = mapped_column(String(64))
    updated_at: Mapped[str] = mapped_column(String(32))


class AuditCheckpointRow(Base):
    __tablename__ = "audit_checkpoints"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    seq: Mapped[int] = mapped_column(Integer, index=True)
    chain_hash: Mapped[str] = mapped_column(String(64))
    # Hash of event 1: binds the signed checkpoint to this specific chain.
    genesis_hash: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[str] = mapped_column(String(32))
    signer_key_id: Mapped[str] = mapped_column(String(16))
    signature: Mapped[str] = mapped_column(String(128))


APPEND_ONLY_TABLES = ("audit_events", "audit_checkpoints")

# Columns whose existing values an INSERT may never collide with. Checked by a
# BEFORE INSERT trigger because SQLite's INSERT OR REPLACE deletes the old row
# without firing DELETE triggers (unless recursive_triggers is on).
_UNIQUE_COLUMNS = {
    "audit_events": ("seq", "event_id", "prev_hash", "hash"),
    "audit_checkpoints": ("id",),
}


def sqlite_append_only_ddl(table: str) -> list[str]:
    clash = " OR ".join(f"{c} = NEW.{c}" for c in _UNIQUE_COLUMNS[table])
    return [
        f"CREATE TRIGGER IF NOT EXISTS trg_{table}_no_update BEFORE UPDATE ON {table} "
        f"BEGIN SELECT RAISE(ABORT, '{table} is append-only'); END",
        f"CREATE TRIGGER IF NOT EXISTS trg_{table}_no_delete BEFORE DELETE ON {table} "
        f"BEGIN SELECT RAISE(ABORT, '{table} is append-only'); END",
        # Table and column names come from the constants above, never from input.
        f"CREATE TRIGGER IF NOT EXISTS trg_{table}_no_replace BEFORE INSERT ON {table} "  # noqa: S608
        f"WHEN EXISTS (SELECT 1 FROM {table} WHERE {clash}) "
        f"BEGIN SELECT RAISE(ABORT, '{table} is append-only'); END",
    ]


def postgres_append_only_ddl(table: str) -> list[str]:
    # Provided for the PostgreSQL path; NOT exercised by the local test suite.
    # PostgreSQL has no INSERT OR REPLACE; ON CONFLICT DO UPDATE fires the UPDATE trigger.
    return [
        "CREATE OR REPLACE FUNCTION guardrail_append_only() RETURNS trigger AS $$ "
        "BEGIN RAISE EXCEPTION '% is append-only', TG_TABLE_NAME; END; $$ LANGUAGE plpgsql",
        f"CREATE TRIGGER trg_{table}_append_only BEFORE UPDATE OR DELETE ON {table} "
        "FOR EACH ROW EXECUTE FUNCTION guardrail_append_only()",
        f"CREATE TRIGGER trg_{table}_no_truncate BEFORE TRUNCATE ON {table} "
        "FOR EACH STATEMENT EXECUTE FUNCTION guardrail_append_only()",
    ]


# Install triggers whenever tables are created via metadata.create_all (tests, dev).
# Alembic migrations create the same triggers explicitly.
for _table in (cast(Table, AuditEventRow.__table__), cast(Table, AuditCheckpointRow.__table__)):
    for _stmt in sqlite_append_only_ddl(_table.name):
        _ddl = DDL(_stmt)  # type: ignore[no-untyped-call]
        event.listen(_table, "after_create", _ddl.execute_if(dialect="sqlite"))
    for _stmt in postgres_append_only_ddl(_table.name):
        _ddl = DDL(_stmt)  # type: ignore[no-untyped-call]
        event.listen(_table, "after_create", _ddl.execute_if(dialect="postgresql"))
