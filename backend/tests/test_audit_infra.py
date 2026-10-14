"""Keys, settings, schemas, migrations and transaction mode for the audit log."""

from __future__ import annotations

import asyncio
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any

import pytest
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.migration import MigrationContext
from pydantic import SecretStr, ValidationError
from sqlalchemy import event

import app.audit.models  # noqa: F401 - register tables
from app.audit.keys import (
    AuditKeyring,
    CheckpointVerifier,
    load_audit_keyring,
    load_checkpoint_signer,
)
from app.audit.schemas import AuditEventIn
from app.audit.service import AuditLog
from app.core.config import Environment, Settings
from app.db.base import Base
from app.db.engine import create_engine
from tests.audit_helpers import audit
from tests.audit_helpers import event as make_event

__all__ = ["audit"]

BACKEND = Path(__file__).resolve().parents[1]
FP_KEY = SecretStr("f" * 40)


# ------------------------------------------------------------------ settings
def test_production_requires_audit_and_checkpoint_keys(tmp_path: Path) -> None:
    with pytest.raises(ValidationError, match="AUDIT_KEY"):
        Settings(environment=Environment.PRODUCTION, fingerprint_key=FP_KEY)
    with pytest.raises(ValidationError, match="CHECKPOINT_KEY_PATH"):
        Settings(
            environment=Environment.PRODUCTION,
            fingerprint_key=FP_KEY,
            audit_key=SecretStr("a" * 40),
        )
    ok = Settings(
        environment=Environment.PRODUCTION,
        fingerprint_key=FP_KEY,
        audit_key=SecretStr("a" * 40),
        checkpoint_key_path=tmp_path / "k.pem",
    )
    assert ok.audit_key is not None


def test_audit_key_must_differ_from_fingerprint_key() -> None:
    with pytest.raises(ValidationError, match="must differ"):
        Settings(environment=Environment.TEST, fingerprint_key=FP_KEY, audit_key=FP_KEY)


def test_short_audit_key_rejected() -> None:
    with pytest.raises(ValidationError, match="at least 32"):
        Settings(environment=Environment.TEST, audit_key=SecretStr("short"))


def test_default_data_dir_is_outside_the_repository() -> None:
    from app.core.config import default_data_dir

    repo = BACKEND.parent.resolve()
    assert not default_data_dir().resolve().is_relative_to(repo)
    fields = Settings.model_fields
    for name in ("keys_dir", "audit_anchor_path"):
        default = fields[name].default
        assert not Path(default).resolve().is_relative_to(repo), name
    assert str(repo).replace("\\", "/") not in str(fields["database_url"].default)


# ---------------------------------------------------------------------- keys
def test_development_keys_are_generated_once_and_persisted(tmp_path: Path) -> None:
    s = Settings(environment=Environment.DEVELOPMENT, fingerprint_key=FP_KEY, keys_dir=tmp_path)
    with pytest.warns(UserWarning, match="generating development audit key"):
        first = load_audit_keyring(s)
    second = load_audit_keyring(s)  # no warning: reused
    assert first.current_id == second.current_id
    with pytest.warns(UserWarning, match="checkpoint signing key"):
        signer1 = load_checkpoint_signer(s)
    assert load_checkpoint_signer(s).key_id == signer1.key_id
    assert (tmp_path / "audit_hmac.key").exists()


def test_previous_keys_parsed_from_settings() -> None:
    s = Settings(
        environment=Environment.TEST,
        audit_key=SecretStr("n" * 32),
        audit_previous_keys=SecretStr("o" * 32 + ", " + "p" * 32),
    )
    ring = load_audit_keyring(s)
    assert len(ring.keys) == 3


def test_keyring_and_signer_repr_hide_secrets() -> None:
    ring = AuditKeyring.from_keys(b"K" * 32)
    assert "KKKK" not in repr(ring)
    signer = load_checkpoint_signer(Settings(environment=Environment.TEST))
    assert "PRIVATE" not in repr(signer)


def test_public_key_export_roundtrip() -> None:
    signer = load_checkpoint_signer(Settings(environment=Environment.TEST))
    verifier = CheckpointVerifier.from_pem(signer.public_pem())
    msg = b"hello"
    assert verifier.verify(signer.key_id, signer.sign(msg), msg)
    assert not verifier.verify(signer.key_id, signer.sign(msg), b"hellO")
    assert not verifier.verify(signer.key_id, "zz", msg)  # malformed hex


# ------------------------------------------------------------------- schemas
@pytest.mark.parametrize(
    "kwargs",
    [
        {"event_type": "Prompt"},
        {"event_type": "prompt"},
        {"event_type": "prompt.inspected; drop table"},
        {"actor": ""},
        {"actor": "a b"},
        {"request_id": "x" * 65},
        {"data": {"x": "y" * 20_000}},
        {"data": {"a": {"b": {"c": {"d": {"e": {"f": {"g": 1}}}}}}}},
        {"data": {"x": float("nan")}},
        {"occurred_at": datetime(2026, 1, 1)},  # naive
        {"unexpected": 1},
    ],
)
def test_invalid_events_rejected(kwargs: dict[str, Any]) -> None:
    base: dict[str, Any] = {"event_type": "prompt.inspected", "actor": "user-1"}
    with pytest.raises(ValidationError):
        AuditEventIn(**(base | kwargs))


# ------------------------------------------------------------ transactions
async def test_appends_use_begin_immediate(audit: AuditLog) -> None:
    seen: list[str] = []

    def capture(conn: Any, cursor: Any, statement: str, *args: Any) -> None:
        seen.append(statement)

    event.listen(audit.engine.sync_engine, "before_cursor_execute", capture)
    try:
        await audit.append(make_event(1))
        await audit.verify()
    finally:
        event.remove(audit.engine.sync_engine, "before_cursor_execute", capture)
    begins = [s for s in seen if s.startswith("BEGIN")]
    assert begins[0] == "BEGIN IMMEDIATE"  # the append
    assert "BEGIN DEFERRED" in begins  # reads do not take the write lock


def test_sqlite_pragmas_applied(tmp_path: Path) -> None:
    async def run() -> tuple[str, int]:
        engine = create_engine(f"sqlite+aiosqlite:///{(tmp_path / 'p.db').as_posix()}")
        async with engine.connect() as conn:
            mode = (await conn.exec_driver_sql("PRAGMA journal_mode")).scalar_one()
            busy = (await conn.exec_driver_sql("PRAGMA busy_timeout")).scalar_one()
        await engine.dispose()
        return mode, busy

    mode, busy = asyncio.run(run())
    assert mode == "wal"
    assert busy >= 10_000


# ---------------------------------------------------------------- migrations
def _alembic(url: str) -> Config:
    cfg = Config(str(BACKEND / "alembic.ini"))
    cfg.set_main_option("sqlalchemy.url", url)
    return cfg


def test_migration_matches_models_and_installs_triggers(tmp_path: Path) -> None:
    db = tmp_path / "migrated.db"
    url = f"sqlite+aiosqlite:///{db.as_posix()}"
    command.upgrade(_alembic(url), "head")

    raw = sqlite3.connect(db)
    try:
        triggers = {
            r[0] for r in raw.execute("SELECT name FROM sqlite_master WHERE type='trigger'")
        }
    finally:
        raw.close()
    assert triggers == {
        "trg_audit_events_no_update",
        "trg_audit_events_no_delete",
        "trg_audit_checkpoints_no_update",
        "trg_audit_events_no_replace",
        "trg_audit_checkpoints_no_replace",
        "trg_audit_checkpoints_no_delete",
    }

    async def diff() -> list[Any]:
        engine = create_engine(url)
        async with engine.connect() as conn:
            result = await conn.run_sync(
                lambda c: compare_metadata(MigrationContext.configure(c), Base.metadata)
            )
        await engine.dispose()
        return list(result)

    assert asyncio.run(diff()) == []
    command.downgrade(_alembic(url), "base")


async def test_migrated_database_works_end_to_end(tmp_path: Path) -> None:
    url = f"sqlite+aiosqlite:///{(tmp_path / 'e2e.db').as_posix()}"
    await asyncio.to_thread(command.upgrade, _alembic(url), "head")
    engine = create_engine(url)
    log = AuditLog.from_settings(Settings(environment=Environment.TEST), engine)
    try:
        for i in range(3):
            await log.append(make_event(i))
        assert (await log.verify()).ok
    finally:
        await engine.dispose()


def test_empty_env_values_mean_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    """Copying .env.example verbatim must not produce empty (rejected) keys."""
    monkeypatch.setenv("GUARDRAIL_ENVIRONMENT", "test")
    monkeypatch.setenv("GUARDRAIL_AUDIT_KEY", "")
    monkeypatch.setenv("GUARDRAIL_FINGERPRINT_KEY", "")
    s = Settings()
    assert s.audit_key is None
    assert s.fingerprint_key is not None  # ephemeral test key
