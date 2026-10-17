"""Audit CLI: demo and operator commands against a temporary database."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.audit.__main__ import main
from app.audit.schemas import AuditEventIn
from app.audit.service import AuditLog
from app.core import config


@pytest.fixture
def cli_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    db = tmp_path / "cli.db"
    monkeypatch.setenv("GUARDRAIL_ENVIRONMENT", "development")
    monkeypatch.setenv("GUARDRAIL_DATABASE_URL", f"sqlite+aiosqlite:///{db.as_posix()}")
    monkeypatch.setenv("GUARDRAIL_KEYS_DIR", str(tmp_path / "keys"))
    # Own anchor: checkpoints written here must not leak into other tests.
    monkeypatch.setenv("GUARDRAIL_AUDIT_ANCHOR_PATH", str(tmp_path / "anchor.json"))
    monkeypatch.setenv("GUARDRAIL_FINGERPRINT_KEY", "f" * 40)
    config.get_settings.cache_clear()
    yield tmp_path
    config.get_settings.cache_clear()


def test_tamper_demo_detects_tampering(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["tamper-demo"]) == 0
    out = capsys.readouterr().out
    assert "tampering DETECTED; first bad event = seq 4" in out
    assert "event 9 is missing" in out


@pytest.mark.filterwarnings("ignore:generating development")
def test_operator_commands_roundtrip(cli_env: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["init-db"]) == 0
    assert main(["verify"]) == 0  # empty chain is valid
    assert main(["checkpoint"]) == 0
    assert "chain is empty" in capsys.readouterr().out

    cps = cli_env / "cps.json"
    pub = cli_env / "pub.pem"
    assert main(["export-checkpoints", str(cps)]) == 0
    assert json.loads(cps.read_text(encoding="utf-8")) == []
    assert main(["export-public-key", str(pub)]) == 0
    assert pub.read_text(encoding="ascii").startswith("-----BEGIN PUBLIC KEY-----")
    assert main(["verify", "--checkpoints", str(cps)]) == 0


@pytest.mark.filterwarnings("ignore:generating development")
def test_verify_without_keys_fails_cleanly(
    cli_env: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    from app.audit.__main__ import _alembic_upgrade

    _alembic_upgrade(config.get_settings().database_url)  # schema only, no keys
    assert main(["verify"]) == 2
    assert "audit key not found" in capsys.readouterr().err
    assert not (cli_env / "keys" / "audit_hmac.key").exists()


@pytest.mark.filterwarnings("ignore:generating development")
def test_backup_is_consistent_verified_and_checksummed(
    cli_env: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    import asyncio
    import hashlib

    from app.audit.__main__ import _with_log

    assert main(["init-db"]) == 0

    async def add(log: AuditLog) -> None:
        for i in range(12):
            await log.append(AuditEventIn(event_type="test.backup", actor="u1", data={"i": i}))
        await log.create_checkpoint()

    asyncio.run(_with_log(config.get_settings(), add))
    capsys.readouterr()
    out = cli_env / "backups" / "audit.db"
    assert main(["backup", "--out", str(out)]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["chain_ok"] is True
    assert report["events"] == 12
    assert report["checkpoints"] == 1
    digest = hashlib.sha256(out.read_bytes()).hexdigest()
    assert report["sha256"] == digest
    assert (cli_env / "backups" / "audit.db.sha256").read_text(
        encoding="ascii"
    ) == f"{digest}  audit.db\n"
    # Never overwrites an existing backup.
    assert main(["backup", "--out", str(out)]) == 2


@pytest.mark.filterwarnings("ignore:generating development")
def test_backup_of_tampered_database_is_reported(
    cli_env: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    import asyncio
    import sqlite3

    from app.audit.__main__ import _with_log

    assert main(["init-db"]) == 0

    async def add(log: AuditLog) -> None:
        for i in range(3):
            await log.append(AuditEventIn(event_type="test.backup", actor="u1", data={"i": i}))

    asyncio.run(_with_log(config.get_settings(), add))
    db = cli_env / "cli.db"
    con = sqlite3.connect(db)
    con.execute("DROP TRIGGER trg_audit_events_no_update")  # an attacker with DB access
    con.execute("UPDATE audit_events SET actor = 'someone-else' WHERE seq = 2")
    con.commit()
    con.close()
    capsys.readouterr()
    assert main(["backup", "--out", str(cli_env / "b.db")]) == 1
    assert json.loads(capsys.readouterr().out)["chain_ok"] is False
