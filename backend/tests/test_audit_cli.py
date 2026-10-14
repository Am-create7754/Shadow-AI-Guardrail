"""Audit CLI: demo and operator commands against a temporary database."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.audit.__main__ import main
from app.core import config


@pytest.fixture
def cli_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    db = tmp_path / "cli.db"
    monkeypatch.setenv("GUARDRAIL_ENVIRONMENT", "development")
    monkeypatch.setenv("GUARDRAIL_DATABASE_URL", f"sqlite+aiosqlite:///{db.as_posix()}")
    monkeypatch.setenv("GUARDRAIL_KEYS_DIR", str(tmp_path / "keys"))
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
