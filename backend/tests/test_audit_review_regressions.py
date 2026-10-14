"""Regression tests for issues found by the independent review of the audit chain."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest
from pydantic import SecretStr, ValidationError

from app.audit.chain import compute_mac, record_payload
from app.audit.keys import AuditKeyring, audit_key_id, load_audit_keyring
from app.audit.service import AuditLog, UnsafeAuditDataError
from app.core.config import Environment, Settings
from tests.audit_helpers import AUDIT_KEY, attacker, audit, db_path, event

__all__ = ["audit"]

OLD_KEY = b"O" * 32


async def fill(log: AuditLog, n: int) -> None:
    for i in range(n):
        await log.append(event(i))


def kinds(report: object) -> set[str]:
    return {i.kind for i in report.issues}  # type: ignore[attr-defined]


# 2. retired keys cannot sign newer events ------------------------------------
async def test_retired_key_cannot_forge_new_tail_event(audit: AuditLog) -> None:
    audit.keyring = AuditKeyring.from_keys(AUDIT_KEY, previous=(OLD_KEY,))
    await fill(audit, 4)
    head = await audit.head()
    assert head is not None
    fields = {
        "seq": 5, "event_id": "e" * 32, "occurred_at": "x", "recorded_at": "x",
        "event_type": "a.b", "actor": "z", "request_id": None, "data": "{}",
        "prev_hash": head[1], "key_id": audit_key_id(OLD_KEY),
    }  # fmt: skip
    mac = compute_mac(OLD_KEY, record_payload(**fields))  # type: ignore[arg-type]
    with attacker(audit) as db:
        db.execute(
            "INSERT INTO audit_events (seq, event_id, occurred_at, recorded_at, event_type, actor,"
            " request_id, data, prev_hash, key_id, hash) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (*fields.values(), mac),
        )
        db.execute("UPDATE audit_chain_head SET seq = 5, hash = ?", (mac,))
    report = await audit.verify()
    assert [(i.seq, i.kind) for i in report.issues] == [(5, "retired_key")]


async def test_rotation_order_allows_old_then_new(audit: AuditLog) -> None:
    audit.keyring = AuditKeyring.from_keys(OLD_KEY)
    await fill(audit, 2)
    audit.keyring = AuditKeyring.from_keys(AUDIT_KEY, previous=(OLD_KEY,))
    await fill(audit, 2)
    assert (await audit.verify()).ok


# 3. malformed rows are reported, never raised ---------------------------------
@pytest.mark.parametrize("column", ["hash", "data", "prev_hash", "actor"])
async def test_blob_columns_reported_not_raised(audit: AuditLog, column: str) -> None:
    await fill(audit, 4)
    with attacker(audit) as db:
        db.execute(f"UPDATE audit_events SET {column} = CAST({column} AS BLOB) WHERE seq = 3")
    report = await audit.verify()
    assert (3, "malformed") in {(i.seq, i.kind) for i in report.issues}


async def test_deeply_nested_data_reported_not_raised(audit: AuditLog) -> None:
    await fill(audit, 2)
    with attacker(audit) as db:
        db.execute("UPDATE audit_events SET data = ? WHERE seq = 1", ("[" * 200_000,))
    report = await audit.verify()
    assert {"mac", "oversized"} <= kinds(report) or {"mac", "non_canonical"} <= kinds(report)


async def test_oversized_planted_row_not_parsed(audit: AuditLog) -> None:
    await fill(audit, 1)
    with attacker(audit) as db:
        db.execute("UPDATE audit_events SET data = ? WHERE seq = 1", ('"' + "x" * 300_000 + '"',))
    assert "oversized" in kinds(await audit.verify())


# 4. junk checkpoint rows (allowed by INSERT triggers) do not break verify ----
async def test_junk_checkpoint_row_reported(audit: AuditLog) -> None:
    await fill(audit, 6)
    raw = sqlite3.connect(db_path(audit), isolation_level=None)
    try:  # plain INSERT, triggers intact
        raw.execute(
            "INSERT INTO audit_checkpoints (seq, chain_hash, genesis_hash, created_at, "
            "signer_key_id, signature) VALUES (1, 'x', 'x', 'x', 'x', 'x')"
        )
    finally:
        raw.close()
    report = await audit.verify()
    assert "checkpoint_malformed" in kinds(report)
    assert [c.seq for c in await audit.checkpoints()] == [5]  # export still works


# 5. INSERT OR REPLACE cannot overwrite rows while triggers are installed ------
@pytest.mark.parametrize(
    "sql",
    [
        "INSERT OR REPLACE INTO audit_events SELECT 3, 'r', occurred_at, recorded_at, event_type,"
        " 'evil', request_id, data, prev_hash, hash, key_id FROM audit_events WHERE seq = 3",
        "REPLACE INTO audit_checkpoints SELECT id, seq, chain_hash, genesis_hash, created_at,"
        " signer_key_id, signature FROM audit_checkpoints LIMIT 1",
    ],
)
async def test_insert_or_replace_blocked_by_triggers(audit: AuditLog, sql: str) -> None:
    await fill(audit, 5)
    raw = sqlite3.connect(db_path(audit), isolation_level=None)  # no special pragmas
    try:
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            raw.execute(sql)
    finally:
        raw.close()
    assert (await audit.verify()).ok


# 6. secret scan sees decoded values -----------------------------------------
@pytest.mark.parametrize(
    "data",
    [
        {"x": 'password="Hunter2!Xyz9#Qw"'},  # escaped quotes in canonical JSON
        {"password": "Hunter2!Xyz9#Qw"},  # secret carried by the key name
        {"parts": ["4111", "1111", "1111", "1111"]},  # card split across a list
        {"nested": [{"db_password": "s3cretValue99"}]},
    ],
)
async def test_secret_scan_bypasses_closed(audit: AuditLog, data: dict[str, object]) -> None:
    with pytest.raises(UnsafeAuditDataError):
        await audit.append(event(data=data))  # type: ignore[arg-type]


# 7. weak keys rejected ---------------------------------------------------------
def test_short_previous_keys_rejected() -> None:
    with pytest.raises(ValidationError, match="PREVIOUS_KEYS"):
        Settings(environment=Environment.TEST, audit_previous_keys=SecretStr("x,y"))


def test_short_key_material_rejected() -> None:
    with pytest.raises(ValueError, match="at least 32"):
        AuditKeyring.from_keys(b"short")


def test_short_dev_key_file_rejected(tmp_path: Path) -> None:
    (tmp_path / "audit_hmac.key").write_bytes(b"")
    s = Settings(environment=Environment.DEVELOPMENT, fingerprint_key=SecretStr("f" * 40),
                 keys_dir=tmp_path)  # fmt: skip
    with pytest.raises(ValueError, match="shorter than 32"):
        load_audit_keyring(s)


# plausible: verification without the private signing key ---------------------
async def test_verify_with_public_key_only(audit: AuditLog) -> None:
    await fill(audit, 6)
    assert audit.signer is not None
    pem = audit.signer.public_pem()
    settings = Settings(environment=Environment.TEST, audit_key=SecretStr(AUDIT_KEY.decode()),
                        audit_anchor_path=audit.anchor_path)  # fmt: skip
    verifier_only = AuditLog.for_verification(settings, audit.engine, (pem,))
    assert verifier_only.signer is None
    assert (await verifier_only.verify()).ok

    other = AuditLog.for_verification(settings, audit.engine, ())
    assert "checkpoint_signature" in kinds(await other.verify())


# plausible: issue cap must not hide rollback findings --------------------------
async def test_issue_cap_never_drops_head_and_checkpoint_findings(audit: AuditLog) -> None:
    await fill(audit, 130)
    with attacker(audit) as db:
        db.execute("UPDATE audit_events SET actor = 'x' WHERE seq <= 120")  # 120 mac issues
        db.execute("DELETE FROM audit_events WHERE seq > 125")
    report = await audit.verify()
    assert report.issues_truncated
    assert {"head_mismatch", "checkpoint_beyond_chain"} <= kinds(report)


def test_verification_never_generates_a_new_audit_key(tmp_path: Path) -> None:
    s = Settings(environment=Environment.DEVELOPMENT, fingerprint_key=SecretStr("f" * 40),
                 keys_dir=tmp_path)  # fmt: skip
    with pytest.raises(FileNotFoundError, match="audit key not found"):
        load_audit_keyring(s, create=False)
    assert not (tmp_path / "audit_hmac.key").exists()
