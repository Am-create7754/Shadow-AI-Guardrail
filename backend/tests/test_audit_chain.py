"""Audit chain: appending, verification and tamper detection."""

from __future__ import annotations

import itertools
import json
import random

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError, IntegrityError

from app.audit.chain import (
    GENESIS_HASH,
    canonical_json,
    checkpoint_message,
    compute_mac,
    record_payload,
)
from app.audit.keys import AuditKeyring, CheckpointSigner
from app.audit.schemas import Checkpoint
from app.audit.service import AuditLog, UnsafeAuditDataError
from evaluation import synth
from tests.audit_helpers import AUDIT_KEY, attacker, audit, event

__all__ = ["audit"]  # fixture re-export for pytest

FIELDS = (
    "seq",
    "event_id",
    "occurred_at",
    "recorded_at",
    "event_type",
    "actor",
    "request_id",
    "data",
    "prev_hash",
    "key_id",
)


async def fill(log: AuditLog, n: int) -> None:
    for i in range(n):
        await log.append(event(i))


def kinds(report: object) -> set[str]:
    return {i.kind for i in report.issues}  # type: ignore[attr-defined]


# ------------------------------------------------------------------- basics
def test_canonical_json_is_order_independent_and_compact() -> None:
    assert canonical_json({"b": 1, "a": [1, {"d": 2, "c": 3}]}) == '{"a":[1,{"c":3,"d":2}],"b":1}'
    assert canonical_json({"x": "\u00e9"}) == '{"x":"\u00e9"}'
    with pytest.raises(ValueError, match="JSON compliant"):
        canonical_json({"x": float("nan")})


@pytest.mark.parametrize("field", FIELDS)
def test_mac_covers_every_field(field: str) -> None:
    base = {
        "seq": 3,
        "event_id": "e" * 32,
        "occurred_at": "2026-01-01T00:00:00.000000Z",
        "recorded_at": "2026-01-01T00:00:01.000000Z",
        "event_type": "prompt.inspected",
        "actor": "user-1",
        "request_id": "req-1",
        "data": '{"a":1}',
        "prev_hash": "0" * 64,
        "key_id": "k" * 16,
    }
    original = compute_mac(AUDIT_KEY, record_payload(**base))  # type: ignore[arg-type]
    changed = dict(base)
    changed[field] = 4 if field == "seq" else str(base[field]) + "x"
    assert compute_mac(AUDIT_KEY, record_payload(**changed)) != original  # type: ignore[arg-type]


async def test_append_builds_contiguous_linked_chain(audit: AuditLog) -> None:
    records = [await audit.append(event(i)) for i in range(12)]
    assert [r.seq for r in records] == list(range(1, 13))
    assert records[0].prev_hash == GENESIS_HASH
    for a, b in itertools.pairwise(records):
        assert b.prev_hash == a.hash
    assert await audit.head() == (12, records[-1].hash)
    report = await audit.verify()
    assert report.ok, report.issues
    assert report.events_checked == 12
    assert report.checkpoints_checked == 3  # stored at seq 5 and 10, plus the anchor (10)
    assert report.anchor_checked


async def test_empty_chain_verifies(audit: AuditLog) -> None:
    report = await audit.verify()
    assert report.ok
    assert report.events_checked == 0
    assert await audit.create_checkpoint() is None


async def test_list_events_newest_first_with_filters(audit: AuditLog) -> None:
    await fill(audit, 6)
    await audit.append(event(99, event_type="policy.updated", actor="admin-1"))
    page = await audit.list_events(limit=3)
    assert [r.seq for r in page] == [7, 6, 5]
    older = await audit.list_events(limit=3, before_seq=5)
    assert [r.seq for r in older] == [4, 3, 2]
    only = await audit.list_events(event_type="policy.updated")
    assert [(r.seq, r.actor) for r in only] == [(7, "admin-1")]
    assert page[0].data["risk_score"] == 139


# ----------------------------------------------------------- tamper detection
async def test_modified_event_is_pinpointed(audit: AuditLog) -> None:
    await fill(audit, 8)
    with attacker(audit) as db:
        db.execute(
            "UPDATE audit_events SET data = ? WHERE seq = 4",
            (canonical_json({"action": "ALLOW", "risk_score": 0}),),
        )
    report = await audit.verify()
    assert not report.ok
    assert report.first_bad_seq == 4
    assert [(i.seq, i.kind) for i in report.issues] == [(4, "mac")]


async def test_modified_actor_detected(audit: AuditLog) -> None:
    await fill(audit, 3)
    with attacker(audit) as db:
        db.execute("UPDATE audit_events SET actor = 'someone-else' WHERE seq = 2")
    assert [(i.seq, i.kind) for i in (await audit.verify()).issues] == [(2, "mac")]


async def test_rehash_without_key_detected(audit: AuditLog) -> None:
    """Attacker edits an event and recomputes its hash with a guessed key."""
    await fill(audit, 6)
    with attacker(audit) as db:
        row = db.execute(f"SELECT {', '.join(FIELDS)} FROM audit_events WHERE seq = 3").fetchone()
        fields = dict(zip(FIELDS, row, strict=True))
        fields["data"] = canonical_json({"action": "ALLOW"})
        forged = compute_mac(b"wrong-key" * 4, record_payload(**fields))
        db.execute(
            "UPDATE audit_events SET data = ?, hash = ? WHERE seq = 3", (fields["data"], forged)
        )
    found = {(i.seq, i.kind) for i in (await audit.verify()).issues}
    assert (3, "mac") in found
    assert (4, "link") in found  # next event still points at the old hash


async def test_deleted_middle_event_detected(audit: AuditLog) -> None:
    await fill(audit, 7)
    with attacker(audit) as db:
        db.execute("DELETE FROM audit_events WHERE seq = 4")
    found = {(i.seq, i.kind) for i in (await audit.verify()).issues}
    assert found == {(5, "gap"), (5, "link")}


async def test_truncated_tail_detected_by_head(audit: AuditLog) -> None:
    await fill(audit, 7)
    with attacker(audit) as db:
        db.execute("DELETE FROM audit_events WHERE seq > 5")
    report = await audit.verify()
    assert "head_mismatch" in kinds(report)
    assert report.last_seq == 5


async def _rollback_to_7(audit: AuditLog) -> None:
    """Keyless rollback: drop newest events, rewind the head, drop newer checkpoints.
    Every remaining row is genuine, so nothing inside the database is inconsistent."""
    with attacker(audit) as db:
        db.execute("DELETE FROM audit_events WHERE seq > 7")
        h = db.execute("SELECT hash FROM audit_events WHERE seq = 7").fetchone()[0]
        db.execute("UPDATE audit_chain_head SET seq = 7, hash = ? WHERE id = 1", (h,))
        db.execute("DELETE FROM audit_checkpoints WHERE seq > 7")


async def test_rollback_detected_by_anchor_file(audit: AuditLog) -> None:
    await fill(audit, 12)  # checkpoints at 5 and 10; anchor holds seq 10
    await _rollback_to_7(audit)
    report = await audit.verify()
    assert report.anchor_checked
    assert [(i.seq, i.kind) for i in report.issues] == [(10, "checkpoint_beyond_chain")]


async def test_rollback_undetectable_without_external_anchor(audit: AuditLog) -> None:
    """Honest limitation, kept as a test: with no anchor and no export, a keyless
    rollback leaves a database that is internally consistent."""
    await fill(audit, 12)
    await _rollback_to_7(audit)
    audit.anchor_path = None
    assert (await audit.verify()).ok


async def test_full_wipe_detected_by_anchor(audit: AuditLog) -> None:
    await fill(audit, 6)
    with attacker(audit) as db:
        for table in ("audit_events", "audit_chain_head", "audit_checkpoints"):
            db.execute(f"DELETE FROM {table}")
    report = await audit.verify()
    assert [(i.seq, i.kind) for i in report.issues] == [(5, "checkpoint_beyond_chain")]


async def test_anchor_is_monotonic_and_validated(audit: AuditLog) -> None:
    await fill(audit, 10)
    anchor = audit.read_anchor()
    assert anchor is not None
    assert anchor.seq == 10
    stored = await audit.checkpoints()
    audit._write_anchor(stored[0])  # older checkpoint must not replace newer anchor
    anchor = audit.read_anchor()
    assert anchor is not None
    assert anchor.seq == 10
    assert audit.anchor_path is not None
    audit.anchor_path.write_text("{not json", encoding="utf-8")
    assert "anchor_malformed" in kinds(await audit.verify())


async def test_missing_anchor_reported_when_checkpoints_exist(audit: AuditLog) -> None:
    await fill(audit, 5)
    assert audit.anchor_path is not None
    audit.anchor_path.unlink()
    assert [i.kind for i in (await audit.verify()).issues] == ["anchor_missing"]


async def test_reordered_events_detected(audit: AuditLog) -> None:
    await fill(audit, 6)
    with attacker(audit) as db:
        cols = ", ".join(c for c in FIELDS if c != "seq") + ", hash"
        a = db.execute(f"SELECT {cols} FROM audit_events WHERE seq = 2").fetchone()
        b = db.execute(f"SELECT {cols} FROM audit_events WHERE seq = 3").fetchone()
        setter = ", ".join(f"{c} = ?" for c in cols.split(", "))
        db.execute(
            "UPDATE audit_events SET event_id = 'tmp', hash = 'tmp', prev_hash = 'tmp' "
            "WHERE seq = 2"
        )
        db.execute(f"UPDATE audit_events SET {setter} WHERE seq = 3", a)
        db.execute(f"UPDATE audit_events SET {setter} WHERE seq = 2", b)
    report = await audit.verify()
    assert report.first_bad_seq == 2
    assert {"mac", "link"} <= kinds(report)


async def test_forged_appended_event_with_unknown_key(audit: AuditLog) -> None:
    await fill(audit, 3)
    head = await audit.head()
    assert head is not None
    fields = {
        "seq": 4,
        "event_id": "f" * 32,
        "occurred_at": "2026-01-01T00:00:00.000000Z",
        "recorded_at": "2026-01-01T00:00:00.000000Z",
        "event_type": "prompt.inspected",
        "actor": "intruder",
        "request_id": None,
        "data": "{}",
        "prev_hash": head[1],
        "key_id": "0123456789abcdef",
    }
    fields_mac = compute_mac(b"x" * 32, record_payload(**fields))  # type: ignore[arg-type]
    with attacker(audit) as db:
        db.execute(
            f"INSERT INTO audit_events ({', '.join(FIELDS)}, hash) VALUES ({', '.join('?' * 11)})",
            (*fields.values(), fields_mac),
        )
        db.execute("UPDATE audit_chain_head SET seq = 4, hash = ?", (fields_mac,))
    report = await audit.verify()
    assert [(i.seq, i.kind) for i in report.issues] == [(4, "unknown_key")]


async def test_full_rewrite_with_stolen_hmac_key(audit: AuditLog) -> None:
    """An attacker with the audit key and DB access rebuilds history consistently,
    deletes the stored checkpoints - and even the anchor file. The chain then
    verifies on its own (honest limitation); a checkpoint exported beforehand,
    verified with the Ed25519 public key, exposes the rewrite."""
    await fill(audit, 10)
    exported = await audit.checkpoints()  # e.g. copied to another system
    assert [c.seq for c in exported] == [5, 10]

    with attacker(audit) as db:
        rows = db.execute(f"SELECT {', '.join(FIELDS)} FROM audit_events ORDER BY seq").fetchall()
        prev = GENESIS_HASH
        for row in rows:
            f = dict(zip(FIELDS, row, strict=True))
            if f["seq"] == 3:
                f["data"] = canonical_json({"action": "ALLOW", "risk_score": 0})
            f["prev_hash"] = prev
            mac = compute_mac(AUDIT_KEY, record_payload(**f))  # stolen key
            db.execute(
                "UPDATE audit_events SET data = ?, prev_hash = 'p' || seq, hash = 'h' || seq "
                "WHERE seq = ?",
                (f["data"], f["seq"]),
            )
            db.execute(
                "UPDATE audit_events SET prev_hash = ?, hash = ? WHERE seq = ?",
                (f["prev_hash"], mac, f["seq"]),
            )
            prev = mac
        db.execute("UPDATE audit_chain_head SET hash = ? WHERE id = 1", (prev,))
        db.execute("DELETE FROM audit_checkpoints")

    with_anchor = await audit.verify()
    assert ("checkpoint_foreign" in kinds(with_anchor)) or (
        "checkpoint_mismatch" in kinds(with_anchor)
    )

    assert audit.anchor_path is not None
    audit.anchor_path.unlink()  # attacker also reached the anchor file
    assert (await audit.verify()).ok  # undetectable from the host alone

    with_export = await audit.verify(external_checkpoints=exported)
    assert {(i.seq, i.kind) for i in with_export.issues} >= {(10, "checkpoint_foreign")} or {
        (i.seq, i.kind) for i in with_export.issues
    } >= {(10, "checkpoint_mismatch")}


def _rogue_checkpoint(
    seq: int, chain_hash: str, genesis: str
) -> tuple[Checkpoint, CheckpointSigner]:
    rogue = CheckpointSigner(Ed25519PrivateKey.generate())
    created = "2026-01-01T00:00:00.000000Z"
    msg = checkpoint_message(
        seq=seq,
        chain_hash=chain_hash,
        genesis_hash=genesis,
        created_at=created,
        signer_key_id=rogue.key_id,
    )
    cp = Checkpoint(
        seq=seq,
        chain_hash=chain_hash,
        genesis_hash=genesis,
        created_at=created,
        signer_key_id=rogue.key_id,
        signature=rogue.sign(msg),
    )
    return cp, rogue


async def test_checkpoint_signed_by_untrusted_key_rejected(audit: AuditLog) -> None:
    await fill(audit, 3)
    head = await audit.head()
    assert head is not None
    forged, _ = _rogue_checkpoint(head[0], head[1], head[1])
    report = await audit.verify(external_checkpoints=[forged])
    assert [(i.seq, i.kind) for i in report.issues] == [(3, "checkpoint_signature")]


async def test_checkpoint_from_another_chain_rejected(audit: AuditLog) -> None:
    await fill(audit, 5)
    (real,) = await audit.checkpoints()
    head = await audit.head()
    assert head is not None
    # A validly signed checkpoint with the right head hash but another chain's genesis.
    assert audit.signer is not None
    other_genesis = "e" * 64
    msg = checkpoint_message(
        seq=real.seq,
        chain_hash=real.chain_hash,
        genesis_hash=other_genesis,
        created_at=real.created_at,
        signer_key_id=audit.signer.key_id,
    )
    foreign = real.model_copy(
        update={"genesis_hash": other_genesis, "signature": audit.signer.sign(msg)}
    )
    report = await audit.verify(external_checkpoints=[foreign])
    assert [(i.seq, i.kind) for i in report.issues] == [(5, "checkpoint_foreign")]


async def test_tampered_checkpoint_fields_rejected(audit: AuditLog) -> None:
    await fill(audit, 5)
    (cp,) = await audit.checkpoints()
    altered = cp.model_copy(update={"seq": 4})
    report = await audit.verify(external_checkpoints=[altered])
    assert "checkpoint_signature" in kinds(report)


async def test_non_canonical_data_detected(audit: AuditLog) -> None:
    await fill(audit, 2)
    with attacker(audit) as db:
        db.execute("""UPDATE audit_events SET data = '{ "action" : "REDACT" }' WHERE seq = 1""")
    assert {"mac", "non_canonical"} <= kinds(await audit.verify())


# ------------------------------------------------------- database protections
async def test_triggers_block_update_and_delete_through_the_app(audit: AuditLog) -> None:
    await fill(audit, 2)
    async with audit.engine.begin() as conn:
        with pytest.raises(DBAPIError, match="append-only"):
            await conn.execute(text("UPDATE audit_events SET actor = 'x' WHERE seq = 1"))
    async with audit.engine.begin() as conn:
        with pytest.raises(DBAPIError, match="append-only"):
            await conn.execute(text("DELETE FROM audit_events WHERE seq = 2"))
    await audit.create_checkpoint()
    async with audit.engine.begin() as conn:
        with pytest.raises(DBAPIError, match="append-only"):
            await conn.execute(text("DELETE FROM audit_checkpoints"))
    assert (await audit.verify()).ok


async def test_unique_prev_hash_prevents_fork(audit: AuditLog) -> None:
    await fill(audit, 2)
    async with audit.engine.begin() as conn:
        with pytest.raises(IntegrityError):
            await conn.execute(
                text(
                    "INSERT INTO audit_events (seq, event_id, occurred_at, recorded_at, event_type,"
                    " actor, request_id, data, prev_hash, hash, key_id) SELECT 99, 'fork', "
                    "occurred_at, recorded_at, event_type, actor, request_id, data, prev_hash, "
                    "'h-fork', key_id FROM audit_events WHERE seq = 2"
                )
            )


# ------------------------------------------------------------ keys / safety
async def test_key_rotation_keeps_old_events_verifiable(audit: AuditLog) -> None:
    await fill(audit, 3)
    new_key = b"B" * 32
    audit.keyring = AuditKeyring.from_keys(new_key, previous=(AUDIT_KEY,))
    await fill(audit, 3)
    report = await audit.verify()
    assert report.ok, report.issues
    audit.keyring = AuditKeyring.from_keys(new_key)  # old key forgotten
    assert [(i.seq, i.kind) for i in (await audit.verify()).issues] == [
        (1, "unknown_key"),
        (2, "unknown_key"),
        (3, "unknown_key"),
    ]


async def test_event_containing_secret_is_rejected_without_echo(audit: AuditLog) -> None:
    token = synth.github_token(random.Random(1))
    with pytest.raises(UnsafeAuditDataError) as exc:
        await audit.append(event(data={"note": f"pasted {token}"}))
    assert token not in str(exc.value)
    assert "GITHUB_TOKEN" in str(exc.value)
    assert await audit.count() == 0


async def test_event_containing_card_number_is_rejected(audit: AuditLog) -> None:
    with pytest.raises(UnsafeAuditDataError, match="CREDIT_CARD"):
        await audit.append(event(data={"x": "4111 1111 1111 1111"}))


async def test_safe_metadata_with_fingerprints_is_accepted(audit: AuditLog) -> None:
    rec = await audit.append(
        event(
            data={
                "action": "REDACT",
                "placeholders": ["[PASSWORD_1]"],
                "fingerprints": ["1760569eebd6f6c0fded596e44556e22"],
                "rule": "password-assignment",
            }
        )
    )
    assert rec.seq == 1
    assert json.loads(canonical_json(rec.data))["placeholders"] == ["[PASSWORD_1]"]
