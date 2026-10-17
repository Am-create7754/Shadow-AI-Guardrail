"""Append-only, tamper-evident audit log.

Appending
---------
Each append runs in one transaction that (1) locks the chain head, (2) reads
the previous hash, (3) inserts the new event MAC'd over ``prev_hash``, and
(4) advances the head with a compare-and-swap on ``seq``. On SQLite the lock is
``BEGIN IMMEDIATE`` (serialises writers across connections and processes); on
PostgreSQL it is ``SELECT ... FOR UPDATE``. ``UNIQUE(prev_hash)`` and the
``seq`` primary key are a second line of defence: if two writers ever raced,
one insert fails instead of forking the chain. Failed attempts are retried;
every retryable error is raised before commit, so a retry never double-appends.

Verifying
---------
The verifier streams events in ``seq`` order and checks, for every event: the
sequence is contiguous, ``prev_hash`` links to the previous event, the MAC is
valid, the key is not older than one already used later in the chain, and the
stored data is canonical. It then checks the head row and every signed
checkpoint - from the database, from the anchor file and from exported files.
Malformed rows are reported, never raised, and each problem is reported with
the sequence number where it occurs.

What this does and does not detect
----------------------------------
* Edits, insertions, deletions and reordering inside the chain: always, by
  anyone without the audit key.
* **Rollback** (deleting the newest events, the head and the newest checkpoints
  together, wiping everything, or restoring an old backup): every remaining row
  is genuine, so this is undetectable from inside the database. It is detected
  only by a signed checkpoint kept *outside* it - the anchor file (on by
  default) or exported checkpoints.
* An attacker holding the audit key *and* database write access can also
  rebuild history; again only external checkpoints, verified with a public key
  whose private half that attacker does not hold, detect it.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import tempfile
import uuid
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, cast

from pydantic import ValidationError
from sqlalchemy import Table, func, insert, select, update
from sqlalchemy.exc import IntegrityError, OperationalError
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from app.audit.chain import (
    GENESIS_HASH,
    canonical_json,
    checkpoint_message,
    compute_mac,
    macs_equal,
    record_payload,
    utc_timestamp,
)
from app.audit.keys import (
    AuditKeyring,
    CheckpointSigner,
    CheckpointVerifier,
    load_audit_keyring,
    load_checkpoint_signer,
    load_checkpoint_verifier,
)
from app.audit.models import AuditChainHead, AuditCheckpointRow, AuditEventRow
from app.audit.schemas import MAX_DATA_BYTES, AuditEventIn, AuditRecord, Checkpoint
from app.core.config import Settings
from app.db.base import Base
from app.detection.engine import DetectionEngine
from app.detection.models import Category

logger = logging.getLogger(__name__)

EVENTS = cast(Table, AuditEventRow.__table__)
HEAD = cast(Table, AuditChainHead.__table__)
CHECKPOINTS = cast(Table, AuditCheckpointRow.__table__)

MAX_APPEND_ATTEMPTS = 8
MAX_REPORTED_ISSUES = 100
VERIFY_BATCH = 250
# Stored data larger than this was not written by append() (16 KiB limit); it is
# reported without being parsed, so planted huge rows cannot exhaust memory.
MAX_STORED_DATA_CHARS = 4 * MAX_DATA_BYTES
_UNSAFE_CATEGORIES = frozenset({Category.SECRET, Category.FINANCIAL})
_SAFETY_MIN_CONFIDENCE = 0.6
_MAC_FIELDS = (
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
_TEXT_FIELDS = (*(f for f in _MAC_FIELDS if f not in ("seq", "request_id")), "hash")


class UnsafeAuditDataError(ValueError):
    """Raised when an event appears to contain a secret or financial data."""


class ConcurrentAppendError(RuntimeError):
    """The chain head moved during an append (retryable)."""


@dataclass(frozen=True)
class Issue:
    seq: int | None
    kind: str
    detail: str


@dataclass
class VerificationReport:
    events_checked: int = 0
    last_seq: int = 0
    last_hash: str = GENESIS_HASH
    genesis_hash: str | None = None
    head_seq: int | None = None
    checkpoints_checked: int = 0
    anchor_checked: bool = False
    issues: list[Issue] = field(default_factory=list)
    issues_truncated: bool = False

    @property
    def ok(self) -> bool:
        return not self.issues

    @property
    def first_bad_seq(self) -> int | None:
        seqs = [i.seq for i in self.issues if i.seq is not None]
        return min(seqs) if seqs else None

    def add(self, seq: int | None, kind: str, detail: str, *, force: bool = False) -> None:
        """Record an issue. Per-event issues are capped; ``force`` (head, checkpoint
        and anchor findings) is never dropped, so the cap cannot hide a rollback."""
        if not force and len(self.issues) >= MAX_REPORTED_ISSUES:
            self.issues_truncated = True
            return
        self.issues.append(Issue(seq, kind, detail))

    def to_public(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "events_checked": self.events_checked,
            "last_seq": self.last_seq,
            "head_seq": self.head_seq,
            "checkpoints_checked": self.checkpoints_checked,
            "anchor_checked": self.anchor_checked,
            "first_bad_seq": self.first_bad_seq,
            "issues": [i.__dict__ for i in self.issues],
            "issues_truncated": self.issues_truncated,
        }


@dataclass
class _Pending:
    """An event waiting for the group commit; ``done`` resolves when committed."""

    ev: AuditEventIn
    data_json: str
    occurred_at: str
    done: asyncio.Future[AuditRecord]


def _retryable(exc: Exception) -> bool:
    if isinstance(exc, ConcurrentAppendError | IntegrityError):
        return True
    return isinstance(exc, OperationalError) and "locked" in str(exc).lower()


# Identifiers the gateway generates (uuid4().hex: request, approval, user, key
# ids). Not scanned: about 1 in 10,000 contains a digit run that passes the card
# checksum, and refusing those events failed requests closed at random (found
# by the Phase 7 load test). A secret cannot hide in exactly 32 hex characters
# without being one of these identifiers' shape, and anything else is scanned.
_HEX_ID = re.compile(r"[0-9a-f]{32}")


def _scan_pieces(ev: AuditEventIn) -> Iterator[str]:
    """Decoded text to scan for secrets.

    Scanning the canonical JSON would see ``password=\\"x\\"`` (escaped quotes) and
    miss it, so every key and string value is yielded raw, plus ``key=value`` for
    string values and the space-joined items of lists (a card number split into
    ``["4111", "1111", ...]``).
    """
    yield ev.event_type
    yield ev.actor
    if ev.request_id and not _HEX_ID.fullmatch(ev.request_id):
        yield ev.request_id

    def walk(value: Any) -> Iterator[str]:
        if isinstance(value, dict):
            for k, v in value.items():
                yield str(k)
                if isinstance(v, str) and not _HEX_ID.fullmatch(v):
                    yield f"{k}={v}"
                yield from walk(v)
        elif isinstance(value, list):
            scalars = [str(v) for v in value if isinstance(v, str | int | float)]
            if len(scalars) > 1:
                yield " ".join(scalars)
            for v in value:
                yield from walk(v)
        elif isinstance(value, str) and not _HEX_ID.fullmatch(value):
            yield value

    yield from walk(ev.data)


class AuditLog:
    def __init__(
        self,
        engine: AsyncEngine,
        keyring: AuditKeyring,
        signer: CheckpointSigner | None = None,
        verifier: CheckpointVerifier | None = None,
        *,
        checkpoint_interval: int = 100,
        anchor_path: Path | None = None,
        scanner: DetectionEngine | None = None,
    ) -> None:
        self.engine = engine
        self.keyring = keyring
        # In-process writers queue here instead of contending for SQLite's write
        # lock (its busy handler retries with growing sleeps: multi-second tails
        # and rare timeouts under load), and are committed in groups (see
        # append). BEGIN IMMEDIATE still serialises writers across processes.
        self._append_lock = asyncio.Lock()
        self._queue: list[_Pending] = []
        self.signer = signer
        if verifier is None and signer is not None:
            verifier = CheckpointVerifier([signer.public_key])
        self.verifier = verifier
        self.checkpoint_interval = checkpoint_interval
        self.anchor_path = anchor_path
        self.scanner = scanner if scanner is not None else DetectionEngine()

    @classmethod
    def from_settings(cls, settings: Settings, engine: AsyncEngine) -> AuditLog:
        signer = load_checkpoint_signer(settings)
        return cls(
            engine,
            load_audit_keyring(settings),
            signer,
            load_checkpoint_verifier(settings, signer),
            checkpoint_interval=settings.checkpoint_interval,
            anchor_path=settings.audit_anchor_path,
        )

    @classmethod
    def for_verification(
        cls, settings: Settings, engine: AsyncEngine, public_key_pems: tuple[str, ...]
    ) -> AuditLog:
        """Verifier that holds NO checkpoint signing key: checkpoints are checked
        only against the given (and configured) trusted public keys."""
        return cls(
            engine,
            load_audit_keyring(settings, create=False),
            None,
            load_checkpoint_verifier(settings, None, public_key_pems),
            checkpoint_interval=0,
            anchor_path=settings.audit_anchor_path,
        )

    async def create_schema(self) -> None:
        """Create tables (development/tests). Production uses Alembic migrations."""
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    # ------------------------------------------------------------------ append
    def _check_safe(self, ev: AuditEventIn) -> None:
        # Each piece is scanned on its own so context from one value (e.g. a rule
        # named "password-assignment") cannot spill onto an unrelated neighbour
        # (e.g. a hex fingerprint); key=value pieces carry their own context.
        hits = sorted(
            {
                f.entity_type
                for piece in _scan_pieces(ev)
                for f in self.scanner.scan(piece).findings
                if f.category in _UNSAFE_CATEGORIES and f.confidence >= _SAFETY_MIN_CONFIDENCE
            }
        )
        if hits:
            # Report types only - never echo the offending value.
            raise UnsafeAuditDataError(f"audit event rejected: contains {', '.join(hits)}")

    async def append(self, ev: AuditEventIn) -> AuditRecord:
        """Append one event and return it once it is **committed**.

        Group commit: events from concurrent callers in this process are queued,
        and whichever caller holds the writer lock commits every queued event in
        one transaction (one disk flush). Each caller still returns only after its
        own event is durable, and receives the error if that transaction fails,
        so fail-closed callers behave exactly as with one transaction per event.
        """
        self._check_safe(ev)
        loop = asyncio.get_running_loop()
        item = _Pending(
            ev, canonical_json(ev.data), utc_timestamp(ev.occurred_at), loop.create_future()
        )
        self._queue.append(item)
        async with self._append_lock:
            if not item.done.done():
                batch, self._queue = self._queue, []
                # Its own task: if this caller is cancelled (client gone), the
                # batch - other callers' events - is still committed, and the lock
                # is held until it is, so transactions never overlap in-process.
                commit = asyncio.ensure_future(self._commit_batch(batch))
                try:
                    await asyncio.shield(commit)
                except asyncio.CancelledError:
                    await asyncio.wait({commit})
                    raise
        return await item.done

    async def _commit_batch(self, batch: list[_Pending]) -> None:
        """Commit ``batch`` (retrying cross-process contention) and settle every future."""
        for attempt in range(MAX_APPEND_ATTEMPTS):
            try:
                records, checkpoints = await self._append_many(batch)
            except (ConcurrentAppendError, IntegrityError, OperationalError) as exc:
                if attempt == MAX_APPEND_ATTEMPTS - 1 or not _retryable(exc):
                    self._fail(batch, exc)
                    return
                await asyncio.sleep(0.005 * (2**attempt))
                continue
            except BaseException as exc:  # incl. cancellation of the committing caller
                self._fail(batch, exc)
                raise
            for cp in checkpoints:
                self._write_anchor(cp)
            for item, record in zip(batch, records, strict=True):
                if not item.done.done():
                    item.done.set_result(record)
            return

    @staticmethod
    def _fail(batch: list[_Pending], exc: BaseException) -> None:
        # Every waiter gets an ordinary exception, so fail-closed callers
        # (``except Exception``) refuse their request instead of crashing.
        err = exc if isinstance(exc, Exception) else RuntimeError("audit write interrupted")
        for item in batch:
            if not item.done.done():
                item.done.set_exception(err)

    async def _append_many(
        self, batch: list[_Pending]
    ) -> tuple[list[AuditRecord], list[Checkpoint]]:
        records: list[AuditRecord] = []
        checkpoints: list[Checkpoint] = []
        async with self.engine.connect() as raw_conn:
            conn = await raw_conn.execution_options(sqlite_begin="IMMEDIATE")
            async with conn.begin():
                head = (
                    await conn.execute(
                        select(HEAD.c.seq, HEAD.c.hash).where(HEAD.c.id == 1).with_for_update()
                    )
                ).first()
                first_prev_seq = head.seq if head else 0
                prev_seq, prev_hash = (head.seq, head.hash) if head else (0, GENESIS_HASH)
                recorded_at = utc_timestamp()
                for item in batch:
                    seq = prev_seq + 1
                    payload = record_payload(
                        seq=seq,
                        event_id=uuid.uuid4().hex,
                        occurred_at=item.occurred_at,
                        recorded_at=recorded_at,
                        event_type=item.ev.event_type,
                        actor=item.ev.actor,
                        request_id=item.ev.request_id,
                        data=item.data_json,
                        prev_hash=prev_hash,
                        key_id=self.keyring.current_id,
                    )
                    mac = compute_mac(self.keyring.current, payload)
                    row = {k: v for k, v in payload.items() if k != "v"} | {"hash": mac}
                    await conn.execute(insert(EVENTS).values(**row))
                    records.append(AuditRecord(**(row | {"data": json.loads(item.data_json)})))
                    if (
                        self.signer
                        and self.checkpoint_interval
                        and seq % self.checkpoint_interval == 0
                    ):
                        checkpoints.append(await self._insert_checkpoint(conn, seq, mac))
                    prev_seq, prev_hash = seq, mac
                if head is None:
                    await conn.execute(
                        insert(HEAD).values(
                            id=1, seq=prev_seq, hash=prev_hash, updated_at=recorded_at
                        )
                    )
                else:
                    result = await conn.execute(
                        update(HEAD)
                        .where(HEAD.c.id == 1, HEAD.c.seq == first_prev_seq)
                        .values(seq=prev_seq, hash=prev_hash, updated_at=recorded_at)
                    )
                    if result.rowcount != 1:
                        raise ConcurrentAppendError("chain head moved during append")
        return records, checkpoints

    # ------------------------------------------------------------- checkpoints
    async def _insert_checkpoint(
        self, conn: AsyncConnection, seq: int, chain_hash: str
    ) -> Checkpoint:
        if self.signer is None:
            raise RuntimeError("no checkpoint signer configured")
        if seq == 1:
            genesis = chain_hash
        else:
            genesis = (
                await conn.execute(select(EVENTS.c.hash).where(EVENTS.c.seq == 1))
            ).scalar_one()
        created_at = utc_timestamp()
        signature = self.signer.sign(
            checkpoint_message(
                seq=seq,
                chain_hash=chain_hash,
                genesis_hash=genesis,
                created_at=created_at,
                signer_key_id=self.signer.key_id,
            )
        )
        cp = Checkpoint(
            seq=seq,
            chain_hash=chain_hash,
            genesis_hash=genesis,
            created_at=created_at,
            signer_key_id=self.signer.key_id,
            signature=signature,
        )
        await conn.execute(insert(CHECKPOINTS).values(**cp.model_dump()))
        return cp

    async def create_checkpoint(self) -> Checkpoint | None:
        """Sign the current chain head. Returns None for an empty chain."""
        async with self.engine.connect() as raw_conn:
            conn = await raw_conn.execution_options(sqlite_begin="IMMEDIATE")
            async with conn.begin():
                head = (
                    await conn.execute(select(HEAD.c.seq, HEAD.c.hash).where(HEAD.c.id == 1))
                ).first()
                if head is None:
                    return None
                cp = await self._insert_checkpoint(conn, head.seq, head.hash)
        self._write_anchor(cp)
        return cp

    def _write_anchor(self, cp: Checkpoint) -> None:
        """Atomically store the newest checkpoint outside the database.

        Monotonic: never replaced by an older checkpoint. Failure to write is
        logged, not raised - the event itself is already committed.
        """
        path = self.anchor_path
        if path is None:
            return
        try:
            current = self.read_anchor()
            if current is not None and current.seq >= cp.seq:
                return
            path.parent.mkdir(parents=True, exist_ok=True)
            fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".anchor-", suffix=".tmp")
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(json.dumps(cp.model_dump(), indent=2))
            os.replace(tmp, path)
        except (OSError, ValueError) as exc:
            logger.warning("could not write audit anchor %s: %s", path, exc)

    def read_anchor(self) -> Checkpoint | None:
        """The anchored checkpoint, None if absent. Raises ValueError if malformed."""
        if self.anchor_path is None or not self.anchor_path.exists():
            return None
        try:
            return Checkpoint.model_validate_json(self.anchor_path.read_text(encoding="utf-8"))
        except ValidationError as exc:
            raise ValueError("audit anchor file is malformed") from exc

    async def _checkpoint_rows(self) -> tuple[list[Checkpoint], list[tuple[Any, str]]]:
        """Valid checkpoints, plus (row id, error) for rows that fail validation."""
        async with self.engine.connect() as conn:
            rows = (
                (await conn.execute(select(CHECKPOINTS).order_by(CHECKPOINTS.c.id)))
                .mappings()
                .all()
            )
        valid: list[Checkpoint] = []
        bad: list[tuple[Any, str]] = []
        for r in rows:
            try:
                valid.append(Checkpoint(**{k: r[k] for k in Checkpoint.model_fields}))
            except (ValidationError, KeyError, TypeError) as exc:
                bad.append((r.get("id"), type(exc).__name__))
        return valid, bad

    async def checkpoints(self) -> list[Checkpoint]:
        """Well-formed stored checkpoints ordered by seq (malformed rows are skipped
        here and reported by :meth:`verify`)."""
        valid, _ = await self._checkpoint_rows()
        return sorted(valid, key=lambda c: c.seq)

    # ------------------------------------------------------------------- reads
    async def head(self) -> tuple[int, str] | None:
        async with self.engine.connect() as conn:
            row = (
                await conn.execute(select(HEAD.c.seq, HEAD.c.hash).where(HEAD.c.id == 1))
            ).first()
            return (row.seq, row.hash) if row else None

    async def count(self) -> int:
        async with self.engine.connect() as conn:
            return int((await conn.execute(select(func.count()).select_from(EVENTS))).scalar_one())

    async def events_since(
        self, since: str, *, limit: int = 50_000
    ) -> tuple[list[AuditRecord], bool]:
        """Events recorded at or after the ISO timestamp ``since``, oldest first.

        At most ``limit`` events - the **newest** ones, so a busy window loses its
        oldest part rather than its most recent - plus whether it was truncated.
        """
        stmt = (
            select(EVENTS)
            .where(EVENTS.c.recorded_at >= since)
            .order_by(EVENTS.c.seq.desc())
            .limit(limit + 1)
        )
        async with self.engine.connect() as conn:
            rows = (await conn.execute(stmt)).mappings().all()
        truncated = len(rows) > limit
        out = []
        for r in reversed(rows[:limit]):
            try:
                out.append(AuditRecord(**(dict(r) | {"data": json.loads(r["data"])})))
            except (ValueError, TypeError):
                continue  # malformed rows are reported by verify(), not here
        return out, truncated

    async def list_events(
        self,
        *,
        limit: int = 50,
        before_seq: int | None = None,
        event_type: str | None = None,
        actor: str | None = None,
    ) -> list[AuditRecord]:
        """Newest first, keyset-paginated by ``before_seq``."""
        limit = max(1, min(limit, 500))
        stmt = select(EVENTS).order_by(EVENTS.c.seq.desc()).limit(limit)
        if before_seq is not None:
            stmt = stmt.where(EVENTS.c.seq < before_seq)
        if event_type is not None:
            stmt = stmt.where(EVENTS.c.event_type == event_type)
        if actor is not None:
            stmt = stmt.where(EVENTS.c.actor == actor)
        async with self.engine.connect() as conn:
            rows = (await conn.execute(stmt)).mappings().all()
        return [AuditRecord(**(dict(r) | {"data": json.loads(r["data"])})) for r in rows]

    # ------------------------------------------------------------------ verify
    async def verify(
        self, *, external_checkpoints: Iterable[Checkpoint] = ()
    ) -> VerificationReport:
        report = VerificationReport()
        stored, malformed = await self._checkpoint_rows()
        for row_id, error in malformed:
            report.add(
                None,
                "checkpoint_malformed",
                f"checkpoint row id {row_id} is malformed ({error})",
                force=True,
            )
        checkpoints = [("database", cp) for cp in stored]
        checkpoints += [("external", cp) for cp in external_checkpoints]
        anchor_unreadable = False
        try:
            anchor = self.read_anchor()
        except ValueError as exc:
            anchor, anchor_unreadable = None, True
            report.add(None, "anchor_malformed", str(exc), force=True)
        if anchor is not None:
            report.anchor_checked = True
            checkpoints.append(("anchor", anchor))
        elif self.anchor_path is not None and stored and not anchor_unreadable:
            report.add(
                None,
                "anchor_missing",
                "checkpoints exist but the anchor file is missing",
                force=True,
            )
        wanted = {cp.seq for _, cp in checkpoints}
        hashes_at: dict[int, str] = {}

        async with self.engine.connect() as conn:
            expected_seq, prev_hash, max_rank, after = 1, GENESIS_HASH, -1, 0
            while True:
                result = await conn.execute(
                    select(EVENTS)
                    .where(EVENTS.c.seq > after)
                    .order_by(EVENTS.c.seq)
                    .limit(VERIFY_BATCH)
                )
                rows = result.mappings().all()
                if not rows:
                    break
                for r in rows:
                    seq = r["seq"]
                    try:
                        max_rank = self._verify_row(r, expected_seq, prev_hash, max_rank, report)
                    except Exception as exc:
                        report.add(
                            seq, "malformed", f"event could not be verified ({type(exc).__name__})"
                        )
                    row_hash = r["hash"] if isinstance(r["hash"], str) else "<invalid>"
                    if seq == 1:
                        report.genesis_hash = row_hash
                    if seq in wanted:
                        hashes_at[seq] = row_hash
                    expected_seq, prev_hash = seq + 1, row_hash
                    report.events_checked += 1
                    report.last_seq, report.last_hash = seq, row_hash
                after = rows[-1]["seq"]
            head = (
                await conn.execute(select(HEAD.c.seq, HEAD.c.hash).where(HEAD.c.id == 1))
            ).first()
        self._verify_head(head, report)
        for source, cp in checkpoints:
            self._verify_checkpoint(source, cp, hashes_at, report)
        return report

    def _verify_row(
        self, r: Any, expected_seq: int, prev_hash: str, max_rank: int, report: VerificationReport
    ) -> int:
        """Check one event; returns the updated highest key rank seen so far."""
        seq = r["seq"]
        bad_types = [c for c in _TEXT_FIELDS if not isinstance(r[c], str)]
        if not isinstance(seq, int) or not (
            r["request_id"] is None or isinstance(r["request_id"], str)
        ):
            bad_types.append("seq/request_id")
        if bad_types:
            report.add(
                seq if isinstance(seq, int) else None,
                "malformed",
                f"columns with wrong type: {', '.join(bad_types)}",
            )
            return max_rank
        if seq != expected_seq:
            missing = (
                f"event {expected_seq} is missing"
                if seq - expected_seq == 1
                else f"events {expected_seq}..{seq - 1} are missing"
            )
            report.add(seq, "gap", missing)
        if r["prev_hash"] != prev_hash:
            report.add(seq, "link", "prev_hash does not match the preceding event's hash")
        key = self.keyring.get(r["key_id"])
        if key is None:
            report.add(seq, "unknown_key", f"no audit key with id {r['key_id']}")
        else:
            rank = self.keyring.rank(r["key_id"])
            if rank < max_rank:
                report.add(
                    seq,
                    "retired_key",
                    "signed with a key older than one already used earlier in the chain",
                )
            max_rank = max(max_rank, rank)
            payload = record_payload(**{k: r[k] for k in _MAC_FIELDS})
            if not macs_equal(compute_mac(key, payload), r["hash"]):
                report.add(seq, "mac", "event content does not match its MAC (modified or forged)")
        data = r["data"]
        if len(data) > MAX_STORED_DATA_CHARS:
            report.add(seq, "oversized", f"stored data is {len(data)} characters")
            return max_rank
        try:
            if canonical_json(json.loads(data)) != data:
                report.add(seq, "non_canonical", "stored data is not canonical JSON")
        except (ValueError, TypeError, RecursionError):
            report.add(seq, "non_canonical", "stored data is not valid JSON")
        return max_rank

    @staticmethod
    def _verify_head(head: Any, report: VerificationReport) -> None:
        if head is None:
            if report.events_checked:
                report.add(
                    None,
                    "head_missing",
                    "events exist but the chain head row is missing",
                    force=True,
                )
            return
        report.head_seq = head.seq if isinstance(head.seq, int) else None
        if head.seq != report.last_seq or head.hash != report.last_hash:
            report.add(
                head.seq if isinstance(head.seq, int) else None,
                "head_mismatch",
                f"head records seq {head.seq} but the chain ends at seq {report.last_seq} "
                "(newest events deleted or head altered)",
                force=True,
            )

    def _verify_checkpoint(
        self, source: str, cp: Checkpoint, hashes_at: dict[int, str], report: VerificationReport
    ) -> None:
        report.checkpoints_checked += 1
        message = checkpoint_message(
            seq=cp.seq,
            chain_hash=cp.chain_hash,
            genesis_hash=cp.genesis_hash,
            created_at=cp.created_at,
            signer_key_id=cp.signer_key_id,
        )
        if self.verifier is None or not self.verifier.verify(
            cp.signer_key_id, cp.signature, message
        ):
            report.add(
                cp.seq,
                "checkpoint_signature",
                f"{source} checkpoint signature is invalid or untrusted",
                force=True,
            )
            return
        if cp.seq > report.last_seq:
            report.add(
                cp.seq,
                "checkpoint_beyond_chain",
                f"{source} checkpoint attests seq {cp.seq} but the chain ends at "
                f"{report.last_seq} (events deleted or database rolled back)",
                force=True,
            )
        elif report.genesis_hash is not None and cp.genesis_hash != report.genesis_hash:
            report.add(
                cp.seq,
                "checkpoint_foreign",
                f"{source} checkpoint belongs to a different chain",
                force=True,
            )
        elif hashes_at.get(cp.seq) != cp.chain_hash:
            report.add(
                cp.seq,
                "checkpoint_mismatch",
                f"{source} checkpoint hash differs from the event stored at seq {cp.seq}",
                force=True,
            )
