"""Audit log command-line tool.

PowerShell examples (from backend/)::

    .venv\\Scripts\\python -m app.audit init-db
    .venv\\Scripts\\python -m app.audit verify
    .venv\\Scripts\\python -m app.audit verify --checkpoints exported.json
    .venv\\Scripts\\python -m app.audit checkpoint
    .venv\\Scripts\\python -m app.audit export-checkpoints exported.json
    .venv\\Scripts\\python -m app.audit export-public-key checkpoint_public.pem
    .venv\\Scripts\\python -m app.audit tamper-demo
    .venv\\Scripts\\python -m app.audit backup --out D:\\backups\\audit-2026-10-18.db

``verify`` exits with status 1 when any integrity problem is found.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import sqlite3
import sys
import tempfile
from pathlib import Path
from typing import Any

from alembic import command
from alembic.config import Config
from sqlalchemy.engine import make_url

from app.audit.keys import CHECKPOINT_KEY_FILE, load_audit_keyring, load_checkpoint_signer
from app.audit.schemas import AuditEventIn, Checkpoint
from app.audit.service import AuditLog
from app.core.config import BACKEND_DIR, Environment, Settings, get_settings
from app.db.engine import create_engine


def _print(obj: Any) -> None:
    print(json.dumps(obj, indent=2, ensure_ascii=False))


def _alembic_upgrade(url: str) -> None:
    cfg = Config(str(BACKEND_DIR / "alembic.ini"))
    # Alembic config values are %-interpolated: a "%" in the path must be escaped.
    cfg.set_main_option("sqlalchemy.url", url.replace("%", "%%"))
    command.upgrade(cfg, "head")


async def _with_log(settings: Settings, fn: Any) -> Any:
    engine = create_engine(settings.database_url)
    try:
        return await fn(AuditLog.from_settings(settings, engine))
    finally:
        await engine.dispose()


def _existing_signer_pems(settings: Settings) -> tuple[str, ...]:
    """Public key of the configured signing key, if one already exists."""
    path = settings.checkpoint_key_path or settings.keys_dir / CHECKPOINT_KEY_FILE
    if not path.exists():
        return ()
    signer = load_checkpoint_signer(settings.model_copy(update={"checkpoint_key_path": path}))
    return (signer.public_pem(),)


def _load_checkpoints(path: Path) -> list[Checkpoint]:
    return [Checkpoint.model_validate(c) for c in json.loads(path.read_text(encoding="utf-8"))]


async def _tamper_demo() -> int:
    """Self-contained demonstration on a throw-away database."""
    with tempfile.TemporaryDirectory() as tmp:
        url = f"sqlite+aiosqlite:///{Path(tmp, 'demo.db').as_posix()}"
        await asyncio.to_thread(_alembic_upgrade, url)
        engine = create_engine(url)
        log = AuditLog.from_settings(Settings(environment=Environment.TEST), engine)
        log.checkpoint_interval = 5
        log.anchor_path = Path(tmp, "anchor.json")  # keep the demo self-contained
        try:
            print("1. Writing 12 audit events (checkpoints are signed every 5 events)...")
            for i in range(12):
                await log.append(
                    AuditEventIn(
                        event_type="prompt.inspected",
                        actor=f"dev-{i % 3}",
                        request_id=f"req-{i:03d}",
                        data={
                            "action": "REDACT" if i % 2 else "ALLOW",
                            "risk_score": 10 * (i % 10),
                        },
                    )
                )
            exported = await log.checkpoints()
            print(
                f"   exported {len(exported)} signed checkpoints off-host (seq "
                f"{', '.join(str(c.seq) for c in exported)})"
            )

            print("\n2. Verifying the untouched chain:")
            _print((await log.verify()).to_public())

            print("\n3. Attacker with raw database access drops the append-only triggers,")
            print("   changes event 4 from REDACT to ALLOW and deletes event 9...")
            db = sqlite3.connect(Path(tmp, "demo.db"), isolation_level=None)
            for (name,) in db.execute(
                "SELECT name FROM sqlite_master WHERE type='trigger'"
            ).fetchall():
                db.execute(f"DROP TRIGGER {name}")
            db.execute(
                "UPDATE audit_events SET data = ? WHERE seq = 4",
                ('{"action":"ALLOW","risk_score":0}',),
            )
            db.execute("DELETE FROM audit_events WHERE seq = 9")
            db.close()

            print("\n4. Verifying again (with the exported checkpoints):")
            report = await log.verify(external_checkpoints=exported)
            _print(report.to_public())
            print(
                f"\nResult: tampering {'DETECTED' if not report.ok else 'NOT detected'}; "
                f"first bad event = seq {report.first_bad_seq}"
            )
            return 0 if not report.ok else 1
        finally:
            await engine.dispose()


def _sqlite_path(database_url: str) -> Path:
    url = make_url(database_url)
    if url.get_backend_name() != "sqlite":
        raise ValueError("backup supports SQLite only; use pg_dump for PostgreSQL")
    # Exactly the file the application opens (SQLAlchemy percent-decodes the path).
    path = url.database
    if not path or path == ":memory:":
        raise ValueError("in-memory database cannot be backed up")
    return Path(path)


def _backup(settings: Settings, out: Path) -> int:
    """Consistent online copy (SQLite backup API: safe while the gateway writes),
    then verify the copy's chain and write a SHA-256 checksum next to it."""
    src_path = _sqlite_path(settings.database_url)
    if out.exists():
        print(f"refusing to overwrite {out}", file=sys.stderr)
        return 2
    out.parent.mkdir(parents=True, exist_ok=True)
    # Proper file URI: a path containing ?, # or % must not change its meaning.
    src = sqlite3.connect(src_path.resolve().as_uri() + "?mode=ro", uri=True)
    dst = sqlite3.connect(out)
    try:
        src.backup(dst)
    finally:
        dst.close()
        src.close()

    async def verify_copy() -> Any:
        engine = create_engine("sqlite+aiosqlite:///" + out.as_posix())
        try:
            # No anchor: it may already be newer than this copy (that would be
            # reported as a rollback, which is expected for a backup).
            copy_settings = settings.model_copy(update={"audit_anchor_path": None})
            log = AuditLog.for_verification(copy_settings, engine, _existing_signer_pems(settings))
            return await log.verify()
        finally:
            await engine.dispose()

    report = asyncio.run(verify_copy())
    digest = hashlib.sha256(out.read_bytes()).hexdigest()
    out.with_name(out.name + ".sha256").write_text(f"{digest}  {out.name}\n", encoding="ascii")
    _print(
        {
            "backup": str(out),
            "sha256": digest,
            "events": report.events_checked,
            "checkpoints": report.checkpoints_checked,
            "chain_ok": report.ok,
        }
    )
    return 0 if report.ok else 1


def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    parser = argparse.ArgumentParser(prog="python -m app.audit", description="Audit log tools")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("init-db", help="apply database migrations")
    v = sub.add_parser("verify", help="verify chain integrity (exit 1 on failure)")
    v.add_argument("--checkpoints", type=Path, help="JSON file of exported checkpoints")
    v.add_argument(
        "--public-key",
        type=Path,
        action="append",
        default=[],
        help="trusted checkpoint public key (PEM); repeatable. When given, the private "
        "signing key is not loaded at all.",
    )
    sub.add_parser("checkpoint", help="sign the current chain head")
    e = sub.add_parser("export-checkpoints", help="write all checkpoints to a JSON file")
    e.add_argument("path", type=Path)
    k = sub.add_parser("export-public-key", help="write the checkpoint public key (PEM)")
    k.add_argument("path", type=Path)
    sub.add_parser("tamper-demo", help="demonstrate tamper detection on a temporary database")
    b = sub.add_parser("backup", help="verified online copy of the SQLite database")
    b.add_argument("--out", type=Path, required=True, help="new file (never overwritten)")
    args = parser.parse_args(argv)

    if args.cmd == "tamper-demo":
        return asyncio.run(_tamper_demo())

    settings = get_settings()
    if args.cmd == "backup":
        try:
            return _backup(settings, args.out)
        except (ValueError, FileNotFoundError, sqlite3.Error) as exc:
            print(f"backup failed: {exc}", file=sys.stderr)
            return 2
    if args.cmd == "init-db":
        _alembic_upgrade(settings.database_url)
        print(f"database ready: {settings.database_url}")
        # First-time setup: make sure keys exist (generated only in development).
        load_audit_keyring(settings)
        load_checkpoint_signer(settings)
        print("audit keys ready")
        return 0
    if args.cmd == "verify":
        external = _load_checkpoints(args.checkpoints) if args.checkpoints else []
        pems = tuple(p.read_text(encoding="ascii") for p in args.public_key)

        async def run_verify() -> int:
            engine = create_engine(settings.database_url)
            try:
                trusted = pems or _existing_signer_pems(settings)
                # Verification never generates keys (see load_audit_keyring).
                log = AuditLog.for_verification(settings, engine, trusted)
                report = await log.verify(external_checkpoints=external)
            finally:
                await engine.dispose()
            _print(report.to_public())
            return 0 if report.ok else 1

        try:
            return asyncio.run(run_verify())
        except FileNotFoundError as exc:
            print(f"cannot verify: {exc}", file=sys.stderr)
            return 2
    if args.cmd == "checkpoint":

        async def run_checkpoint(log: AuditLog) -> int:
            cp = await log.create_checkpoint()
            _print(cp.model_dump() if cp else {"detail": "chain is empty"})
            return 0

        return int(asyncio.run(_with_log(settings, run_checkpoint)))
    if args.cmd == "export-checkpoints":

        async def run_export(log: AuditLog) -> int:
            cps = [c.model_dump() for c in await log.checkpoints()]
            args.path.write_text(json.dumps(cps, indent=2), encoding="utf-8")
            print(f"wrote {len(cps)} checkpoints to {args.path}")
            return 0

        return int(asyncio.run(_with_log(settings, run_export)))
    if args.cmd == "export-public-key":

        async def run_key(log: AuditLog) -> int:
            if log.signer is None:
                print("no checkpoint signer configured", file=sys.stderr)
                return 2
            args.path.write_text(log.signer.public_pem(), encoding="ascii")
            print(f"wrote public key {log.signer.key_id} to {args.path}")
            return 0

        return int(asyncio.run(_with_log(settings, run_key)))
    return 2  # pragma: no cover - argparse enforces a command


if __name__ == "__main__":
    sys.exit(main())
