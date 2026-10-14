"""Resolve symmetric application keys (JWT, API-key pepper, data encryption).

Same policy as the audit keys (``app.audit.keys``):

* configured value -> used as-is (length already validated by ``Settings``);
* test environment -> random per process;
* development -> generated once, persisted in ``keys_dir`` (outside the repo);
* production -> must be configured (``Settings`` refuses to start otherwise).
"""

from __future__ import annotations

import os
import secrets
import warnings
from pathlib import Path

from pydantic import SecretStr

from app.core.config import MIN_KEY_BYTES, Environment, Settings


def _write_private_file(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)


def resolve_key(settings: Settings, value: SecretStr | None, name: str) -> bytes:
    """Return key bytes for setting ``name`` (e.g. "jwt_secret")."""
    if value is not None:
        return value.get_secret_value().encode()
    if settings.environment is Environment.TEST:
        return secrets.token_bytes(32)
    if settings.environment is Environment.PRODUCTION:  # pragma: no cover - Settings rejects it
        raise RuntimeError(f"GUARDRAIL_{name.upper()} missing in production")
    path = settings.keys_dir / f"{name}.key"
    if not path.exists():
        warnings.warn(f"generating development {name} at {path}", stacklevel=2)
        _write_private_file(path, secrets.token_hex(32).encode())
    key = path.read_bytes().strip()
    if len(key) < MIN_KEY_BYTES:
        raise ValueError(f"{path} is shorter than {MIN_KEY_BYTES} bytes")
    return key
