"""Key management for the audit chain.

Two independent keys:

* **Audit HMAC key** (symmetric) - authenticates every event. Needed by the
  gateway to append, so it lives with the application.
* **Checkpoint signing key** (Ed25519) - signs periodic snapshots of the chain
  head. Only the *public* key is needed to verify, so verification can happen on
  a machine that never holds the signing key. In a real deployment the private key
  belongs in a separate secret store / HSM.

Verification of checkpoints needs only public keys
(:func:`load_checkpoint_verifier`); verification of event MACs needs the
symmetric audit key - an HMAC cannot be checked without it.

Key sources, in order:
1. Explicit configuration (``GUARDRAIL_AUDIT_KEY``, ``GUARDRAIL_CHECKPOINT_KEY_PATH``).
2. Development only: generated once and persisted under ``keys_dir`` (outside the
   repository), with a warning.
3. Test only: ephemeral in-memory keys.
Production refuses to start without explicit keys (enforced in ``Settings``).
"""

from __future__ import annotations

import hashlib
import os
import secrets
import warnings
from dataclasses import dataclass, field
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from app.core.config import MIN_KEY_BYTES, Environment, Settings

AUDIT_KEY_FILE = "audit_hmac.key"
CHECKPOINT_KEY_FILE = "checkpoint_ed25519.pem"


def audit_key_id(key: bytes) -> str:
    """Public identifier of an HMAC key (a hash; reveals nothing usable about the key)."""
    return hashlib.sha256(b"guardrail-audit-key-id\n" + key).hexdigest()[:16]


def public_key_id(public_key: Ed25519PublicKey) -> str:
    raw = public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return hashlib.sha256(raw).hexdigest()[:16]


@dataclass(frozen=True)
class AuditKeyring:
    """Audit HMAC keys in rotation order (oldest first, current last).

    The order matters for verification: once an event signed with a newer key
    appears in the chain, a later event signed with an *older* key is rejected
    ("retired_key"), so a leaked retired key cannot be used to forge new events.
    """

    current_id: str
    keys: dict[str, bytes] = field(repr=False)
    order: tuple[str, ...] = ()

    @classmethod
    def from_keys(cls, current: bytes, previous: tuple[bytes, ...] = ()) -> AuditKeyring:
        """``previous`` lists retired keys oldest first."""
        sequence = (*previous, current)
        for k in sequence:
            if len(k) < MIN_KEY_BYTES:
                raise ValueError(f"audit keys must be at least {MIN_KEY_BYTES} bytes")
        ids = tuple(dict.fromkeys(audit_key_id(k) for k in sequence))
        return cls(audit_key_id(current), {audit_key_id(k): k for k in sequence}, ids)

    def rank(self, key_id: str) -> int:
        """Position in rotation order (higher = newer); -1 if unknown."""
        return self.order.index(key_id) if key_id in self.order else -1

    @property
    def current(self) -> bytes:
        return self.keys[self.current_id]

    def get(self, key_id: str) -> bytes | None:
        return self.keys.get(key_id)

    def __repr__(self) -> str:
        return f"AuditKeyring(current_id={self.current_id!r}, key_ids={sorted(self.keys)!r})"


class CheckpointSigner:
    def __init__(self, private_key: Ed25519PrivateKey) -> None:
        self._private = private_key
        self.public_key = private_key.public_key()
        self.key_id = public_key_id(self.public_key)

    def sign(self, message: bytes) -> str:
        return self._private.sign(message).hex()

    def public_pem(self) -> str:
        return self.public_key.public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode("ascii")

    def __repr__(self) -> str:
        return f"CheckpointSigner(key_id={self.key_id!r})"


class CheckpointVerifier:
    """Trusted public keys for checkpoint verification, indexed by key id."""

    def __init__(self, public_keys: list[Ed25519PublicKey]) -> None:
        self.keys = {public_key_id(k): k for k in public_keys}

    @classmethod
    def from_pem(cls, *pems: str | bytes) -> CheckpointVerifier:
        keys = []
        for pem in pems:
            data = pem.encode("ascii") if isinstance(pem, str) else pem
            key = serialization.load_pem_public_key(data)
            if not isinstance(key, Ed25519PublicKey):
                raise ValueError("checkpoint public key must be Ed25519")
            keys.append(key)
        return cls(keys)

    def verify(self, key_id: str, signature_hex: str, message: bytes) -> bool:
        key = self.keys.get(key_id)
        if key is None:
            return False
        try:
            key.verify(bytes.fromhex(signature_hex), message)
        except (InvalidSignature, ValueError):
            return False
        return True


def _write_private_file(path: Path, data: bytes) -> None:
    """Create ``path`` exclusively with owner-only permissions where supported."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)


def load_audit_keyring(settings: Settings, *, create: bool = True) -> AuditKeyring:
    """Load the audit keyring. ``create=False`` (used by verification) never
    generates a development key: verifying with a freshly invented key would
    only produce a wall of ``unknown_key`` errors and hide the real problem."""
    previous: tuple[bytes, ...] = ()
    if settings.audit_previous_keys is not None:
        previous = tuple(
            k.strip().encode()
            for k in settings.audit_previous_keys.get_secret_value().split(",")
            if k.strip()
        )
    if settings.audit_key is not None:
        return AuditKeyring.from_keys(settings.audit_key.get_secret_value().encode(), previous)
    if settings.environment is Environment.TEST:
        return AuditKeyring.from_keys(secrets.token_bytes(32), previous)
    if settings.environment is Environment.PRODUCTION:  # pragma: no cover - Settings rejects it
        raise RuntimeError("audit key missing in production")
    path = settings.keys_dir / AUDIT_KEY_FILE
    if not path.exists() and not create:
        raise FileNotFoundError(f"audit key not found at {path} (set GUARDRAIL_AUDIT_KEY)")
    if not path.exists():
        warnings.warn(f"generating development audit key at {path}", stacklevel=2)
        _write_private_file(path, secrets.token_hex(32).encode())
    key = path.read_bytes().strip()
    if len(key) < MIN_KEY_BYTES:
        raise ValueError(f"audit key file {path} is shorter than {MIN_KEY_BYTES} bytes")
    return AuditKeyring.from_keys(key, previous)


def load_checkpoint_signer(settings: Settings) -> CheckpointSigner:
    if settings.checkpoint_key_path is not None:
        return CheckpointSigner(_load_private_pem(settings.checkpoint_key_path.read_bytes()))
    if settings.environment is Environment.TEST:
        return CheckpointSigner(Ed25519PrivateKey.generate())
    if settings.environment is Environment.PRODUCTION:  # pragma: no cover - Settings rejects it
        raise RuntimeError("checkpoint key missing in production")
    path = settings.keys_dir / CHECKPOINT_KEY_FILE
    if not path.exists():
        warnings.warn(f"generating development checkpoint signing key at {path}", stacklevel=2)
        pem = Ed25519PrivateKey.generate().private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        _write_private_file(path, pem)
    return CheckpointSigner(_load_private_pem(path.read_bytes()))


def load_checkpoint_verifier(
    settings: Settings, signer: CheckpointSigner | None = None, extra_pems: tuple[str, ...] = ()
) -> CheckpointVerifier:
    """Trusted public keys: the current signer's, configured extra keys (e.g. keys
    used before a rotation) and any PEMs passed explicitly."""
    pems: list[str | bytes] = list(extra_pems)
    if settings.checkpoint_trusted_keys:
        pems += [
            Path(p.strip()).read_bytes()
            for p in settings.checkpoint_trusted_keys.split(",")
            if p.strip()
        ]
    verifier = CheckpointVerifier.from_pem(*pems) if pems else CheckpointVerifier([])
    if signer is not None:
        verifier.keys[signer.key_id] = signer.public_key
    return verifier


def _load_private_pem(data: bytes) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(data, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("checkpoint signing key must be an Ed25519 private key")
    return key
