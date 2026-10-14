"""Application settings.

All configuration comes from environment variables prefixed with ``GUARDRAIL_``
(optionally loaded from ``backend/.env``). Secrets are typed as ``SecretStr`` so
they are never rendered by ``repr()``/logging by accident.
"""

from __future__ import annotations

import os
import secrets
import warnings
from enum import StrEnum
from functools import lru_cache
from pathlib import Path

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

BACKEND_DIR = Path(__file__).resolve().parents[2]
DEFAULT_POLICY_PATH = BACKEND_DIR / "app" / "policy" / "default_policy.yaml"


def default_data_dir() -> Path:
    """Machine-local, non-synced data directory.

    Deliberately NOT inside the repository: this project may live in a synced
    folder (OneDrive), which would upload generated keys to the cloud and can
    corrupt SQLite WAL files while syncing.
    """
    if os.name == "nt":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    else:
        base = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
    return base / "guardrail"


# Keys shorter than this are rejected: HMAC-SHA256 keys should carry >=256 bits.
MIN_KEY_BYTES = 32


class Environment(StrEnum):
    DEVELOPMENT = "development"
    TEST = "test"
    PRODUCTION = "production"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="GUARDRAIL_",
        env_file=BACKEND_DIR / ".env",
        env_file_encoding="utf-8",
        extra="ignore",
        # "GUARDRAIL_AUDIT_KEY=" (as in .env.example) means "unset", not "empty key".
        env_ignore_empty=True,
    )

    environment: Environment = Environment.DEVELOPMENT
    policy_path: Path = DEFAULT_POLICY_PATH

    # Hard ceiling on prompt size (characters). Enforced before any detection runs.
    max_input_chars: int = Field(default=100_000, ge=1, le=2_000_000)

    # Key used to HMAC detected values into non-reversible fingerprints, so repeated
    # secrets can be correlated without ever storing the secret itself.
    fingerprint_key: SecretStr | None = None

    # --- Persistence -------------------------------------------------------------
    # SQLite for local use; any SQLAlchemy async URL (e.g. postgresql+asyncpg://...)
    # works for the models.
    database_url: str = f"sqlite+aiosqlite:///{(default_data_dir() / 'guardrail.db').as_posix()}"

    # --- Audit chain -------------------------------------------------------------
    # HMAC-SHA256 key for the audit chain. Deliberately separate from the
    # fingerprint key: compromising one must not allow forging the other.
    audit_key: SecretStr | None = None
    # Retired audit keys (comma-separated), still accepted when verifying old events.
    audit_previous_keys: SecretStr | None = None
    # Ed25519 private key (PEM, PKCS#8) that signs chain checkpoints. Should live
    # on a different host / secret store from the database in a real deployment.
    checkpoint_key_path: Path | None = None
    # Extra trusted Ed25519 public keys (comma-separated PEM paths), e.g. keys that
    # signed checkpoints before a signing-key rotation.
    checkpoint_trusted_keys: str | None = None
    # File OUTSIDE the database holding the latest signed checkpoint. Rolling the
    # database back (deleting newest events and checkpoints) cannot be detected
    # from inside the database; this anchor detects it. None disables it.
    audit_anchor_path: Path | None = default_data_dir() / "anchors" / "audit_anchor.json"
    # Sign a checkpoint automatically every N events (0 disables).
    checkpoint_interval: int = Field(default=100, ge=0, le=1_000_000)
    # Where development keys are generated and persisted (outside the repository).
    keys_dir: Path = default_data_dir() / "keys"

    @model_validator(mode="after")
    def _ensure_keys(self) -> Settings:
        if self.fingerprint_key is None:
            if self.environment is Environment.PRODUCTION:
                raise ValueError("GUARDRAIL_FINGERPRINT_KEY must be set in production")
            # Ephemeral key: fingerprints stay consistent within this process only.
            if self.environment is Environment.DEVELOPMENT:
                warnings.warn(
                    "GUARDRAIL_FINGERPRINT_KEY not set; using an ephemeral per-process key",
                    stacklevel=2,
                )
            self.fingerprint_key = SecretStr(secrets.token_urlsafe(48))
        if len(self.fingerprint_key.get_secret_value().encode()) < MIN_KEY_BYTES:
            raise ValueError(f"GUARDRAIL_FINGERPRINT_KEY must be at least {MIN_KEY_BYTES} bytes")
        if self.environment is Environment.PRODUCTION:
            if self.audit_key is None:
                raise ValueError("GUARDRAIL_AUDIT_KEY must be set in production")
            if self.checkpoint_key_path is None:
                raise ValueError("GUARDRAIL_CHECKPOINT_KEY_PATH must be set in production")
        if self.audit_key is not None and self.fingerprint_key is not None:
            if len(self.audit_key.get_secret_value().encode()) < MIN_KEY_BYTES:
                raise ValueError(f"GUARDRAIL_AUDIT_KEY must be at least {MIN_KEY_BYTES} bytes")
            if self.audit_key.get_secret_value() == self.fingerprint_key.get_secret_value():
                raise ValueError("GUARDRAIL_AUDIT_KEY must differ from GUARDRAIL_FINGERPRINT_KEY")
        if self.audit_previous_keys is not None:
            for old in self.audit_previous_keys.get_secret_value().split(","):
                if old.strip() and len(old.strip().encode()) < MIN_KEY_BYTES:
                    raise ValueError(
                        f"each GUARDRAIL_AUDIT_PREVIOUS_KEYS entry must be >= {MIN_KEY_BYTES} bytes"
                    )
        return self

    def fingerprint_key_bytes(self) -> bytes:
        if self.fingerprint_key is None:  # unreachable: set by the validator
            raise RuntimeError("fingerprint key not initialised")
        return self.fingerprint_key.get_secret_value().encode()


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
