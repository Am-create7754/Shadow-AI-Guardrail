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

    # --- Gateway -----------------------------------------------------------------
    # HMAC key for dashboard session tokens (JWT, HS256).
    jwt_secret: SecretStr | None = None
    jwt_ttl_minutes: int = Field(default=30, ge=1, le=24 * 60)
    # Server-side pepper for hashing API keys (keys are random, so HMAC suffices).
    api_key_pepper: SecretStr | None = None
    # AES-256-GCM key encrypting prompts held for administrator approval.
    data_key: SecretStr | None = None
    # Hard ceiling on HTTP request bodies, enforced before JSON parsing.
    max_body_bytes: int = Field(default=1_000_000, ge=1_024, le=20_000_000)
    # Per-principal request budget (token bucket) and a stricter login budget per client.
    rate_limit_per_minute: int = Field(default=120, ge=1, le=100_000)
    login_rate_limit_per_minute: int = Field(default=10, ge=1, le=1_000)
    # Browser origins allowed to call the API (the dashboard). Comma-separated.
    cors_origins: str = "http://localhost:5173,http://127.0.0.1:5173"
    approval_ttl_minutes: int = Field(default=24 * 60, ge=1, le=30 * 24 * 60)
    # Which AI provider adapter to use ("mock" needs no key or network).
    provider: str = Field(default="mock", pattern=r"^[a-z][a-z0-9_]{1,30}$")
    provider_timeout_seconds: float = Field(default=30.0, gt=0, le=600)

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

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
            for name in ("jwt_secret", "api_key_pepper", "data_key"):
                if getattr(self, name) is None:
                    raise ValueError(f"GUARDRAIL_{name.upper()} must be set in production")
        # Every configured key must be strong and distinct from every other key.
        named = {
            name: value.get_secret_value()
            for name in ("fingerprint_key", "audit_key", "jwt_secret", "api_key_pepper", "data_key")
            if (value := getattr(self, name)) is not None
        }
        for name, value in named.items():
            if len(value.encode()) < MIN_KEY_BYTES:
                raise ValueError(f"GUARDRAIL_{name.upper()} must be at least {MIN_KEY_BYTES} bytes")
        if len(set(named.values())) != len(named):
            raise ValueError("GUARDRAIL_* keys must all be different from each other")
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
