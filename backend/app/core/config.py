"""Application settings.

All configuration comes from environment variables prefixed with ``GUARDRAIL_``
(optionally loaded from ``backend/.env``). Secrets are typed as ``SecretStr`` so
they are never rendered by ``repr()``/logging by accident.
"""

from __future__ import annotations

import secrets
import warnings
from enum import StrEnum
from functools import lru_cache
from pathlib import Path

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

BACKEND_DIR = Path(__file__).resolve().parents[2]
DEFAULT_POLICY_PATH = BACKEND_DIR / "app" / "policy" / "default_policy.yaml"

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
    )

    environment: Environment = Environment.DEVELOPMENT
    policy_path: Path = DEFAULT_POLICY_PATH

    # Hard ceiling on prompt size (characters). Enforced before any detection runs.
    max_input_chars: int = Field(default=100_000, ge=1, le=2_000_000)

    # Key used to HMAC detected values into non-reversible fingerprints, so repeated
    # secrets can be correlated without ever storing the secret itself.
    fingerprint_key: SecretStr | None = None

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
        return self

    def fingerprint_key_bytes(self) -> bytes:
        if self.fingerprint_key is None:  # unreachable: set by the validator
            raise RuntimeError("fingerprint key not initialised")
        return self.fingerprint_key.get_secret_value().encode()


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
