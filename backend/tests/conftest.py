from __future__ import annotations

import os
import random
import tempfile

import pytest
from pydantic import SecretStr

from app.core.config import Environment, Settings
from app.detection.engine import DetectionEngine
from app.guardrail import Guardrail
from app.policy.engine import load_policy

# Never read the developer's backend/.env in tests: it may hold a real provider API
# key, and tests must be hermetic, offline and free. Live tests load it explicitly.
Settings.model_config["env_file"] = None
for _name in [k for k in os.environ if k.startswith("GUARDRAIL_PROVIDER")]:
    del os.environ[_name]

# Never let tests touch the real per-user data directory (database, keys, anchor).
_ISOLATED = tempfile.mkdtemp(prefix="guardrail-tests-")
os.environ.setdefault("GUARDRAIL_KEYS_DIR", os.path.join(_ISOLATED, "keys"))
os.environ.setdefault("GUARDRAIL_AUDIT_ANCHOR_PATH", os.path.join(_ISOLATED, "anchor.json"))
os.environ.setdefault(
    "GUARDRAIL_DATABASE_URL",
    "sqlite+aiosqlite:///" + os.path.join(_ISOLATED, "db.sqlite").replace("\\", "/"),
)

# Test-only key (not a secret): fixed so fingerprints are reproducible across runs.
TEST_FINGERPRINT_KEY = "test-fingerprint-key-0123456789abcdef-not-secret"


@pytest.fixture(scope="session")
def settings() -> Settings:
    return Settings(
        environment=Environment.TEST,
        fingerprint_key=SecretStr(TEST_FINGERPRINT_KEY),
    )


@pytest.fixture(scope="session")
def guard(settings: Settings) -> Guardrail:
    return Guardrail(load_policy(settings.policy_path), settings)


@pytest.fixture(scope="session")
def engine() -> DetectionEngine:
    return DetectionEngine()


@pytest.fixture
def rng() -> random.Random:
    return random.Random(1234)  # deterministic synthetic data
