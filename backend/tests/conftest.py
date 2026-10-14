from __future__ import annotations

import random

import pytest
from pydantic import SecretStr

from app.core.config import Environment, Settings
from app.detection.engine import DetectionEngine
from app.guardrail import Guardrail
from app.policy.engine import load_policy

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
