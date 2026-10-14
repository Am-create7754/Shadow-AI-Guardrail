"""Construct the configured provider."""

from __future__ import annotations

from app.core.config import Settings
from app.providers.base import Provider
from app.providers.mock import MockProvider


def build_provider(settings: Settings) -> Provider:
    if settings.provider == "mock":
        return MockProvider()
    raise ValueError(f"unknown provider {settings.provider!r} (available: mock)")
