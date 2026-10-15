"""Construct the configured provider."""

from __future__ import annotations

from app.core.config import Settings
from app.providers.base import Provider
from app.providers.mock import MockProvider
from app.providers.openai_compat import OpenAICompatibleProvider


def build_provider(settings: Settings) -> Provider:
    if settings.provider == "mock":
        return MockProvider()
    if settings.provider == "openai":
        return OpenAICompatibleProvider(
            base_url=settings.provider_base_url,
            api_key=settings.provider_api_key,
            timeout_seconds=settings.provider_timeout_seconds,
            max_retries=settings.provider_max_retries,
            max_output_chars=settings.provider_max_output_chars,
            total_timeout_seconds=settings.provider_total_timeout_seconds,
        )
    raise ValueError(f"unknown provider {settings.provider!r} (available: mock, openai)")
