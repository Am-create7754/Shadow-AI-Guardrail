"""Deterministic mock provider: no network, no API key.

Behaviour (chosen by the requested model name):

* ``mock-echo`` (default for any other ``mock*`` model): replies with a short
  summary that quotes the last user message *as the provider received it*, so a
  demo shows exactly what left the gateway (placeholders instead of secrets).
* ``mock-error``    -> ProviderError("unavailable")
* ``mock-timeout``  -> ProviderError("timeout")
* ``mock-ratelimit``-> ProviderError("rate_limited")
* ``mock-leak``     -> a reply that itself contains a synthetic secret, for
  testing output handling (Phase 4).

Every request is recorded in ``calls`` so tests can prove what was - and was
not - forwarded.
"""

from __future__ import annotations

from app.providers.base import (
    ChatMessage,
    ProviderError,
    ProviderRequest,
    ProviderResponse,
    ProviderUsage,
)

_QUOTE_LIMIT = 300


class MockProvider:
    name = "mock"

    def __init__(self) -> None:
        self.calls: list[ProviderRequest] = []

    async def chat(self, request: ProviderRequest) -> ProviderResponse:
        self.calls.append(request)
        model = request.model
        if model == "mock-error":
            raise ProviderError("unavailable", "upstream provider unavailable")
        if model == "mock-timeout":
            raise ProviderError("timeout", "upstream provider timed out")
        if model == "mock-ratelimit":
            raise ProviderError("rate_limited", "upstream provider rate limit reached")
        if model == "mock-leak":
            # Assembled at runtime: a synthetic, AWS-shaped example value.
            leaked = "AK" + "IA" + "MOCKLEAKEXAMPLE7"
            content = f"Sure - use the key {leaked} in your config."
        else:
            last_user = next(
                (m for m in reversed(request.messages) if m.role == "user"),
                ChatMessage("user", ""),
            )
            quoted = last_user.content[:_QUOTE_LIMIT]
            more = "..." if len(last_user.content) > _QUOTE_LIMIT else ""
            content = (
                f"[mock model] I received {len(request.messages)} message(s). "
                f'Your last message, as delivered to me: "{quoted}{more}"'
            )
        prompt_tokens = sum(len(m.content.split()) for m in request.messages)
        return ProviderResponse(
            content=content,
            model=model,
            usage=ProviderUsage(prompt_tokens, len(content.split())),
        )

    async def aclose(self) -> None:
        return None
