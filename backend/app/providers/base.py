"""Provider abstraction: the only path by which text leaves the gateway.

Security logic never lives in a provider. A provider receives messages that the
gateway has already inspected and redacted, and returns raw model output that
the gateway is responsible for handling. Adding a real provider therefore cannot
weaken any policy.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator
from dataclasses import dataclass, field
from typing import Literal, Protocol

Role = Literal["system", "user", "assistant"]


@dataclass(frozen=True)
class ChatMessage:
    role: Role
    content: str


@dataclass(frozen=True)
class ProviderRequest:
    model: str
    messages: tuple[ChatMessage, ...]
    temperature: float | None = None
    max_tokens: int | None = None


@dataclass(frozen=True)
class ProviderUsage:
    prompt_tokens: int = 0
    completion_tokens: int = 0


@dataclass(frozen=True)
class ProviderResponse:
    content: str
    model: str
    finish_reason: str = "stop"
    usage: ProviderUsage = field(default_factory=ProviderUsage)


class ProviderError(RuntimeError):
    """Upstream failure. ``kind`` drives the HTTP status; ``detail`` must be safe
    to return to the client (never upstream bodies or credentials)."""

    def __init__(self, kind: str, detail: str) -> None:
        super().__init__(detail)
        # "timeout" | "unavailable" | "rate_limited" | "bad_response" | "bad_request"
        self.kind = kind
        self.detail = detail


class Provider(Protocol):
    name: str

    async def chat(self, request: ProviderRequest) -> ProviderResponse: ...

    def stream(self, request: ProviderRequest) -> AsyncGenerator[str, None]:
        """Yield the answer as text deltas. Raise ProviderError on failure."""
        ...

    async def aclose(self) -> None: ...
