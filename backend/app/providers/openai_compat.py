"""Adapter for OpenAI-compatible chat APIs (OpenAI, Anthropic's OpenAI-compatible
endpoint, Ollama, vLLM, ...).

Security properties
-------------------
* The API key is used only in the ``Authorization`` header of requests to the
  configured ``base_url``; it is held as ``SecretStr`` until the client is built
  and never appears in ``repr``, logs, errors or responses.
* Upstream error bodies are never forwarded: a client sees a fixed message plus,
  at most, the upstream error *code* if it is a short ``snake_case`` identifier.
* Responses are validated (Pydantic) and size-capped; anything malformed is a
  ``bad_response`` error rather than partially trusted data.
* Only transient failures are retried (429, 5xx, connection errors, timeouts),
  with exponential backoff and a capped ``Retry-After``.
* Redirects are not followed, so the key can never be sent to another host.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import re
from collections.abc import AsyncGenerator
from typing import Any

import httpx
from pydantic import BaseModel, ConfigDict, Field, SecretStr, ValidationError

from app.providers.base import ProviderError, ProviderRequest, ProviderResponse, ProviderUsage

_RETRY_STATUS = frozenset({429, 500, 502, 503, 504})
_ERROR_CODE_RE = re.compile(r"^[a-z][a-z0-9_]{1,63}$")
_FINISH_REASONS = frozenset({"stop", "length", "content_filter", "tool_calls", "function_call"})
_MAX_LINE_BYTES = 1_048_576  # one SSE line; longer means a broken or hostile upstream
_MAX_RETRY_AFTER = 5.0
# Only well-known upstream error identifiers are ever shown to clients: an
# arbitrary snake_case "code" could itself carry data.
_KNOWN_ERROR_CODES = frozenset(
    {
        "insufficient_quota", "credit_balance_exhausted", "billing_hard_limit_reached",
        "billing_not_active", "quota_exceeded", "rate_limit_exceeded", "model_not_found",
        "invalid_api_key", "context_length_exceeded", "invalid_request_error",
        "authentication_error", "permission_error", "not_found_error", "rate_limit_error",
        "overloaded_error", "api_error", "server_error", "not_found", "permission_denied",
        "invalid_argument", "resource_exhausted", "unauthenticated", "unavailable",
        "failed_precondition", "deadline_exceeded", "internal",
    }
)  # fmt: skip
# 429s that will not go away by waiting: retrying only wastes time.
_QUOTA_CODES = frozenset(
    {
        "insufficient_quota",
        "credit_balance_exhausted",
        "billing_hard_limit_reached",
        "billing_not_active",
        "quota_exceeded",
    }
)


class _Message(BaseModel):
    model_config = ConfigDict(extra="ignore")
    content: str | None = None


class _Choice(BaseModel):
    model_config = ConfigDict(extra="ignore")
    message: _Message
    finish_reason: str | None = None


class _Usage(BaseModel):
    model_config = ConfigDict(extra="ignore")
    prompt_tokens: int = Field(default=0, ge=0)
    completion_tokens: int = Field(default=0, ge=0)


class _Completion(BaseModel):
    model_config = ConfigDict(extra="ignore")
    model: str = ""
    choices: list[_Choice] = Field(min_length=1)
    usage: _Usage = Field(default_factory=_Usage)


class _Delta(BaseModel):
    model_config = ConfigDict(extra="ignore")
    content: str | None = None


class _ChunkChoice(BaseModel):
    model_config = ConfigDict(extra="ignore")
    delta: _Delta = Field(default_factory=_Delta)
    finish_reason: str | None = None


class _Chunk(BaseModel):
    model_config = ConfigDict(extra="ignore")
    choices: list[_ChunkChoice] = Field(default_factory=list)


def _safe_error_code(response: httpx.Response) -> str | None:
    """Extract an error identifier only if it is harmless (``snake_case``).

    Accepts OpenAI's ``{"error": {"code"|"type": ...}}`` and Google's list-wrapped
    ``[{"error": {"status": "NOT_FOUND"}}]``; free-text messages are never used.
    """
    try:
        body = response.json()
    except ValueError:
        return None
    if isinstance(body, list) and body:
        body = body[0]
    err = body.get("error") if isinstance(body, dict) else None
    if not isinstance(err, dict):
        return None
    for field in ("code", "type", "status"):
        value = err.get(field)
        if isinstance(value, str):
            value = value.lower() if field == "status" else value
            if _ERROR_CODE_RE.match(value) and value in _KNOWN_ERROR_CODES:
                return value
    return None


def _status_error(response: httpx.Response) -> ProviderError:
    status = response.status_code
    code = _safe_error_code(response)
    suffix = f" ({code})" if code else ""
    if status in (401, 403):
        return ProviderError("unavailable", f"provider rejected the gateway's credentials{suffix}")
    if status == 429 and code in _QUOTA_CODES:
        return ProviderError("quota_exhausted", f"provider account has no remaining quota{suffix}")
    if status == 429:
        return ProviderError("rate_limited", f"provider rate limit reached{suffix}")
    if status in (400, 404, 409, 413, 422):
        return ProviderError("bad_request", f"provider rejected the request{suffix}")
    if status >= 500:
        return ProviderError("unavailable", f"provider error (HTTP {status})")
    return ProviderError("bad_response", f"unexpected provider status {status}")


class OpenAICompatibleProvider:
    name = "openai"

    def __init__(
        self,
        *,
        base_url: str,
        api_key: SecretStr | None,
        timeout_seconds: float,
        max_retries: int = 2,
        max_output_chars: int = 200_000,
        total_timeout_seconds: float = 300.0,
        transport: httpx.AsyncBaseTransport | None = None,
        backoff_base: float = 0.5,
    ) -> None:
        headers = {"Accept": "application/json"}
        if api_key is not None:
            headers["Authorization"] = f"Bearer {api_key.get_secret_value()}"
        self._client = httpx.AsyncClient(
            base_url=base_url.rstrip("/") + "/",
            headers=headers,
            timeout=httpx.Timeout(timeout_seconds, connect=10.0),
            follow_redirects=False,
            transport=transport,
        )
        self._max_retries = max_retries
        self._max_output_chars = max_output_chars
        # Byte budget for everything read from the upstream (content, events, JSON).
        self._max_bytes = max_output_chars * 8 + 65_536
        self._total_timeout = total_timeout_seconds
        self._backoff = backoff_base

    def __repr__(self) -> str:
        return f"OpenAICompatibleProvider(base_url={str(self._client.base_url)!r})"

    @staticmethod
    def _payload(request: ProviderRequest, *, stream: bool) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "model": request.model,
            "messages": [{"role": m.role, "content": m.content} for m in request.messages],
            "stream": stream,
        }
        if request.temperature is not None:
            payload["temperature"] = request.temperature
        if request.max_tokens is not None:
            payload["max_tokens"] = request.max_tokens
        return payload

    async def _sleep_before_retry(self, attempt: int, response: httpx.Response | None) -> None:
        delay = self._backoff * (2**attempt)
        if response is not None:
            with contextlib.suppress(ValueError):
                delay = max(delay, float(response.headers.get("retry-after", "0")))
        await asyncio.sleep(min(delay, _MAX_RETRY_AFTER))

    async def _send(self, payload: dict[str, Any], *, stream: bool) -> httpx.Response:
        """POST with retries for transient failures; returns a 2xx response."""
        last: ProviderError | None = None
        for attempt in range(self._max_retries + 1):
            response: httpx.Response | None = None
            try:
                req = self._client.build_request("POST", "chat/completions", json=payload)
                response = await self._client.send(req, stream=stream)
            except httpx.TimeoutException:
                last = ProviderError("timeout", "provider timed out")
            except httpx.TransportError:
                last = ProviderError("unavailable", "could not reach provider")
            else:
                if response.is_success:
                    return response
                if stream:
                    await response.aread()
                await response.aclose()
                last = _status_error(response)
                if response.status_code not in _RETRY_STATUS or last.kind == "quota_exhausted":
                    raise last
            if attempt < self._max_retries:
                await self._sleep_before_retry(attempt, response)
        assert last is not None  # noqa: S101 - loop ran at least once
        raise last

    async def chat(self, request: ProviderRequest) -> ProviderResponse:
        try:
            async with asyncio.timeout(self._total_timeout):
                response = await self._send(self._payload(request, stream=False), stream=True)
                body = await self._read_capped(response)
        except TimeoutError:
            raise ProviderError("timeout", "provider exceeded the total time limit") from None
        try:
            completion = _Completion.model_validate_json(body)
        except ValidationError:
            raise ProviderError("bad_response", "provider returned a malformed response") from None
        choice = completion.choices[0]
        content = choice.message.content or ""
        if len(content) > self._max_output_chars:
            raise ProviderError("bad_response", "provider response too large")
        finish = choice.finish_reason if choice.finish_reason in _FINISH_REASONS else "stop"
        return ProviderResponse(
            content=content,
            model=request.model,  # the upstream's own label is not trusted or echoed
            finish_reason=finish or "stop",
            usage=ProviderUsage(completion.usage.prompt_tokens, completion.usage.completion_tokens),
        )

    async def _read_capped(self, response: httpx.Response) -> bytes:
        """Read a body, stopping as soon as it exceeds the byte budget."""
        chunks: list[bytes] = []
        total = 0
        try:
            async for chunk in response.aiter_bytes():
                total += len(chunk)
                if total > self._max_bytes:
                    raise ProviderError("bad_response", "provider response too large")
                chunks.append(chunk)
        except httpx.TimeoutException:
            raise ProviderError("timeout", "provider timed out") from None
        except httpx.TransportError:
            raise ProviderError("unavailable", "provider connection lost") from None
        finally:
            await response.aclose()
        return b"".join(chunks)

    async def _lines(self, response: httpx.Response) -> AsyncGenerator[str, None]:
        """Split a byte stream into lines with per-line, total-byte and total-time
        limits (``aiter_lines`` would buffer an endless line without bound)."""
        deadline = asyncio.get_running_loop().time() + self._total_timeout
        pending = b""
        total = 0
        async for chunk in response.aiter_bytes():
            total += len(chunk)
            if total > self._max_bytes:
                raise ProviderError("bad_response", "provider response too large")
            if asyncio.get_running_loop().time() > deadline:
                raise ProviderError("timeout", "provider exceeded the total time limit")
            pending += chunk
            *lines, pending = pending.split(b"\n")
            if len(pending) > _MAX_LINE_BYTES:
                raise ProviderError("bad_response", "provider sent an oversized stream line")
            for raw in lines:
                yield raw.rstrip(b"\r").decode("utf-8", "replace")
        if pending:
            yield pending.rstrip(b"\r").decode("utf-8", "replace")

    async def stream(self, request: ProviderRequest) -> AsyncGenerator[str, None]:
        """Parse an SSE stream of ``chat.completion.chunk`` objects into text deltas."""
        response = await self._send(self._payload(request, stream=True), stream=True)
        content_chars = 0
        try:
            async for line in self._lines(response):
                if not line.startswith("data:"):
                    continue  # comments, event names, keep-alives
                data = line[5:].strip()
                if data == "[DONE]":
                    return
                try:
                    obj = json.loads(data)
                except ValueError:
                    raise ProviderError(
                        "bad_response", "provider sent a malformed stream"
                    ) from None
                if isinstance(obj, dict) and "error" in obj:
                    raise ProviderError("unavailable", "provider reported an error mid-stream")
                try:
                    chunk = _Chunk.model_validate(obj)
                except ValidationError:
                    raise ProviderError(
                        "bad_response", "provider sent a malformed stream"
                    ) from None
                for choice in chunk.choices[:1]:
                    if choice.delta.content:
                        content_chars += len(choice.delta.content)
                        if content_chars > self._max_output_chars:
                            raise ProviderError("bad_response", "provider response too large")
                        yield choice.delta.content
        except httpx.TimeoutException:
            raise ProviderError("timeout", "provider timed out mid-stream") from None
        except httpx.TransportError:
            raise ProviderError("unavailable", "provider connection lost mid-stream") from None
        finally:
            await response.aclose()

    async def aclose(self) -> None:
        await self._client.aclose()
