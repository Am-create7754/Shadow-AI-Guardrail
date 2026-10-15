"""OpenAI-compatible adapter against a simulated upstream (httpx.MockTransport)."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Callable

import httpx
import pytest
from pydantic import SecretStr

from app.providers.base import ChatMessage, ProviderError, ProviderRequest
from app.providers.openai_compat import OpenAICompatibleProvider

FAKE_KEY = "sk-test-" + "x" * 40  # not a real credential
REQ = ProviderRequest("gpt-4o-mini", (ChatMessage("user", "hello"),), temperature=0, max_tokens=9)
SECRET_MARKER = "upstream-body-secret-marker"


def completion(content: str = "hi there", model: str = "gpt-4o-mini") -> dict[str, object]:
    return {
        "id": "x",
        "object": "chat.completion",
        "model": model,
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": content},
                "finish_reason": "stop",
            }
        ],
        "usage": {"prompt_tokens": 3, "completion_tokens": 2},
    }


def provider(
    handler: Callable[[httpx.Request], httpx.Response], **kw: object
) -> OpenAICompatibleProvider:
    return OpenAICompatibleProvider(
        base_url="https://api.example.test/v1",
        api_key=SecretStr(FAKE_KEY),
        timeout_seconds=5,
        transport=httpx.MockTransport(handler),
        backoff_base=0.0,
        **kw,  # type: ignore[arg-type]
    )


def run(coro: object) -> object:
    return asyncio.run(coro)  # type: ignore[arg-type]


def test_success_and_request_shape() -> None:
    seen: list[httpx.Request] = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(req)
        return httpx.Response(200, json=completion())

    p = provider(handler)
    resp = run(p.chat(REQ))
    assert resp.content == "hi there"  # type: ignore[attr-defined]
    assert resp.usage.prompt_tokens == 3  # type: ignore[attr-defined]
    (req,) = seen
    assert str(req.url) == "https://api.example.test/v1/chat/completions"
    assert req.headers["authorization"] == f"Bearer {FAKE_KEY}"
    body = json.loads(req.content)
    assert body == {
        "model": "gpt-4o-mini",
        "messages": [{"role": "user", "content": "hello"}],
        "stream": False,
        "temperature": 0,
        "max_tokens": 9,
    }


def test_key_never_in_repr() -> None:
    p = provider(lambda r: httpx.Response(200, json=completion()))
    assert FAKE_KEY not in repr(p)


@pytest.mark.parametrize(
    ("status", "kind", "calls"),
    [
        (401, "unavailable", 1),
        (403, "unavailable", 1),
        (400, "bad_request", 1),
        (404, "bad_request", 1),
        (500, "unavailable", 3),
        (503, "unavailable", 3),
        (429, "rate_limited", 3),
    ],
)
def test_status_mapping_and_retries(status: int, kind: str, calls: int) -> None:
    count = 0

    def handler(req: httpx.Request) -> httpx.Response:
        nonlocal count
        count += 1
        return httpx.Response(status, json={"error": {"message": SECRET_MARKER, "code": "x_y"}})

    with pytest.raises(ProviderError) as exc:
        run(provider(handler).chat(REQ))
    assert exc.value.kind == kind
    assert count == calls
    assert SECRET_MARKER not in exc.value.detail  # upstream bodies are never echoed


def test_quota_exhausted_is_not_retried() -> None:
    count = 0

    def handler(req: httpx.Request) -> httpx.Response:
        nonlocal count
        count += 1
        return httpx.Response(429, json={"error": {"code": "insufficient_quota"}})

    with pytest.raises(ProviderError) as exc:
        run(provider(handler).chat(REQ))
    assert exc.value.kind == "quota_exhausted"
    assert count == 1


def test_transient_failure_then_success() -> None:
    replies = iter(
        [
            httpx.Response(503),
            httpx.Response(429, headers={"retry-after": "0"}),
            httpx.Response(200, json=completion("recovered")),
        ]
    )
    resp = run(provider(lambda r: next(replies)).chat(REQ))
    assert resp.content == "recovered"  # type: ignore[attr-defined]


def test_unsafe_error_codes_are_not_reflected() -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(400, json={"error": {"code": "Bad Code <script>", "type": "x" * 99}})

    with pytest.raises(ProviderError) as exc:
        run(provider(handler).chat(REQ))
    assert exc.value.detail == "provider rejected the request"


def test_timeout_and_connection_errors() -> None:
    def timeout(req: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("slow", request=req)

    def refused(req: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused " + SECRET_MARKER, request=req)

    with pytest.raises(ProviderError) as exc:
        run(provider(timeout).chat(REQ))
    assert exc.value.kind == "timeout"
    with pytest.raises(ProviderError) as exc2:
        run(provider(refused).chat(REQ))
    assert exc2.value.kind == "unavailable"
    assert SECRET_MARKER not in exc2.value.detail


@pytest.mark.parametrize(
    "body",
    [
        b"not json",
        b"{}",
        json.dumps({"choices": []}).encode(),
        json.dumps({"choices": [{"message": {"content": 5}}]}).encode(),
    ],
)
def test_malformed_responses_rejected(body: bytes) -> None:
    with pytest.raises(ProviderError) as exc:
        run(provider(lambda r: httpx.Response(200, content=body)).chat(REQ))
    assert exc.value.kind == "bad_response"


def test_oversized_response_rejected() -> None:
    p = provider(lambda r: httpx.Response(200, json=completion("x" * 5000)), max_output_chars=1000)
    with pytest.raises(ProviderError, match="too large"):
        run(p.chat(REQ))


def test_redirects_are_not_followed() -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(307, headers={"location": "https://evil.example/steal"})

    with pytest.raises(ProviderError) as exc:
        run(provider(handler).chat(REQ))
    assert exc.value.kind == "bad_response"


def test_null_content_becomes_empty_string() -> None:
    body = completion()
    body["choices"][0]["message"]["content"] = None  # type: ignore[index]
    assert run(provider(lambda r: httpx.Response(200, json=body)).chat(REQ)).content == ""  # type: ignore[attr-defined]


# --------------------------------------------------------------------- streaming
def sse(*events: object) -> bytes:
    lines = []
    for e in events:
        lines.append(e if isinstance(e, str) else "data: " + json.dumps(e))
    return ("\n\n".join(lines) + "\n\n").encode()


def delta(text: str) -> dict[str, object]:
    return {"choices": [{"index": 0, "delta": {"content": text}, "finish_reason": None}]}


async def collect(p: OpenAICompatibleProvider) -> list[str]:
    return [d async for d in p.stream(REQ)]


def test_stream_parses_deltas_and_ignores_noise() -> None:
    body = sse(
        ": keep-alive",
        "event: message",
        {"choices": [{"delta": {"role": "assistant"}}]},
        delta("Hel"),
        delta("lo"),
        {"choices": []},
        "data: [DONE]",
        delta("after done"),
    )
    seen: list[httpx.Request] = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(req)
        return httpx.Response(200, content=body, headers={"content-type": "text/event-stream"})

    assert run(collect(provider(handler))) == ["Hel", "lo"]
    assert json.loads(seen[0].content)["stream"] is True


@pytest.mark.parametrize(
    ("events", "kind"),
    [
        (("data: {broken",), "bad_response"),
        (({"error": {"message": SECRET_MARKER}},), "unavailable"),
        (({"choices": "nope"},), "bad_response"),
    ],
)
def test_stream_errors(events: tuple[object, ...], kind: str) -> None:
    body = sse(delta("ok"), *events)
    p = provider(lambda r: httpx.Response(200, content=body))
    with pytest.raises(ProviderError) as exc:
        run(collect(p))
    assert exc.value.kind == kind
    assert SECRET_MARKER not in exc.value.detail


def test_stream_size_cap() -> None:
    body = sse(*[delta("x" * 400) for _ in range(5)])
    p = provider(lambda r: httpx.Response(200, content=body), max_output_chars=1000)
    with pytest.raises(ProviderError, match="too large"):
        run(collect(p))


def test_stream_http_error_before_body() -> None:
    p = provider(lambda r: httpx.Response(401, json={"error": {"message": SECRET_MARKER}}))
    with pytest.raises(ProviderError) as exc:
        run(collect(p))
    assert exc.value.kind == "unavailable"


def test_google_style_error_list_yields_safe_code() -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(
            404, json=[{"error": {"code": 404, "status": "NOT_FOUND", "message": SECRET_MARKER}}]
        )

    with pytest.raises(ProviderError) as exc:
        run(provider(handler).chat(REQ))
    assert exc.value.kind == "bad_request"
    assert exc.value.detail == "provider rejected the request (not_found)"
    assert SECRET_MARKER not in exc.value.detail
