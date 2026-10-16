"""Gateway behaviour for model output: redaction, blocking, code checks, streaming."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from typing import Any

from app.providers.base import ProviderError, ProviderRequest, ProviderResponse
from tests.api_helpers import Gateway, gw

__all__ = ["gw"]

PEM = "-----BEGIN " + "PRIVATE KEY-----\n" + "MIIEvQ" * 20 + "\n-----END PRIVATE KEY-----"
LEAK = "AK" + "IA" + "MOCKLEAKEXAMPLE7"


def events(response: Any) -> list[dict[str, Any] | str]:
    out: list[dict[str, Any] | str] = []
    for line in response.text.split("\n"):
        if line.startswith("data: "):
            data = line[6:]
            out.append(data if data == "[DONE]" else json.loads(data))
    return out


def streamed_text(evts: list[dict[str, Any] | str]) -> str:
    return "".join(
        e["choices"][0]["delta"].get("content", "")
        for e in evts
        if isinstance(e, dict) and "choices" in e
    )


def stream(g: Gateway, content: str, model: str = "mock-echo") -> Any:
    return g.client.post(
        "/v1/chat/completions",
        headers=g.h("dev1"),
        json={"model": model, "stream": True, "messages": [{"role": "user", "content": content}]},
    )


class ScriptedProvider:
    """Returns a fixed answer; can fail before or during streaming."""

    def __init__(
        self,
        answer: str,
        *,
        name: str = "mock",
        fail_at: int | None = None,
        fail_first: bool = False,
    ) -> None:
        self.name, self.answer, self.fail_at, self.fail_first = name, answer, fail_at, fail_first
        self.calls: list[ProviderRequest] = []

    async def chat(self, request: ProviderRequest) -> ProviderResponse:
        self.calls.append(request)
        if self.fail_first:
            raise ProviderError("unavailable", "upstream down")
        return ProviderResponse(self.answer, request.model)

    async def stream(self, request: ProviderRequest) -> AsyncIterator[str]:
        self.calls.append(request)
        if self.fail_first:
            raise ProviderError("unavailable", "upstream down")
        for i in range(0, len(self.answer), 5):
            if self.fail_at is not None and i >= self.fail_at:
                raise ProviderError("timeout", "upstream timed out mid-stream")
            yield self.answer[i : i + 5]

    async def aclose(self) -> None:
        return None


# ------------------------------------------------------------ complete answers
def test_secret_in_model_answer_is_redacted(gw: Gateway) -> None:
    r = gw.chat("dev1", "give me a key", model="mock-leak")
    assert r.status_code == 200
    body = r.json()
    assert LEAK not in r.text
    assert (
        body["choices"][0]["message"]["content"]
        == "Sure - use the key [AWS_ACCESS_KEY_1] in your config."
    )
    assert body["guardrail"]["output_inspected"] is True
    assert body["guardrail"]["output"]["entities"] == {"AWS_ACCESS_KEY": 1}


def test_private_key_in_answer_withholds_it(gw: Gateway) -> None:
    gw.services.provider = ScriptedProvider("Here:\n" + PEM)
    r = gw.chat("dev1", "help me")
    assert r.status_code == 502
    assert r.json()["error"]["type"] == "output_blocked"
    assert "MIIEvQ" not in r.text
    events_ = gw.call(gw.services.audit.list_events, event_type="chat.output_blocked")
    assert len(events_) == 1
    assert "MIIEvQ" not in json.dumps(events_[0].model_dump())


def test_insecure_code_annotated(gw: Gateway) -> None:
    r = gw.chat("dev1", "write a script", model="mock-code")
    assert r.status_code == 200
    rules = [f["rule_id"] for f in r.json()["guardrail"]["output"]["code_findings"]]
    assert rules == ["py-subprocess-shell", "py-eval-exec", "tls-verify-disabled"]
    done = gw.call(gw.services.audit.list_events, event_type="chat.completed")[0]
    assert done.data["code_findings"] == sorted(rules)


def test_approved_request_answer_is_inspected(gw: Gateway) -> None:
    r = gw.chat("dev1", "Project Nightingale budget", model="mock-leak")
    approval_id = r.json()["error"]["details"]["approval_id"]
    gw.client.post(f"/v1/admin/approvals/{approval_id}/approve", headers=gw.h("admin"))
    run = gw.client.post(f"/v1/approvals/{approval_id}/execute", headers=gw.h("dev1"))
    assert run.status_code == 200
    assert LEAK not in run.text
    assert run.json()["guardrail"]["output_inspected"] is True


def test_model_allow_list_applies_to_real_providers(gw: Gateway) -> None:
    gw.services.provider = ScriptedProvider("hi", name="openai")
    r = gw.chat("dev1", "hello", model="gpt-5-ultra-expensive")
    assert r.status_code == 400
    assert r.json()["error"]["type"] == "model_not_allowed"
    assert gw.services.provider.calls == []  # type: ignore[attr-defined]
    assert gw.chat("dev1", "hello", model="gpt-4o-mini").status_code == 200


# ------------------------------------------------------------------- streaming
def test_stream_format_and_redaction(gw: Gateway) -> None:
    r = stream(gw, "Fix db_password=hunter2hunter please")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/event-stream")
    assert r.headers["cache-control"] == "no-store"
    evts = events(r)
    assert evts[0]["choices"][0]["delta"] == {"role": "assistant"}  # type: ignore[index]
    assert evts[-1] == "[DONE]"
    final = evts[-2]
    assert final["choices"][0]["finish_reason"] == "stop"  # type: ignore[index]
    assert final["guardrail"]["output_inspected"] is True  # type: ignore[index]
    text = streamed_text(evts)
    assert "db_password=[PASSWORD_1]" in text
    assert "hunter2hunter" not in r.text


def test_stream_redacts_secret_split_across_chunks(gw: Gateway) -> None:
    r = stream(gw, "give me a key", model="mock-leak")  # mock streams 7-char chunks
    assert LEAK not in r.text
    assert LEAK[:8] not in r.text
    assert "[AWS_ACCESS_KEY_1]" in streamed_text(events(r))


def test_stream_blocks_private_key_mid_answer(gw: Gateway) -> None:
    gw.services.provider = ScriptedProvider("Intro sentence. " * 20 + PEM + " the end")
    r = stream(gw, "hi")
    assert r.status_code == 200  # already streaming when the key appears
    evts = events(r)
    err = next(e for e in evts if isinstance(e, dict) and "error" in e)
    assert err["error"]["type"] == "output_blocked"
    assert evts[-1] == "[DONE]"
    assert "MIIEvQ" not in r.text
    assert "BEGIN" not in streamed_text(evts)
    assert gw.call(gw.services.audit.list_events, event_type="chat.output_blocked")


def test_stream_provider_failure_before_first_chunk_is_http_error(gw: Gateway) -> None:
    gw.services.provider = ScriptedProvider("x", fail_first=True)
    r = stream(gw, "hi")
    assert r.status_code == 502
    assert r.json()["error"]["type"] == "provider_unavailable"


def test_stream_provider_failure_mid_stream_is_error_event(gw: Gateway) -> None:
    gw.services.provider = ScriptedProvider("word " * 200, fail_at=300)
    r = stream(gw, "hi")
    evts = events(r)
    err = next(e for e in evts if isinstance(e, dict) and "error" in e)
    assert err["error"]["type"] == "provider_timeout"
    assert evts[-1] == "[DONE]"
    assert gw.call(gw.services.audit.list_events, event_type="chat.provider_error")


def test_stream_audit_trail(gw: Gateway) -> None:
    stream(gw, "give me a key", model="mock-leak")
    done = gw.call(gw.services.audit.list_events, event_type="chat.completed")
    assert len(done) == 1
    assert done[0].data["stream"] is True
    assert done[0].data["output_entities"] == {"AWS_ACCESS_KEY": 1}
    assert LEAK not in json.dumps(done[0].model_dump())


def test_stream_ends_only_after_its_closing_audit_record(gw: Gateway) -> None:
    """Regression (CI): the closing record was written fire-and-forget, so on slow
    machines a client could read the audit log before it existed. Simulate a slow
    database for the closing events only."""
    import asyncio

    from app.api.deps import Services

    original = Services.record

    async def slow_record(self: Services, request: Any, event_type: str, *a: Any) -> None:
        if event_type.startswith(("chat.completed", "chat.output_blocked", "chat.provider")):
            await asyncio.sleep(0.5)
        await original(self, request, event_type, *a)

    Services.record = slow_record  # type: ignore[method-assign]
    try:
        stream(gw, "give me a key", model="mock-leak")
        done = gw.call(gw.services.audit.list_events, event_type="chat.completed")
    finally:
        Services.record = original  # type: ignore[method-assign]
    assert len(done) == 1
