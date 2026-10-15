"""Regression tests for the independent security review of Phase 4 (output path)."""

from __future__ import annotations

import asyncio
import random
import string
import time
from pathlib import Path

import httpx
import pytest
from pydantic import SecretStr, ValidationError

from app.core.config import Environment, Settings
from app.output.code_checks import check_code
from app.output.inspector import OutputInspector, StreamGuard
from app.policy.engine import load_policy
from app.policy.models import CodeCheckMode, CodePolicy, OutputAction
from app.providers.base import ChatMessage, ProviderError, ProviderRequest
from app.providers.openai_compat import OpenAICompatibleProvider
from evaluation import synth


@pytest.fixture(scope="module")
def ins(settings: Settings) -> OutputInspector:
    return OutputInspector(load_policy(settings.policy_path), settings)


@pytest.fixture(scope="module")
def ins_block(settings: Settings) -> OutputInspector:
    policy = load_policy(settings.policy_path)
    out = policy.output.model_copy(update={"code": CodePolicy(mode=CodeCheckMode.BLOCK)})
    return OutputInspector(policy.model_copy(update={"output": out}), settings)


def stream(ins: OutputInspector, text: str, size: int) -> tuple[str, StreamGuard]:
    g = StreamGuard(ins, ins.allocator([]))
    parts = []
    for i in range(0, len(text), size):
        parts.append(g.feed(text[i : i + size]))
        if g.blocked:
            break
    parts.append(g.finish())
    return "".join(parts), g


# 1. streaming CPU cost -------------------------------------------------------------
def test_long_token_run_streams_in_bounded_time(ins: OutputInspector) -> None:
    blob = "".join(
        random.Random(1).choice(string.ascii_letters + string.digits) for _ in range(20_000)
    )
    t0 = time.perf_counter()
    _, g = stream(ins, "here: " + blob + " end", 4)
    assert time.perf_counter() - t0 < 10
    assert g.blocked  # a 20k unbroken run exceeds the held-text cap: fail closed


def test_long_prose_streams_fast_in_tiny_chunks(ins: OutputInspector) -> None:
    text = "The quick brown fox jumps over the lazy dog. " * 2_000  # 90k chars
    t0 = time.perf_counter()
    out, _ = stream(ins, text, 1)
    assert out == text
    assert time.perf_counter() - t0 < 20


def test_block_mode_long_code_streams_in_bounded_time(ins_block: OutputInspector) -> None:
    block = "```sql\n" + "SELECT id, name FROM users WHERE active = 1;\n" * 200 + "```\n"
    t0 = time.perf_counter()
    out, g = stream(ins_block, block * 5, 3)
    assert time.perf_counter() - t0 < 20
    assert not g.blocked
    assert out == block * 5


# 2. candidate cap must fail closed on output too ------------------------------------
def test_truncated_output_scan_blocks(ins: OutputInspector) -> None:
    text = " ".join(f"u{i}@example.com" for i in range(5_100)) + " Card: 4111 1111 1111 1111"
    out = ins.inspect(text, ins.allocator([]))
    assert out.action is OutputAction.BLOCK
    assert "4111 1111" not in out.text


# 3. repeated secrets while streaming -------------------------------------------------
def test_stream_redacts_later_repeat_of_detected_secret(ins: OutputInspector) -> None:
    secret = "Tr0ub4dor&3xQ!"
    text = f"password={secret} " + "filler words here. " * 20 + f"login with {secret} now"
    out, _ = stream(ins, text, 3)
    assert secret not in out
    assert out == ins.inspect(text, ins.allocator([])).text


# 4. long secret with non-token punctuation ----------------------------------------------
def test_stream_never_releases_prefix_of_long_url_password(ins: OutputInspector) -> None:
    password = "Ab9!" * 64
    text = f"postgres://admin:{password}@db.internal.example/app ok"
    out, _ = stream(ins, text, 1)
    assert "Ab9!Ab9!" not in out
    assert "[CONNECTION_PASSWORD_1]" in out


# 5. code-fence handling -------------------------------------------------------------------
@pytest.mark.parametrize(
    "answer",
    [
        "Run this:\n```python\nimport os\nos.system(input())\n",  # unclosed final fence
        "Use ``` to fence code. Then:\n```python\neval(input())\n```\n",  # stray inline ```
        "~~~python\nos.system(cmd)\n~~~\n",  # tilde fence
    ],
)
def test_code_block_bypasses_closed(ins_block: OutputInspector, answer: str) -> None:
    assert check_code(answer), answer
    assert ins_block.inspect(answer, ins_block.allocator([])).action is OutputAction.BLOCK
    out, g = stream(ins_block, answer, 4)
    assert g.blocked
    assert "system(" not in out
    assert "eval(" not in out


# 8. base URL validation ---------------------------------------------------------------------
@pytest.mark.parametrize(
    "url",
    [
        "http://localhost.evil.example/v1",
        "http://localhost@evil.example/v1",
        "http://127.0.0.1.nip.io/v1",
        "https://user:pw@api.example.com/v1",
        "ftp://localhost/v1",
    ],
)
def test_lookalike_local_urls_rejected(url: str) -> None:
    with pytest.raises(ValidationError):
        Settings(
            environment=Environment.TEST,
            provider="openai",
            provider_base_url=url,
            provider_api_key=SecretStr("k" * 40),
        )


@pytest.mark.parametrize(
    "url", ["http://localhost:11434/v1", "http://127.0.0.1:8080/v1", "http://[::1]:11434/v1"]
)
def test_real_local_urls_accepted_without_key(url: str) -> None:
    assert Settings(environment=Environment.TEST, provider="openai", provider_base_url=url)


# 9. low severity ----------------------------------------------------------------------------
def test_literal_placeholder_in_stream_is_reserved(ins: OutputInspector) -> None:
    text = "Placeholders look like [EMAIL_1] in our docs. Contact a.b@example.com today. " * 2
    out, _ = stream(ins, text, 5)
    assert out == ins.inspect(text, ins.allocator([])).text
    assert "[EMAIL_2]" in out


def _adapter(handler: object, **kw: object) -> OpenAICompatibleProvider:
    return OpenAICompatibleProvider(
        base_url="https://api.example.test/v1",
        api_key=SecretStr("sk-" + "x" * 40),
        timeout_seconds=5,
        transport=httpx.MockTransport(handler),  # type: ignore[arg-type]
        backoff_base=0.0,
        **kw,
    )  # type: ignore[arg-type]


REQ = ProviderRequest("m", (ChatMessage("user", "hi"),))


def test_unknown_upstream_error_codes_not_echoed() -> None:
    p = _adapter(lambda r: httpx.Response(400, json={"error": {"code": "user_said_hunter2"}}))
    with pytest.raises(ProviderError) as exc:
        asyncio.run(p.chat(REQ))
    assert "hunter2" not in exc.value.detail


def test_upstream_model_and_finish_reason_not_trusted() -> None:
    body = {
        "model": "evil db_password=leak123",
        "choices": [{"message": {"content": "ok"}, "finish_reason": "x" * 50 + " secret"}],
    }
    resp = asyncio.run(_adapter(lambda r: httpx.Response(200, json=body)).chat(REQ))
    assert resp.model == "m"
    assert resp.finish_reason == "stop"


# 7. adapter resource limits -------------------------------------------------------------------
def test_huge_non_stream_body_rejected_without_full_read() -> None:
    p = _adapter(lambda r: httpx.Response(200, content=b"x" * 30_000_000), max_output_chars=1000)
    with pytest.raises(ProviderError, match="too large"):
        asyncio.run(p.chat(REQ))


def test_stream_byte_cap_counts_non_content_events() -> None:
    noise = b"".join(b": ping\n\n" for _ in range(200_000))
    p = _adapter(lambda r: httpx.Response(200, content=noise), max_output_chars=1000)

    async def drain() -> None:
        async for _ in p.stream(REQ):
            pass

    with pytest.raises(ProviderError, match="too large"):
        asyncio.run(drain())


def test_single_giant_stream_line_rejected() -> None:
    p = _adapter(
        lambda r: httpx.Response(200, content=b"data: " + b"x" * 5_000_000), max_output_chars=1000
    )

    async def drain() -> None:
        async for _ in p.stream(REQ):
            pass

    with pytest.raises(ProviderError):
        asyncio.run(drain())


def test_total_deadline_stops_slow_drip() -> None:
    async def slow_body():  # type: ignore[no-untyped-def]
        for _ in range(100):
            await asyncio.sleep(0.05)
            yield b": ping\n\n"

    p = _adapter(lambda r: httpx.Response(200, content=slow_body()), total_timeout_seconds=0.3)

    async def drain() -> None:
        async for _ in p.stream(REQ):
            pass

    t0 = time.perf_counter()
    with pytest.raises(ProviderError) as exc:
        asyncio.run(drain())
    assert exc.value.kind == "timeout"
    assert time.perf_counter() - t0 < 3


# 6. client disconnect must still produce an audit record and not break the DB ------------------
def test_stream_disconnect_is_audited_and_db_stays_healthy(tmp_path: Path) -> None:
    from tests.api_helpers import gateway

    with gateway(tmp_path) as g:
        with g.client.stream(
            "POST",
            "/v1/chat/completions",
            headers=g.h("dev1"),
            json={
                "model": "mock-echo",
                "stream": True,
                "messages": [{"role": "user", "content": "x " * 400}],
            },
        ) as r:
            next(r.iter_lines())  # read one event, then hang up
        time.sleep(0.5)
        for _ in range(3):
            assert g.client.get("/v1/me", headers=g.h("dev1")).status_code == 200
        types = [e.event_type for e in g.call(g.services.audit.list_events, limit=50)]
        assert types.count("chat.forwarded") == 1
        assert any(t in ("chat.completed", "chat.stream_aborted") for t in types)
        assert g.call(g.services.audit.verify).ok


def test_execute_rechecks_model_allow_list(tmp_path: Path) -> None:
    from tests.api_helpers import gateway

    with gateway(tmp_path) as g:
        r = g.chat("dev1", "Project Nightingale budget", model="mock-echo")
        approval_id = r.json()["error"]["details"]["approval_id"]
        g.client.post(f"/v1/admin/approvals/{approval_id}/approve", headers=g.h("admin"))
        g.services.provider.name = "openai"  # type: ignore[misc]  # provider switched since
        run = g.client.post(f"/v1/approvals/{approval_id}/execute", headers=g.h("dev1"))
        assert run.status_code == 400
        assert run.json()["error"]["type"] == "model_not_allowed"


def test_synth_secret_sanity() -> None:  # keeps the synth import meaningful
    assert synth.github_token(random.Random(0)).startswith("gh")
