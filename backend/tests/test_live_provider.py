"""Live tests against the real provider configured in backend/.env (OpenAI, Gemini, ...).

Skipped unless explicitly enabled - they cost money and need network access:

    $env:GUARDRAIL_LIVE_TESTS = "1"
    .venv\\Scripts\\python -m pytest -m live -q

Each test sends a handful of tiny requests (max 40 output tokens).
"""

from __future__ import annotations

import asyncio
import json
import os
from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.api.app import create_app
from app.auth.models import Role
from app.core.config import BACKEND_DIR, Environment, Settings
from app.providers.base import ChatMessage, ProviderRequest
from app.providers.factory import build_provider

pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(
        os.environ.get("GUARDRAIL_LIVE_TESTS") != "1",
        reason="set GUARDRAIL_LIVE_TESTS=1 to call the real provider",
    ),
]

PASSWORD = "live test passphrase 42"
MODEL = ""  # set from backend/.env in live_settings()


def live_settings(tmp_path: Path) -> Settings:
    base = Settings(_env_file=BACKEND_DIR / ".env")  # type: ignore[call-arg]
    if base.provider != "openai" or base.provider_api_key is None:
        pytest.skip("backend/.env does not configure GUARDRAIL_PROVIDER=openai with a key")
    global MODEL
    MODEL = base.provider_model_list[0]  # first allowed model, e.g. gpt-4o-mini or a Gemini model
    return base.model_copy(
        update={
            "environment": Environment.TEST,
            "database_url": "sqlite+aiosqlite:///" + (tmp_path / "live.db").as_posix(),
            "audit_anchor_path": tmp_path / "anchor.json",
        }
    )


@pytest.fixture
def live_client(tmp_path: Path) -> Iterator[tuple[TestClient, dict[str, str]]]:
    app = create_app(live_settings(tmp_path))
    with TestClient(app) as client:
        services = app.state.services
        user = client.portal.call(services.auth.create_user, "livedev", PASSWORD, Role.DEVELOPER)  # type: ignore[union-attr]
        token = services.auth.issue_token(user)[0]
        yield client, {"Authorization": f"Bearer {token}"}


def test_adapter_round_trip(tmp_path: Path) -> None:
    async def run() -> tuple[str, str]:
        p = build_provider(live_settings(tmp_path))
        req = ProviderRequest(
            MODEL, (ChatMessage("user", "Reply with exactly: pong"),), temperature=0, max_tokens=10
        )
        try:
            full = (await p.chat(req)).content
            streamed = "".join([d async for d in p.stream(req)])
        finally:
            await p.aclose()
        return full, streamed

    full, streamed = asyncio.run(run())
    assert "pong" in full.lower()
    assert "pong" in streamed.lower()


def test_secret_never_reaches_the_real_model(
    live_client: tuple[TestClient, dict[str, str]],
) -> None:
    client, h = live_client
    r = client.post(
        "/v1/chat/completions",
        headers=h,
        json={
            "model": MODEL,
            "temperature": 0,
            "max_tokens": 40,
            "messages": [
                {
                    "role": "user",
                    "content": "Repeat my config line exactly, nothing else: "
                    "db_password=hunter2hunter",
                }
            ],
        },
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["guardrail"]["action"] == "REDACT"
    assert "hunter2hunter" not in r.text
    assert "[PASSWORD_1]" in body["choices"][0]["message"]["content"]


def test_secret_in_real_answer_is_redacted(live_client: tuple[TestClient, dict[str, str]]) -> None:
    client, h = live_client
    example = "AK" + "IA" + "IOSFODNN7EXAMPLE"  # AWS's documented example key
    r = client.post(
        "/v1/chat/completions",
        headers=h,
        json={
            "model": MODEL,
            "temperature": 0,
            "max_tokens": 40,
            "messages": [
                {
                    "role": "user",
                    "content": "Print AWS's documented example access key ID (the one ending in "
                    "EXAMPLE). Output only the key.",
                }
            ],
        },
    )
    assert r.status_code == 200, r.text
    assert example not in r.text
    assert r.json()["guardrail"]["output_inspected"] is True


def test_real_streaming(live_client: tuple[TestClient, dict[str, str]]) -> None:
    client, h = live_client
    r = client.post(
        "/v1/chat/completions",
        headers=h,
        json={
            "model": MODEL,
            "stream": True,
            "temperature": 0,
            "max_tokens": 30,
            "messages": [{"role": "user", "content": "Count from one to five in words."}],
        },
    )
    assert r.status_code == 200
    events = [
        json.loads(line[6:])
        for line in r.text.split("\n")
        if line.startswith("data: ") and line != "data: [DONE]"
    ]
    text = "".join(e["choices"][0]["delta"].get("content", "") for e in events if "choices" in e)
    assert "three" in text.lower()
    assert events[-1]["guardrail"]["output_inspected"] is True


def test_model_allow_list(live_client: tuple[TestClient, dict[str, str]]) -> None:
    client, h = live_client
    r = client.post(
        "/v1/chat/completions",
        headers=h,
        json={"model": "gpt-4-32k", "messages": [{"role": "user", "content": "hi"}]},
    )
    assert r.status_code == 400
    assert r.json()["error"]["type"] == "model_not_allowed"
