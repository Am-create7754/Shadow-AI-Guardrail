"""Unit tests: AEAD, rate limiter, management CLI, provider mock, settings helpers."""

from __future__ import annotations

import asyncio
import io
from pathlib import Path

import pytest

from app.api.ratelimit import RateLimiter, retry_after_header
from app.crypto.aead import Aead, DecryptionError
from app.providers.base import ChatMessage, ProviderError, ProviderRequest
from app.providers.mock import MockProvider

KEY = b"m" * 32


# ------------------------------------------------------------------- AEAD
def test_aead_roundtrip_and_random_nonces() -> None:
    a = Aead(KEY, "approvals")
    c1, c2 = a.encrypt(b"hello", b"id-1"), a.encrypt(b"hello", b"id-1")
    assert c1 != c2  # fresh nonce every time
    assert a.decrypt(c1, b"id-1") == b"hello"


@pytest.mark.parametrize("mutate", ["flip", "truncate", "aad", "purpose", "key", "version"])
def test_aead_rejects_tampering(mutate: str) -> None:
    a = Aead(KEY, "approvals")
    blob = a.encrypt(b"confidential", b"id-1")
    aad = b"id-1"
    other = a
    if mutate == "flip":
        blob = blob[:-1] + bytes([blob[-1] ^ 1])
    elif mutate == "truncate":
        blob = blob[:10]
    elif mutate == "aad":
        aad = b"id-2"
    elif mutate == "purpose":
        other = Aead(KEY, "something-else")
    elif mutate == "key":
        other = Aead(b"n" * 32, "approvals")
    elif mutate == "version":
        blob = b"\x02" + blob[1:]
    with pytest.raises(DecryptionError):
        other.decrypt(blob, aad)


def test_aead_requires_strong_key() -> None:
    with pytest.raises(ValueError, match="32 bytes"):
        Aead(b"short", "x")


# ------------------------------------------------------------- rate limiter
def test_token_bucket_refills_over_time() -> None:
    now = [0.0]
    rl = RateLimiter(60, clock=lambda: now[0])  # 1 token / second, burst 60
    assert all(rl.hit("k") == 0 for _ in range(60))
    wait = rl.hit("k")
    assert wait == pytest.approx(1.0)
    assert retry_after_header(wait) == "1"
    now[0] += 1.0
    assert rl.hit("k") == 0
    assert rl.hit("other") == 0  # independent keys


def test_rate_limiter_memory_is_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.api import ratelimit

    monkeypatch.setattr(ratelimit, "MAX_KEYS", 100)
    now = [0.0]
    rl = RateLimiter(60, clock=lambda: now[0])
    for i in range(1000):
        now[0] += 0.001
        rl.hit(f"k{i}")
    assert len(rl._buckets) <= 100


# --------------------------------------------------------------- mock provider
def test_mock_provider_records_and_fails_on_demand() -> None:
    p = MockProvider()
    req = ProviderRequest("mock-echo", (ChatMessage("user", "hi [PASSWORD_1]"),))
    resp = asyncio.run(p.chat(req))
    assert "hi [PASSWORD_1]" in resp.content
    assert p.calls == [req]
    with pytest.raises(ProviderError) as exc:
        asyncio.run(p.chat(ProviderRequest("mock-timeout", req.messages)))
    assert exc.value.kind == "timeout"


# ---------------------------------------------------------------- manage CLI
def test_manage_cli_creates_user_and_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from app.api import manage
    from app.core import config

    monkeypatch.setenv("GUARDRAIL_ENVIRONMENT", "test")
    monkeypatch.setenv(
        "GUARDRAIL_DATABASE_URL", "sqlite+aiosqlite:///" + (tmp_path / "m.db").as_posix()
    )
    config.get_settings.cache_clear()
    try:
        monkeypatch.setattr("sys.stdin", io.StringIO("a long enough passphrase\n"))
        assert manage.main(["create-user", "opsadmin", "--role", "admin", "--password-stdin"]) == 0
        assert "created admin 'opsadmin'" in capsys.readouterr().out
        monkeypatch.setattr("sys.stdin", io.StringIO("short\n"))
        assert manage.main(["create-user", "weak", "--password-stdin"]) == 1
        assert manage.main(["create-api-key", "opsadmin", "--name", "ci"]) == 0
        out = capsys.readouterr()
        assert out.out.startswith("grk_")
        assert "cannot be shown again" in out.err
        assert manage.main(["create-api-key", "nobody"]) == 1
    finally:
        config.get_settings.cache_clear()
