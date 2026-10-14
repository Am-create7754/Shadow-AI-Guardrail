"""Regression tests for the independent security review of the Phase 3 gateway."""

from __future__ import annotations

import asyncio
import random
import time
from pathlib import Path

import pytest

from app.providers.base import ProviderRequest, ProviderResponse
from evaluation import synth
from tests.api_helpers import PASSWORD, Gateway, gateway, gw

__all__ = ["gw"]


def _token() -> str:
    return synth.github_token(random.Random(9))


# 1. secrets in the model name -------------------------------------------------
def test_secret_in_model_name_rejected_and_never_stored(gw: Gateway) -> None:
    token = _token()
    r = gw.chat("dev1", "Project Nightingale budget", model=token)
    assert r.status_code == 400
    assert r.json()["error"]["type"] == "invalid_model"
    assert token not in r.text
    for who, path in (("admin", "/v1/admin/approvals"), ("dev1", "/v1/approvals")):
        listing = gw.client.get(path, headers=gw.h(who))
        assert token not in listing.text
        assert listing.json() == []
    assert gw.provider.calls == []


def test_approval_not_created_when_audit_fails(
    gw: Gateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def broken(*_: object, **__: object) -> None:
        raise RuntimeError("audit down")

    monkeypatch.setattr(gw.services.audit, "append", broken)
    r = gw.chat("dev1", "COMPANY CONFIDENTIAL merger memo")
    assert r.status_code == 503
    monkeypatch.undo()
    assert gw.client.get("/v1/admin/approvals", headers=gw.h("admin")).json() == []


# 2. separation of duties --------------------------------------------------------
def _create(gw: Gateway, by: str, username: str, role: str = "developer") -> str:
    r = gw.client.post(
        "/v1/admin/users",
        headers=gw.h(by),
        json={"username": username, "password": PASSWORD, "role": role},
    )
    assert r.status_code == 201
    login = gw.client.post("/v1/auth/login", json={"username": username, "password": PASSWORD})
    gw.tokens[username] = login.json()["access_token"]
    return str(r.json()["id"])


def _held(gw: Gateway, who: str) -> str:
    r = gw.chat(who, "Project Nightingale budget")
    assert r.status_code == 403
    return str(r.json()["error"]["details"]["approval_id"])


def test_admin_cannot_approve_requests_of_accounts_they_created(gw: Gateway) -> None:
    _create(gw, "admin", "sock")
    approval_id = _held(gw, "sock")
    r = gw.client.post(f"/v1/admin/approvals/{approval_id}/approve", headers=gw.h("admin"))
    assert r.status_code == 403
    assert (
        gw.client.post(
            f"/v1/admin/approvals/{approval_id}/approve", headers=gw.h("admin2")
        ).status_code
        == 200
    )


def test_admin_created_admin_cannot_approve_for_its_creator(gw: Gateway) -> None:
    _create(gw, "admin", "sockadmin", role="admin")
    _create(gw, "admin", "sockdev")
    own = _held(gw, "admin")
    sibling = _held(gw, "sockdev")
    for approval_id in (own, sibling):
        r = gw.client.post(f"/v1/admin/approvals/{approval_id}/approve", headers=gw.h("sockadmin"))
        assert r.status_code == 403


# 3. login lock-out denial of service --------------------------------------------
def test_failed_logins_from_one_client_do_not_lock_out_others(tmp_path: Path) -> None:
    with gateway(tmp_path, login_rate_limit_per_minute=3) as g:
        for _ in range(5):
            g.client.post("/v1/auth/login", json={"username": "admin2", "password": "x" * 12})
        g.services.login_limiter._buckets = {
            k: v
            for k, v in g.services.login_limiter._buckets.items()
            if not k.startswith("login-ip:")
        }  # simulate the real user arriving from a different address
        ok = g.client.post("/v1/auth/login", json={"username": "admin2", "password": PASSWORD})
        assert ok.status_code == 200


# 4. unexpected exceptions --------------------------------------------------------
class ExplodingProvider:
    name = "exploding"

    async def chat(self, request: ProviderRequest) -> ProviderResponse:
        raise RuntimeError("upstream said: " + request.messages[0].content)

    async def aclose(self) -> None:
        return None


def test_unexpected_provider_exception_is_contained(
    gw: Gateway, caplog: pytest.LogCaptureFixture
) -> None:
    gw.services.provider = ExplodingProvider()
    r = gw.chat("dev1", "harmless marker-xyz text")
    assert r.status_code == 502
    assert r.headers["x-request-id"]
    assert r.headers["cache-control"] == "no-store"
    assert "marker-xyz" not in r.text
    assert "marker-xyz" not in caplog.text
    events = gw.call(gw.services.audit.list_events, event_type="chat.provider_error")
    assert len(events) == 1


def test_unhandled_route_exception_keeps_headers_and_hides_message(
    gw: Gateway, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    def boom(*_: object, **__: object) -> None:
        raise ValueError("internal detail secret-marker-777")

    monkeypatch.setattr(gw.services.guard, "inspect_conversation", boom)
    r = gw.chat("dev1", "hi")
    assert r.status_code == 500
    assert r.headers["x-request-id"]
    assert r.headers["x-content-type-options"] == "nosniff"
    assert "secret-marker-777" not in r.text
    assert "secret-marker-777" not in caplog.text


# 5. secrets split across messages -------------------------------------------------
def test_token_split_across_messages_is_redacted(gw: Gateway) -> None:
    token = _token()
    msgs = [
        {"role": "user", "content": f"part one: {token[:16]}"},
        {"role": "user", "content": token[16:]},
    ]
    r = gw.chat("dev1", msgs)
    assert r.status_code == 200
    assert r.json()["guardrail"]["action"] == "REDACT"
    sent = " ".join(m.content for m in gw.provider.calls[0].messages)
    assert token[:16] not in sent
    assert token[16:] not in sent


def test_phrase_split_across_messages_still_needs_approval(gw: Gateway) -> None:
    msgs = [
        {"role": "user", "content": "status of Project"},
        {"role": "user", "content": "Nightingale please"},
    ]
    r = gw.chat("dev1", msgs)
    assert r.status_code == 403
    assert r.json()["error"]["type"] == "approval_required"
    assert gw.provider.calls == []


# 6. Argon2 must not block the event loop -----------------------------------------
def test_login_hashing_runs_off_the_event_loop(
    gw: Gateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []
    real = asyncio.to_thread

    async def spy(fn, *a, **k):  # type: ignore[no-untyped-def]
        calls.append(getattr(fn, "__name__", "?"))
        return await real(fn, *a, **k)

    monkeypatch.setattr(asyncio, "to_thread", spy)
    gw.client.post("/v1/auth/login", json={"username": "dev1", "password": PASSWORD})
    assert "verify" in calls


# 7. failed execution must not consume the approval --------------------------------
def test_approval_survives_provider_failure(gw: Gateway) -> None:
    r = gw.chat("dev1", "Project Nightingale budget", model="mock-error")
    approval_id = r.json()["error"]["details"]["approval_id"]
    gw.client.post(f"/v1/admin/approvals/{approval_id}/approve", headers=gw.h("admin"))
    first = gw.client.post(f"/v1/approvals/{approval_id}/execute", headers=gw.h("dev1"))
    assert first.status_code == 502
    status = gw.call(gw.services.approvals.get, approval_id).status.value
    assert status == "approved"
    assert gw.call(gw.services.approvals.review_messages, approval_id) is not None


# plausible items ---------------------------------------------------------------------
def test_expired_request_cannot_be_reviewed(gw: Gateway) -> None:
    approval_id = _held(gw, "dev1")
    from sqlalchemy import update

    from app.approvals.service import APPROVALS

    async def backdate() -> None:
        async with gw.services.approvals.engine.begin() as conn:
            await conn.execute(update(APPROVALS).values(expires_at="2000-01-01T00:00:00.000000Z"))

    gw.call(backdate)
    r = gw.client.get(f"/v1/admin/approvals/{approval_id}", headers=gw.h("admin"))
    assert r.json()["status"] == "expired"
    assert r.json()["messages"] is None


def test_last_active_admin_cannot_be_deactivated(gw: Gateway) -> None:
    r = gw.client.patch(
        f"/v1/admin/users/{gw.user_ids['admin2']}", headers=gw.h("admin"), json={"is_active": False}
    )
    assert r.status_code == 200
    # admin is now the only active admin: the service refuses to remove them
    from app.auth.service import AuthError

    with pytest.raises(AuthError, match="last active administrator"):
        gw.call(gw.services.auth.set_active, gw.user_ids["admin"], False)


def test_tokens_issued_before_deactivation_stay_dead_after_reactivation(gw: Gateway) -> None:
    old = gw.tokens["dev2"]
    uid = gw.user_ids["dev2"]
    time.sleep(1.1)  # token iat has one-second resolution
    gw.client.patch(f"/v1/admin/users/{uid}", headers=gw.h("admin"), json={"is_active": False})
    gw.client.patch(f"/v1/admin/users/{uid}", headers=gw.h("admin"), json={"is_active": True})
    assert gw.client.get("/v1/me", headers={"Authorization": f"Bearer {old}"}).status_code == 401
    fresh = gw.client.post("/v1/auth/login", json={"username": "dev2", "password": PASSWORD})
    assert fresh.status_code == 200


def test_logout_revokes_existing_sessions(gw: Gateway) -> None:
    time.sleep(1.1)
    assert gw.client.post("/v1/auth/logout", headers=gw.h("dev1")).status_code == 204
    assert gw.client.get("/v1/me", headers=gw.h("dev1")).status_code == 401


def test_unknown_field_names_not_echoed(gw: Gateway) -> None:
    token = _token()
    r = gw.client.post("/v1/inspect", headers=gw.h("dev1"), json={"text": "x", token: 1})
    assert r.status_code == 422
    assert token not in r.text


def test_api_key_count_is_limited(gw: Gateway) -> None:
    codes = [
        gw.client.post("/v1/me/api-keys", headers=gw.h("dev1"), json={"name": f"k{i}"}).status_code
        for i in range(22)
    ]
    assert codes.count(201) == 20
    assert codes[-1] == 400


def test_docs_csp_exemption_is_exact(gw: Gateway) -> None:
    assert "content-security-policy" in gw.client.get("/docsX").headers
