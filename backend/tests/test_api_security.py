"""Authentication, authorisation and HTTP hardening of the gateway."""

from __future__ import annotations

import base64
import json
import random
import time
from pathlib import Path
from typing import Any

import jwt
import pytest
from fastapi.testclient import TestClient

from app.api.app import create_app
from app.auth.service import JWT_AUDIENCE, JWT_ISSUER
from app.core.config import Environment, Settings
from evaluation import synth
from tests.api_helpers import PASSWORD, Gateway, gateway, gw

__all__ = ["gw"]


def _claims(user_id: str, **over: Any) -> dict[str, Any]:
    now = int(time.time())
    base = {
        "sub": user_id,
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
        "iat": now,
        "nbf": now,
        "exp": now + 600,
        "jti": "x" * 32,
        "typ": "access",
    }
    return base | over


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


# ------------------------------------------------------------------- basics
def test_health_is_public_and_minimal(gw: Gateway) -> None:
    r = gw.client.get("/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}
    assert gw.client.get("/ready").json() == {"status": "ready"}


def test_security_headers_and_request_ids(gw: Gateway) -> None:
    a, b = gw.client.get("/health"), gw.client.get("/health")
    for r in (a, b):
        assert r.headers["x-content-type-options"] == "nosniff"
        assert r.headers["x-frame-options"] == "DENY"
        assert r.headers["cache-control"] == "no-store"
        assert "default-src 'none'" in r.headers["content-security-policy"]
    assert a.headers["x-request-id"] != b.headers["x-request-id"]


def test_client_supplied_request_id_is_not_trusted(gw: Gateway) -> None:
    r = gw.client.get("/health", headers={"X-Request-ID": "attacker-chosen"})
    assert r.headers["x-request-id"] != "attacker-chosen"


def test_unknown_route_returns_structured_404(gw: Gateway) -> None:
    r = gw.client.get("/nope")
    assert r.status_code == 404
    assert r.json()["error"]["type"] == "not_found"


# ---------------------------------------------------------------------- login
def test_login_success_and_failure_are_indistinguishable_for_unknown_users(gw: Gateway) -> None:
    ok = gw.client.post("/v1/auth/login", json={"username": "dev1", "password": PASSWORD})
    assert ok.status_code == 200
    assert ok.json()["token_type"] == "bearer"
    bad_pw = gw.client.post("/v1/auth/login", json={"username": "dev1", "password": "wrong" * 3})
    no_user = gw.client.post("/v1/auth/login", json={"username": "ghost", "password": "wrong" * 3})
    assert bad_pw.status_code == no_user.status_code == 401
    assert bad_pw.json()["error"]["message"] == no_user.json()["error"]["message"]


def test_failed_login_audit_does_not_record_attempted_username(gw: Gateway) -> None:
    gw.client.post("/v1/auth/login", json={"username": "MySecretPassw0rd!", "password": "x" * 12})
    events = gw.call(gw.services.audit.list_events, event_type="auth.login_failed")
    assert len(events) == 1
    assert events[0].actor == "anonymous"
    assert "MySecretPassw0rd" not in json.dumps(events[0].model_dump())


def test_login_rate_limited(tmp_path: Path) -> None:
    with gateway(tmp_path, login_rate_limit_per_minute=3) as g:
        codes = [
            g.client.post(
                "/v1/auth/login", json={"username": "dev1", "password": "bad" * 4}
            ).status_code
            for _ in range(5)
        ]
        assert codes[:3] == [401, 401, 401]
        assert codes[3] == 429
        r = g.client.post("/v1/auth/login", json={"username": "dev1", "password": PASSWORD})
        assert r.status_code == 429
        assert int(r.headers["retry-after"]) >= 1


def test_deactivated_user_cannot_login(gw: Gateway) -> None:
    gw.client.patch(
        f"/v1/admin/users/{gw.user_ids['dev2']}", headers=gw.h("admin"), json={"is_active": False}
    )
    r = gw.client.post("/v1/auth/login", json={"username": "dev2", "password": PASSWORD})
    assert r.status_code == 401


# --------------------------------------------------------------------- tokens
def test_missing_or_malformed_credentials(gw: Gateway) -> None:
    for headers in (
        {},
        {"Authorization": "Basic abc"},
        {"Authorization": "Bearer"},
        {"Authorization": "Bearer not.a.jwt"},
    ):
        r = gw.client.get("/v1/me", headers=headers)
        assert r.status_code == 401
        assert r.headers["www-authenticate"] == "Bearer"


def test_token_signed_with_other_key_rejected(gw: Gateway) -> None:
    forged = jwt.encode(_claims(gw.user_ids["admin"]), b"k" * 32, algorithm="HS256")
    assert gw.client.get("/v1/me", headers=_bearer(forged)).status_code == 401


def test_alg_none_token_rejected(gw: Gateway) -> None:
    def b64(obj: dict[str, Any]) -> str:
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()

    token = f"{b64({'alg': 'none', 'typ': 'JWT'})}.{b64(_claims(gw.user_ids['admin']))}."
    assert gw.client.get("/v1/me", headers=_bearer(token)).status_code == 401


@pytest.mark.parametrize(
    "over",
    [
        {"exp": int(time.time()) - 10},
        {"aud": "other"},
        {"iss": "evil"},
        {"typ": "refresh"},
        {"nbf": int(time.time()) + 3600},
    ],
)
def test_invalid_claims_rejected(gw: Gateway, over: dict[str, Any]) -> None:
    token = jwt.encode(
        _claims(gw.user_ids["dev1"], **over), gw.services.auth._jwt_key, algorithm="HS256"
    )
    assert gw.client.get("/v1/me", headers=_bearer(token)).status_code == 401


def test_role_claim_in_token_is_ignored(gw: Gateway) -> None:
    """Even a validly signed token cannot grant a role: the DB role is used."""
    token = jwt.encode(
        _claims(gw.user_ids["dev1"], role="admin", is_admin=True),
        gw.services.auth._jwt_key,
        algorithm="HS256",
    )
    assert gw.client.get("/v1/me", headers=_bearer(token)).json()["role"] == "developer"
    assert gw.client.get("/v1/admin/users", headers=_bearer(token)).status_code == 403


def test_deactivation_revokes_existing_tokens_immediately(gw: Gateway) -> None:
    assert gw.client.get("/v1/me", headers=gw.h("dev1")).status_code == 200
    gw.client.patch(
        f"/v1/admin/users/{gw.user_ids['dev1']}", headers=gw.h("admin"), json={"is_active": False}
    )
    assert gw.client.get("/v1/me", headers=gw.h("dev1")).status_code == 401


def test_admin_cannot_deactivate_self(gw: Gateway) -> None:
    r = gw.client.patch(
        f"/v1/admin/users/{gw.user_ids['admin']}", headers=gw.h("admin"), json={"is_active": False}
    )
    assert r.status_code == 400


# ------------------------------------------------------------------- API keys
def test_api_key_lifecycle(gw: Gateway) -> None:
    created = gw.client.post("/v1/me/api-keys", headers=gw.h("dev1"), json={"name": "laptop"})
    assert created.status_code == 201
    key = created.json()["key"]
    assert key.startswith("grk_")
    assert gw.client.get("/v1/me", headers=_bearer(key)).json()["username"] == "dev1"

    listing = gw.client.get("/v1/me/api-keys", headers=gw.h("dev1"))
    assert key not in listing.text
    assert "key_hash" not in listing.text

    events = gw.call(gw.services.audit.list_events, event_type="api_key.created")
    assert key not in json.dumps([e.model_dump() for e in events])

    key_id = created.json()["id"]
    assert gw.client.delete(f"/v1/me/api-keys/{key_id}", headers=gw.h("dev2")).status_code == 404
    assert gw.client.delete(f"/v1/me/api-keys/{key_id}", headers=gw.h("dev1")).status_code == 204
    assert gw.client.get("/v1/me", headers=_bearer(key)).status_code == 401


def test_tampered_or_guessed_api_keys_rejected(gw: Gateway) -> None:
    key = gw.client.post("/v1/me/api-keys", headers=gw.h("dev1"), json={"name": "k"}).json()["key"]
    tampered = key[:-1] + ("A" if key[-1] != "A" else "B")
    for candidate in (tampered, "grk_000000000000_" + "x" * 43, "grk_bad"):
        assert gw.client.get("/v1/me", headers=_bearer(candidate)).status_code == 401


def test_api_key_of_deactivated_user_rejected(gw: Gateway) -> None:
    key = gw.client.post("/v1/me/api-keys", headers=gw.h("dev2"), json={"name": "k"}).json()["key"]
    gw.client.patch(
        f"/v1/admin/users/{gw.user_ids['dev2']}", headers=gw.h("admin"), json={"is_active": False}
    )
    assert gw.client.get("/v1/me", headers=_bearer(key)).status_code == 401


# --------------------------------------------------------------- authorisation
ADMIN_ROUTES = [
    ("GET", "/v1/admin/approvals"),
    ("GET", "/v1/admin/approvals/abc"),
    ("POST", "/v1/admin/approvals/abc/approve"),
    ("POST", "/v1/admin/approvals/abc/deny"),
    ("GET", "/v1/admin/audit/events"),
    ("GET", "/v1/admin/audit/verify"),
    ("GET", "/v1/admin/users"),
    ("POST", "/v1/admin/users"),
    ("PATCH", "/v1/admin/users/abc"),
]


@pytest.mark.parametrize(("method", "path"), ADMIN_ROUTES)
def test_admin_routes_forbidden_for_developers(gw: Gateway, method: str, path: str) -> None:
    r = gw.client.request(method, path, headers=gw.h("dev1"), json={})
    assert r.status_code == 403
    assert gw.client.request(method, path, json={}).status_code == 401


def test_admin_creates_user_with_password_policy(gw: Gateway) -> None:
    weak = gw.client.post(
        "/v1/admin/users", headers=gw.h("admin"), json={"username": "newdev", "password": "short"}
    )
    assert weak.status_code == 400
    ok = gw.client.post(
        "/v1/admin/users",
        headers=gw.h("admin"),
        json={"username": "newdev", "password": "a much longer passphrase"},
    )
    assert ok.status_code == 201
    assert ok.json()["role"] == "developer"
    dup = gw.client.post(
        "/v1/admin/users",
        headers=gw.h("admin"),
        json={"username": "newdev", "password": "a much longer passphrase"},
    )
    assert dup.status_code == 400


def test_per_user_rate_limit(tmp_path: Path) -> None:
    with gateway(tmp_path, rate_limit_per_minute=3) as g:
        codes = [g.client.get("/v1/me", headers=g.h("dev1")).status_code for _ in range(5)]
        assert codes == [200, 200, 200, 429, 429]
        assert g.client.get("/v1/me", headers=g.h("dev2")).status_code == 200  # separate bucket


# ---------------------------------------------------------- input handling
def test_validation_errors_never_echo_input(gw: Gateway) -> None:
    token = synth.github_token(random.Random(3))
    r = gw.client.post(
        "/v1/chat/completions",
        headers=gw.h("dev1"),
        json={"model": "m", "messages": [{"role": "user", "content": "x"}], "temperature": token},
    )
    assert r.status_code == 422
    assert token not in r.text
    r = gw.client.post("/v1/inspect", headers=gw.h("dev1"), json={"text": 5, "extra": token})
    assert r.status_code == 422
    assert token not in r.text


def test_body_size_limit_by_content_length(tmp_path: Path) -> None:
    with gateway(tmp_path, max_body_bytes=2048) as g:
        r = g.client.post("/v1/inspect", headers=g.h("dev1"), json={"text": "a" * 5000})
        assert r.status_code == 413
        assert r.json()["error"]["type"] == "payload_too_large"


def test_body_size_limit_for_chunked_upload(tmp_path: Path) -> None:
    with gateway(tmp_path, max_body_bytes=2048) as g:

        def chunks():  # type: ignore[no-untyped-def]
            yield b'{"text": "'
            for _ in range(10):
                yield b"a" * 1000
            yield b'"}'

        headers = g.h("dev1") | {"Content-Type": "application/json"}
        r = g.client.post("/v1/inspect", headers=headers, content=chunks())
        assert r.status_code == 413


def test_conversation_size_limit(tmp_path: Path) -> None:
    with gateway(tmp_path, max_input_chars=1000) as g:
        msgs = [{"role": "user", "content": "a" * 600}, {"role": "user", "content": "b" * 600}]
        r = g.chat("dev1", msgs)
        assert r.status_code == 413
        assert g.provider.calls == []


# ----------------------------------------------------------------------- CORS
def test_cors_allows_only_configured_origins(gw: Gateway) -> None:
    pre = {
        "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "authorization,content-type",
    }
    ok = gw.client.options("/v1/inspect", headers={"Origin": "http://localhost:5173"} | pre)
    assert ok.headers.get("access-control-allow-origin") == "http://localhost:5173"
    evil = gw.client.options("/v1/inspect", headers={"Origin": "https://evil.example"} | pre)
    assert "access-control-allow-origin" not in evil.headers


def test_docs_disabled_in_production(tmp_path: Path) -> None:
    keys = {
        name: "k" + str(i) * 40
        for i, name in enumerate(
            ["fingerprint_key", "audit_key", "jwt_secret", "api_key_pepper", "data_key"]
        )
    }
    settings = Settings(
        environment=Environment.PRODUCTION,
        checkpoint_key_path=tmp_path / "k.pem",
        database_url="sqlite+aiosqlite:///" + (tmp_path / "p.db").as_posix(),
        **keys,
    )  # type: ignore[arg-type]
    client = TestClient(create_app(settings))  # no lifespan needed for routing
    assert client.get("/docs").status_code == 404
    assert client.get("/openapi.json").status_code == 404


def test_production_requires_gateway_keys(tmp_path: Path) -> None:
    from pydantic import ValidationError

    with pytest.raises(ValidationError, match="JWT_SECRET"):
        Settings(
            environment=Environment.PRODUCTION,
            fingerprint_key="f" * 40,  # type: ignore[arg-type]
            audit_key="a" * 40,
            checkpoint_key_path=tmp_path / "k.pem",
        )  # type: ignore[arg-type]


def test_all_keys_must_be_distinct() -> None:
    from pydantic import ValidationError

    with pytest.raises(ValidationError, match="different"):
        Settings(
            environment=Environment.TEST,
            jwt_secret="s" * 40,  # type: ignore[arg-type]
            data_key="s" * 40,
        )  # type: ignore[arg-type]


def test_root_redirects_to_docs_outside_production(gw: Gateway) -> None:
    r = gw.client.get("/", follow_redirects=False)
    assert r.status_code == 307
    assert r.headers["location"] == "/docs"
