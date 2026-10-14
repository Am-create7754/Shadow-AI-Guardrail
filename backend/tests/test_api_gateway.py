"""Gateway behaviour: what reaches the provider, what is returned, what is audited."""

from __future__ import annotations

import json
import random
from pathlib import Path

import pytest

from evaluation import synth
from tests.api_helpers import Gateway, gateway, gw

__all__ = ["gw"]

PRIVATE_KEY = "-----BEGIN " + "PRIVATE KEY-----\n" + "MIIEvQ" * 12 + "\n-----END PRIVATE KEY-----"


def provider_text(g: Gateway) -> str:
    return json.dumps([[m.content for m in c.messages] for c in g.provider.calls])


# ------------------------------------------------------------------ inspect
def test_inspect_returns_findings_without_raw_value(gw: Gateway) -> None:
    token = synth.github_token(random.Random(1))
    r = gw.client.post("/v1/inspect", headers=gw.h("dev1"), json={"text": f"use {token} now"})
    assert r.status_code == 200
    body = r.json()
    assert body["action"] == "REDACT"
    assert body["sanitized_text"] == "use [GITHUB_TOKEN_1] now"
    assert token not in r.text
    assert gw.provider.calls == []  # inspect never contacts a provider


# --------------------------------------------------------------------- chat
def test_harmless_prompt_forwarded_unchanged(gw: Gateway) -> None:
    r = gw.chat("dev1", "How do I sort a list in Python?")
    assert r.status_code == 200
    body = r.json()
    assert body["object"] == "chat.completion"
    assert body["guardrail"]["action"] == "ALLOW"
    assert gw.provider.calls[0].messages[0].content == "How do I sort a list in Python?"


def test_secret_is_redacted_before_reaching_provider(gw: Gateway) -> None:
    r = gw.chat("dev1", "Fix this connection string: db_password=admin_pass_123")
    assert r.status_code == 200
    assert r.json()["guardrail"]["action"] == "REDACT"
    (call,) = gw.provider.calls
    assert call.messages[0].content == "Fix this connection string: db_password=[PASSWORD_1]"
    assert "admin_pass_123" not in provider_text(gw)
    assert "admin_pass_123" not in r.text


@pytest.mark.parametrize(
    "content",
    [PRIVATE_KEY, "card 4111 1111 1111 1111 declined", "aws_secret_access_key=" + "Ab1/" * 10],
)
def test_blocked_prompt_never_reaches_provider(gw: Gateway, content: str) -> None:
    r = gw.chat("dev1", content)
    assert r.status_code == 403
    err = r.json()["error"]
    assert err["type"] == "policy_blocked"
    assert gw.provider.calls == []
    assert "4111 1111" not in r.text
    assert "MIIEvQ" not in r.text


def test_conversation_redacted_consistently_across_messages(gw: Gateway) -> None:
    msgs = [
        {"role": "system", "content": "You are helpful. db_password=hunter2hunter"},
        {
            "role": "user",
            "content": "Is db_password=hunter2hunter strong? Also [PASSWORD_1] is text.",
        },
    ]
    r = gw.chat("dev1", msgs)
    assert r.status_code == 200
    sent = [m.content for m in gw.provider.calls[0].messages]
    assert sent[0] == "You are helpful. db_password=[PASSWORD_2]"
    assert sent[1] == "Is db_password=[PASSWORD_2] strong? Also [PASSWORD_1] is text."
    assert [m.role for m in gw.provider.calls[0].messages] == ["system", "user"]


def test_secret_in_any_role_is_inspected(gw: Gateway) -> None:
    msgs = [{"role": "assistant", "content": PRIVATE_KEY}, {"role": "user", "content": "ok?"}]
    assert gw.chat("dev1", msgs).status_code == 403
    assert gw.provider.calls == []


def test_streaming_rejected_explicitly(gw: Gateway) -> None:
    r = gw.chat("dev1", "hi", stream=True)
    assert r.status_code == 400
    assert r.json()["error"]["type"] == "streaming_not_supported"
    assert gw.provider.calls == []


def test_unknown_openai_fields_are_ignored_not_forwarded(gw: Gateway) -> None:
    r = gw.chat("dev1", "hi", user="someone", n=3, logit_bias={"1": 2})
    assert r.status_code == 200


@pytest.mark.parametrize(
    ("model", "status", "kind"),
    [
        ("mock-error", 502, "provider_unavailable"),
        ("mock-timeout", 504, "provider_timeout"),
        ("mock-ratelimit", 503, "provider_rate_limited"),
    ],
)
def test_provider_failures_mapped_and_audited(
    gw: Gateway, model: str, status: int, kind: str
) -> None:
    r = gw.chat("dev1", "hello", model=model)
    assert r.status_code == status
    assert r.json()["error"]["type"] == kind
    events = gw.call(gw.services.audit.list_events, event_type="chat.provider_error")
    assert len(events) == 1


def test_audit_failure_fails_closed(gw: Gateway, monkeypatch: pytest.MonkeyPatch) -> None:
    async def broken(*_: object, **__: object) -> None:
        raise RuntimeError("disk full")

    monkeypatch.setattr(gw.services.audit, "append", broken)
    r = gw.chat("dev1", "hello")
    assert r.status_code == 503
    assert r.json()["error"]["type"] == "audit_unavailable"
    assert gw.provider.calls == []


def test_audit_trail_has_no_raw_secrets_and_verifies(gw: Gateway) -> None:
    token = synth.github_token(random.Random(2))
    gw.chat("dev1", f"deploy with {token} please")
    gw.chat("dev1", PRIVATE_KEY)
    r = gw.client.get("/v1/admin/audit/events?limit=100", headers=gw.h("admin"))
    assert r.status_code == 200
    assert token not in r.text
    assert "MIIEvQ" not in r.text
    types = [e["event_type"] for e in r.json()]
    assert {"chat.forwarded", "chat.completed", "chat.blocked"} <= set(types)
    forwarded = next(e for e in r.json() if e["event_type"] == "chat.forwarded")
    assert forwarded["data"]["placeholders"] == ["[GITHUB_TOKEN_1]"]
    assert forwarded["actor"] == gw.user_ids["dev1"]
    verify = gw.client.get("/v1/admin/audit/verify", headers=gw.h("admin")).json()
    assert verify["ok"] is True


# ---------------------------------------------------------------- approvals
def _request_approval(gw: Gateway, who: str = "dev1") -> str:
    r = gw.chat(who, "STRICTLY CONFIDENTIAL: summarise the merger plan. db_password=hunter2hunter")
    assert r.status_code == 403
    err = r.json()["error"]
    assert err["type"] == "approval_required"
    return str(err["details"]["approval_id"])


def test_approval_flow_end_to_end(gw: Gateway) -> None:
    approval_id = _request_approval(gw)
    assert gw.provider.calls == []

    mine = gw.client.get("/v1/approvals", headers=gw.h("dev1")).json()
    assert [a["id"] for a in mine] == [approval_id]
    assert gw.client.get("/v1/approvals", headers=gw.h("dev2")).json() == []

    review = gw.client.get(f"/v1/admin/approvals/{approval_id}", headers=gw.h("admin"))
    assert review.status_code == 200
    assert "hunter2hunter" not in review.text  # only redacted text is ever held
    assert review.json()["messages"][0]["content"].endswith("db_password=[PASSWORD_1]")

    # Executing before approval is refused.
    early = gw.client.post(f"/v1/approvals/{approval_id}/execute", headers=gw.h("dev1"))
    assert early.status_code == 409

    ok = gw.client.post(
        f"/v1/admin/approvals/{approval_id}/approve",
        headers=gw.h("admin"),
        json={"note": "fine for the summary"},
    )
    assert ok.status_code == 200
    assert ok.json()["status"] == "approved"

    other = gw.client.post(f"/v1/approvals/{approval_id}/execute", headers=gw.h("dev2"))
    assert other.status_code == 409  # not the requester
    run = gw.client.post(f"/v1/approvals/{approval_id}/execute", headers=gw.h("dev1"))
    assert run.status_code == 200
    assert run.json()["guardrail"]["approval_id"] == approval_id
    (call,) = gw.provider.calls
    assert call.messages[0].content.endswith("db_password=[PASSWORD_1]")

    again = gw.client.post(f"/v1/approvals/{approval_id}/execute", headers=gw.h("dev1"))
    assert again.status_code == 409  # single use
    assert gw.call(gw.services.approvals.review_messages, approval_id) is None  # erased


def test_denied_request_cannot_execute_and_is_erased(gw: Gateway) -> None:
    approval_id = _request_approval(gw)
    r = gw.client.post(f"/v1/admin/approvals/{approval_id}/deny", headers=gw.h("admin"))
    assert r.json()["status"] == "denied"
    assert (
        gw.client.post(f"/v1/approvals/{approval_id}/execute", headers=gw.h("dev1")).status_code
        == 409
    )
    assert gw.call(gw.services.approvals.review_messages, approval_id) is None
    second = gw.client.post(f"/v1/admin/approvals/{approval_id}/approve", headers=gw.h("admin2"))
    assert second.status_code == 409


def test_admin_cannot_decide_own_request(gw: Gateway) -> None:
    approval_id = _request_approval(gw, "admin")
    r = gw.client.post(f"/v1/admin/approvals/{approval_id}/approve", headers=gw.h("admin"))
    assert r.status_code == 403
    assert (
        gw.client.post(
            f"/v1/admin/approvals/{approval_id}/approve", headers=gw.h("admin2")
        ).status_code
        == 200
    )


def test_expired_approval_cannot_execute(tmp_path: Path) -> None:
    with gateway(tmp_path, approval_ttl_minutes=1) as g:
        approval_id = _request_approval(g)
        g.client.post(f"/v1/admin/approvals/{approval_id}/approve", headers=g.h("admin"))
        from sqlalchemy import update

        from app.approvals.service import APPROVALS

        async def backdate() -> None:
            async with g.services.approvals.engine.begin() as conn:
                await conn.execute(
                    update(APPROVALS).values(expires_at="2000-01-01T00:00:00.000000Z")
                )

        g.call(backdate)
        r = g.client.post(f"/v1/approvals/{approval_id}/execute", headers=g.h("dev1"))
        assert r.status_code == 409
        assert "expired" in r.json()["error"]["message"]
        assert g.provider.calls == []


def test_held_ciphertext_is_encrypted_and_bound_to_row(gw: Gateway) -> None:
    a1 = _request_approval(gw)
    a2 = _request_approval(gw)
    from sqlalchemy import select, update

    from app.approvals.service import APPROVALS
    from app.crypto.aead import DecryptionError

    async def raw() -> dict[str, bytes]:
        async with gw.services.approvals.engine.connect() as conn:
            rows = (await conn.execute(select(APPROVALS.c.id, APPROVALS.c.ciphertext))).all()
        return {r.id: r.ciphertext for r in rows}

    blobs = gw.call(raw)
    assert b"CONFIDENTIAL" not in blobs[a1]  # encrypted at rest

    async def swap() -> None:  # copy row 2's ciphertext onto row 1
        async with gw.services.approvals.engine.begin() as conn:
            await conn.execute(
                update(APPROVALS).where(APPROVALS.c.id == a1).values(ciphertext=blobs[a2])
            )

    gw.call(swap)
    with pytest.raises(DecryptionError):
        gw.call(gw.services.approvals.review_messages, a1)
