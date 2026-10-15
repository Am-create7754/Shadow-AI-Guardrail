"""Read-only endpoints used by the dashboards: models, metrics, policy."""

from __future__ import annotations

from tests.api_helpers import Gateway, gw

__all__ = ["gw"]


def test_models_list_is_openai_shaped(gw: Gateway) -> None:
    r = gw.client.get("/v1/models", headers=gw.h("dev1"))
    assert r.status_code == 200
    body = r.json()
    assert body["object"] == "list"
    assert {"id": "mock-echo", "object": "model", "owned_by": "mock"} in body["data"]
    assert gw.client.get("/v1/models").status_code == 401


def test_metrics_reflect_decisions_without_text(gw: Gateway) -> None:
    gw.chat("dev1", "How do I sort a list?")
    gw.chat("dev1", "db_password=hunter2hunter fix this")
    gw.chat("dev1", "card 4111 1111 1111 1111")
    gw.chat("dev2", "STRICTLY CONFIDENTIAL merger memo")
    gw.chat("dev1", "give me a key", model="mock-leak")
    r = gw.client.get("/v1/admin/metrics?hours=24", headers=gw.h("admin"))
    assert r.status_code == 200
    m = r.json()
    assert m["actions"] == {"ALLOW": 2, "REDACT": 1, "REQUIRE_APPROVAL": 1, "BLOCK": 1}
    assert m["requests"] == 5
    assert m["protected_requests"] == 3
    assert m["active_users"] == 2
    assert dict(m["top_entities"])["PASSWORD"] == 1
    assert dict(m["output_entities"]) == {"AWS_ACCESS_KEY": 1}
    assert sum(sum(v for k, v in b.items() if k != "bucket") for b in m["timeline"]) == 5
    assert "hunter2hunter" not in r.text
    assert "4111" not in r.text


def test_metrics_and_policy_are_admin_only(gw: Gateway) -> None:
    for path in ("/v1/admin/metrics", "/v1/admin/policy"):
        assert gw.client.get(path, headers=gw.h("dev1")).status_code == 403
    policy = gw.client.get("/v1/admin/policy", headers=gw.h("admin")).json()
    assert policy["category_actions"]["SECRET"] == "REDACT"
    assert policy["output"]["code"]["mode"] == "annotate"


def test_metrics_window_validated(gw: Gateway) -> None:
    assert gw.client.get("/v1/admin/metrics?hours=0", headers=gw.h("admin")).status_code == 422


def test_chat_response_explains_what_was_forwarded(gw: Gateway) -> None:
    r = gw.chat("dev1", "Fix db_password=hunter2hunter please")
    g = r.json()["guardrail"]
    assert g["sanitized_messages"] == ["Fix db_password=[PASSWORD_1] please"]
    assert [f["entity_type"] for f in g["findings"]] == ["PASSWORD"]
    assert "hunter2hunter" not in r.text
    assert "start" not in g["findings"][0]


def test_blocked_response_has_findings_but_no_sanitized_text(gw: Gateway) -> None:
    r = gw.chat("dev1", "card 4111 1111 1111 1111")
    details = r.json()["error"]["details"]
    assert [f["entity_type"] for f in details["findings"]] == ["CREDIT_CARD"]
    assert "sanitized_messages" not in details


def test_inspect_only_is_not_counted_as_a_request(gw: Gateway) -> None:
    """Regression (Phase 5 review): dry runs inflated requests and entity counts."""
    for _ in range(3):
        body = {"text": "db_password=x9y8z7w6v5"}
        r = gw.client.post("/v1/inspect", headers=gw.h("dev1"), json=body)
        assert r.status_code == 200
    gw.chat("dev1", "db_password=hunter2hunter fix this")
    m = gw.client.get("/v1/admin/metrics?hours=24", headers=gw.h("admin")).json()
    assert m["requests"] == 1
    assert m["actions"]["REDACT"] == 1
    assert dict(m["top_entities"])["PASSWORD"] == 1
    assert m["inspections"] == 3
    assert m["truncated"] is False


def test_events_since_keeps_newest_and_reports_truncation(gw: Gateway) -> None:
    for i in range(5):
        gw.chat("dev1", f"How do I sort list {i}?")
    events, truncated = gw.call(gw.services.audit.events_since, "2000-01-01T00:00:00.000000Z",
                                limit=3)  # fmt: skip
    assert truncated is True
    assert len(events) == 3
    seqs = [e.seq for e in events]
    assert seqs == sorted(seqs)
    newest = gw.call(gw.services.audit.head)
    assert newest is not None
    assert seqs[-1] == newest[0]
    _, complete = gw.call(gw.services.audit.events_since, "2000-01-01T00:00:00.000000Z")
    assert complete is False


def test_public_explanations_do_not_reveal_value_length(gw: Gateway) -> None:
    """Regression (Phase 5 review): entropy explanations included the token length."""
    import random
    import string

    rng = random.Random(7)  # synthetic, generated at runtime (repo hygiene)
    token = "".join(rng.choices(string.ascii_letters + string.digits, k=40))
    r = gw.client.post("/v1/inspect", headers=gw.h("dev1"), json={"text": f"token {token}"})
    assert r.status_code == 200
    explanations = [f["explanation"] for f in r.json()["findings"]]
    assert explanations, "expected an entropy finding"
    assert not [e for e in explanations if "length" in e]
