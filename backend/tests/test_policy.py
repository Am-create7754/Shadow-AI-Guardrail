from __future__ import annotations

import random
import time
from pathlib import Path

import pytest
from pydantic import ValidationError

from app.core.config import Settings
from app.guardrail import Guardrail
from app.policy.engine import PolicyEngine, build_detection_engine, load_policy, risk_score
from app.policy.models import Action, CustomPattern, PolicyConfig, compile_custom_pattern
from evaluation import synth


def test_default_policy_loads(settings: Settings) -> None:
    policy = load_policy(settings.policy_path)
    assert policy.name == "default"
    assert policy.entity_actions["PRIVATE_KEY"] is Action.BLOCK


def test_harmless_prompt_allowed_and_forwarded_unchanged(guard: Guardrail) -> None:
    text = "How do I paginate results in SQLAlchemy?"
    insp = guard.inspect(text)
    assert insp.action is Action.ALLOW
    assert insp.forwardable_text == text
    assert insp.decision.risk_score == 0


def test_spec_example_redacted(guard: Guardrail) -> None:
    insp = guard.inspect("Fix this connection string: db_password=admin_pass_123")
    assert insp.action is Action.REDACT
    assert insp.forwardable_text == "Fix this connection string: db_password=[PASSWORD_1]"


def test_private_key_blocks_and_nothing_is_forwardable(guard: Guardrail) -> None:
    insp = guard.inspect("convert this\n" + synth.private_key(random.Random(1)))
    assert insp.action is Action.BLOCK
    assert insp.forwardable_text is None
    assert insp.to_public()["sanitized_text"] is None


def test_block_beats_redact_in_mixed_prompt(guard: Guardrail) -> None:
    rng = random.Random(2)
    insp = guard.inspect(f"mail {synth.email(rng)} card {synth.credit_card(rng)}")
    assert insp.action is Action.BLOCK
    actions = {d.finding.entity_type: d.action for d in insp.decision.findings}
    assert actions == {"EMAIL": Action.REDACT, "CREDIT_CARD": Action.BLOCK}


def test_confidential_marker_requires_approval_and_is_not_forwardable(guard: Guardrail) -> None:
    insp = guard.inspect("COMPANY CONFIDENTIAL: summarise the merger plan")
    assert insp.action is Action.REQUIRE_APPROVAL
    assert insp.forwardable_text is None


def test_low_confidence_finding_is_monitored_only(guard: Guardrail) -> None:
    insp = guard.inspect("The Confidential flag in our schema is a boolean")
    assert insp.action is Action.ALLOW
    (d,) = insp.decision.findings
    assert "below policy threshold" in d.reason


def test_bulk_records_escalate_to_approval(guard: Guardrail) -> None:
    rng = random.Random(3)
    rows = "\n".join(f"{synth.email(rng)},{synth.phone_in(rng)}" for _ in range(6))
    insp = guard.inspect(rows)
    assert insp.action is Action.REQUIRE_APPROVAL
    assert any("require review" in r for r in insp.decision.reasons)


def test_bulk_records_escalate_to_block() -> None:
    policy = PolicyConfig(
        category_actions={"PII": Action.REDACT}, escalation={"block_at_findings": 3}
    )  # type: ignore[arg-type]
    engine = build_detection_engine(policy, max_input_chars=10_000)
    decision = PolicyEngine(policy).evaluate(
        engine.scan("a@example.com b@example.com c@example.com").findings
    )
    assert decision.action is Action.BLOCK


def test_rule_action_overrides_entity_and_category() -> None:
    policy = PolicyConfig(
        category_actions={"PII": Action.BLOCK},  # type: ignore[dict-item]
        entity_actions={"EMAIL": Action.REQUIRE_APPROVAL},
        rule_actions={"email": Action.REDACT},
    )
    engine = build_detection_engine(policy, max_input_chars=1000)
    decision = PolicyEngine(policy).evaluate(engine.scan("x@example.com").findings)
    assert decision.action is Action.REDACT


def test_risk_score_monotonic_and_bounded(guard: Guardrail) -> None:
    one = guard.inspect("mail a@example.com").decision.risk_score
    two = guard.inspect("mail a@example.com and b@example.com").decision.risk_score
    assert 0 < one < two <= 100
    assert risk_score([]) == 0


def test_custom_term_and_pattern_from_default_policy(guard: Guardrail) -> None:
    insp = guard.inspect("Status of project nightingale for EMP-123456?")
    types = {d.finding.entity_type for d in insp.decision.findings}
    assert types == {"CODENAME", "EMPLOYEE_ID"}
    assert insp.action is Action.REQUIRE_APPROVAL


def test_policy_reasons_are_explainable(guard: Guardrail) -> None:
    insp = guard.inspect("db_password=admin_pass_123")
    (d,) = insp.decision.findings
    assert d.reason == "category SECRET -> REDACT"
    assert insp.decision.reasons == ("PASSWORD (category SECRET -> REDACT)",)


@pytest.mark.parametrize(
    "pattern",
    # Classic catastrophic-backtracking shapes, including the reviewer's bypasses
    # of the old heuristic. Under RE2 they are harmless, so they are accepted.
    [r"(a+)+$", r"((a+))+$", r"(?:a|a)+$", r"(a|aa)+$", r"(\w*)*x", r"(\d+)*z"],
)
def test_catastrophic_shapes_run_in_linear_time_under_re2(pattern: str) -> None:
    compiled = compile_custom_pattern(CustomPattern(rule_id="slow-one", pattern=pattern,
                                                    entity_type="BAD").pattern)  # fmt: skip
    t0 = time.perf_counter()
    compiled.search("a" * 200_000 + "b")
    assert time.perf_counter() - t0 < 0.5


@pytest.mark.parametrize("pattern", [r"(a)\1", r"(?<=x)y", r"(?=x)x", r"(?P<n>a)(?P=n)"])
def test_patterns_re2_cannot_run_are_rejected(pattern: str) -> None:
    with pytest.raises(ValidationError):
        CustomPattern(rule_id="bad-one", pattern=pattern, entity_type="BAD")


@pytest.mark.parametrize("pattern", [r"[", r"a*", r"x?"])
def test_invalid_or_empty_matching_patterns_rejected(pattern: str) -> None:
    with pytest.raises(ValidationError):
        CustomPattern(rule_id="bad-two", pattern=pattern, entity_type="BAD")


def test_unknown_policy_keys_rejected() -> None:
    with pytest.raises(ValidationError):
        PolicyConfig.model_validate({"version": 1, "default_actoin": "BLOCK"})


def test_invalid_action_rejected() -> None:
    with pytest.raises(ValidationError):
        PolicyConfig.model_validate({"category_actions": {"SECRET": "IGNORE"}})


def test_custom_rule_id_clash_rejected() -> None:
    policy = PolicyConfig(
        custom_patterns=[CustomPattern(rule_id="email", pattern=r"\bZZZ\d+\b", entity_type="ZED")]
    )
    with pytest.raises(ValueError, match="clash"):
        build_detection_engine(policy, max_input_chars=100)


def test_policy_file_roundtrip(tmp_path: Path) -> None:
    p = tmp_path / "p.yaml"
    p.write_text("version: 1\nname: strict\ndefault_action: BLOCK\n", encoding="utf-8")
    assert load_policy(p).default_action is Action.BLOCK


# --- regressions from the independent security review -------------------------


def test_card_inside_url_password_still_blocks(guard: Guardrail) -> None:
    insp = guard.inspect("mysql://bob:4111111111111111@db.local")  # Luhn-valid test card
    assert insp.action is Action.BLOCK
    assert insp.forwardable_text is None


def test_sub_threshold_entropy_hit_cannot_hide_email(guard: Guardrail) -> None:
    insp = guard.inspect("contact Q7mZ2xKp9LwR4vTb8NcY@example.com")
    assert insp.action is Action.REDACT
    assert insp.forwardable_text == "contact [EMAIL_1]"


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("password: 2345 6789 0124", "password: [PASSWORD_1]"),
        ("my pin is 98765 43210", "my pin is [PASSWORD_1]"),
    ],
)
def test_cross_entity_overlap_redacts_the_union(guard: Guardrail, text: str, expected: str) -> None:
    assert guard.inspect(text).forwardable_text == expected


def test_repeat_of_widened_secret_is_redacted(guard: Guardrail) -> None:
    v = "aB3_xY" * 50
    insp = guard.inspect("password_token=" + v + "\nlater: " + v)
    assert insp.forwardable_text is not None
    assert v not in insp.forwardable_text


def test_jwt_and_bearer_fold_into_one_decision(guard: Guardrail) -> None:
    token = synth.jwt(random.Random(5))
    insp = guard.inspect(f"Authorization: Bearer {token}")
    secrets = [d for d in insp.decision.findings if d.finding.category.value == "SECRET"]
    assert len(secrets) == 1
    assert secrets[0].finding.corroborated_by


def test_fold_never_weakens_action() -> None:
    policy = PolicyConfig(
        category_actions={"SECRET": Action.REDACT},  # type: ignore[dict-item]
        entity_actions={"JWT": Action.BLOCK},
    )
    engine = build_detection_engine(policy, max_input_chars=10_000)
    token = synth.jwt(random.Random(6))
    decision = PolicyEngine(policy).evaluate(engine.scan(f"Bearer {token}").findings)
    assert decision.action is Action.BLOCK


def test_truncated_scan_fails_closed() -> None:
    policy = PolicyConfig()
    decision = PolicyEngine(policy).evaluate([], truncated=True)
    assert decision.action is Action.BLOCK
    assert any("fail closed" in r for r in decision.reasons)


def test_overlapping_findings_count_once_for_escalation(guard: Guardrail) -> None:
    token = synth.jwt(random.Random(7))
    insp = guard.inspect(f"Authorization: Bearer {token}")
    assert insp.action is Action.REDACT


def test_decision_reasons_do_not_trip_the_detector(guard: Guardrail) -> None:
    """Reasons are written to the audit log, which rejects secret-looking text."""
    samples = ["db_password=admin_pass_123", "mail a@example.com", "COMPANY CONFIDENTIAL memo",
               "card 4111 1111 1111 1111", "token ghp_" + "a1B2" * 9]  # fmt: skip
    for text in samples:
        for reason in guard.inspect(text).decision.reasons:
            secrets = [f for f in guard.detector.scan(reason).findings
                       if f.category.value in ("SECRET", "FINANCIAL")]  # fmt: skip
            assert not secrets, (reason, secrets)
