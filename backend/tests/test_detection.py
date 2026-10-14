from __future__ import annotations

import random

import pytest

from app.detection import engine as engine_mod
from app.detection.engine import DetectionEngine, InputTooLargeError, merge_same_entity
from app.detection.models import Category, DetectorKind, Finding, Severity
from app.detection.rules import BUILTIN_RULES
from evaluation import synth

# (generator, template, expected entity type)
POSITIVE_CASES = [
    (synth.aws_access_key, "aws_access_key_id = {}", "AWS_ACCESS_KEY"),
    (synth.aws_secret_key, "aws_secret_access_key={}", "AWS_SECRET_KEY"),
    (synth.gcp_api_key, 'apiKey: "{}"', "GCP_API_KEY"),
    (synth.github_token, "export GH={}", "GITHUB_TOKEN"),
    (synth.gitlab_token, "token {}", "GITLAB_TOKEN"),
    (synth.slack_token, "slack {}", "SLACK_TOKEN"),
    (synth.stripe_key, "stripe.api_key = '{}'", "STRIPE_KEY"),
    (synth.sendgrid_key, "key: {}", "SENDGRID_KEY"),
    (synth.npm_token, "//registry/:_authToken={}", "NPM_TOKEN"),
    (synth.openai_key, "OPENAI_API_KEY={}", "OPENAI_KEY"),
    (synth.anthropic_key, "use {} please", "ANTHROPIC_KEY"),
    (synth.jwt, "token {}", "JWT"),
    (synth.private_key, "here:\n{}\n", "PRIVATE_KEY"),
    (synth.email, "mail {} today", "EMAIL"),
    (synth.credit_card, "card {} declined", "CREDIT_CARD"),
    (synth.aadhaar, "aadhaar {}", "AADHAAR"),
    (synth.pan, "PAN {}", "PAN"),
    (synth.ssn, "SSN {}", "SSN"),
    (synth.iban, "IBAN {}", "IBAN"),
    (synth.phone_in, "phone {}", "PHONE"),
    (synth.private_ip, "host {} down", "INTERNAL_IP"),
]


@pytest.mark.parametrize(("gen", "template", "entity"), POSITIVE_CASES)
@pytest.mark.parametrize("seed", range(5))
def test_each_entity_detected_with_exact_span(
    engine: DetectionEngine, gen: synth.Generator, template: str, entity: str, seed: int
) -> None:
    value = gen(random.Random(seed))
    text = template.format(value)
    result = engine.scan(text)
    start = text.index(value)
    hits = [f for f in result.findings if f.entity_type == entity]
    assert hits, f"{entity} not detected in {text!r}"
    f = hits[0]
    assert f.start <= start
    assert f.end >= start + len(value)


def test_spec_example_masks_only_the_value(engine: DetectionEngine) -> None:
    text = "Fix this connection string: db_password=admin_pass_123"
    (f,) = engine.scan(text).findings
    assert f.entity_type == "PASSWORD"
    assert text[f.start : f.end] == "admin_pass_123"
    assert f.detector is DetectorKind.CONTEXT


@pytest.mark.parametrize(
    "text",
    [
        "How do I reverse a linked list in Python?",
        "password = os.getenv('DB_PASSWORD')\nif not password:\n    raise RuntimeError()",
        "tokens = tokenizer(text, max_tokens=1024)",
        "git commit 3f786850e387550fdab836ed7e6dc881de23001b broke the build",
        "Request 123e4567-e89b-12d3-a456-426614174000 timed out",
        "def get_user_profile_picture_url(user_id: int) -> str: ...",
        "DB_PASSWORD=${DB_PASSWORD}",
        "api_key: ********",
        "Set password: <your-password-here>",
        "Version 10.2.3.4 of the SDK",
        "mysql -h db -P 3306 -u app",
        "compass: north",
        "const password = await bcrypt.hash(req.body.password, 12);",
        "ssh ops@bastion.example.com",
        "git remote add origin git@github.com:org/repo.git",
    ],
)
def test_benign_text_has_no_actionable_secret(engine: DetectionEngine, text: str) -> None:
    secrets = [f for f in engine.scan(text).findings if f.category is Category.SECRET]
    pii = [f for f in engine.scan(text).findings if f.redactable and f.confidence >= 0.6]
    assert not secrets, secrets
    assert not pii, pii


def test_finding_repr_and_public_view_never_contain_value(engine: DetectionEngine) -> None:
    value = synth.github_token(random.Random(7))
    (f,) = [f for f in engine.scan(f"tok {value}").findings if f.entity_type == "GITHUB_TOKEN"]
    assert value not in repr(f)
    assert value not in str(f.to_public())
    assert f.value == value  # still available internally for redaction


def test_zero_width_split_secret_detected_and_span_covers_hidden_chars(
    engine: DetectionEngine,
) -> None:
    key = synth.aws_access_key(random.Random(3))
    text = f"key {key[:8]}\u200b{key[8:]} end"
    (f,) = [f for f in engine.scan(text).findings if f.entity_type == "AWS_ACCESS_KEY"]
    assert text[f.start : f.end] == f"{key[:8]}\u200b{key[8:]}"
    assert "normalised" in f.explanation


def test_fullwidth_secret_detected(engine: DetectionEngine) -> None:
    token = synth.github_token(random.Random(4))
    fw = "".join(chr(ord(c) + 0xFEE0) if c.isalnum() else c for c in token)
    result = engine.scan(f"token {fw}")
    assert result.normalized
    assert any(f.entity_type == "GITHUB_TOKEN" for f in result.findings)


def test_repeated_secret_without_context_is_also_found(engine: DetectionEngine) -> None:
    text = "postgres://svc:Hunter2Secret@db.example.com/app and later Hunter2Secret again"
    spans = [(f.start, f.end) for f in engine.scan(text).findings if f.category is Category.SECRET]
    occurrences = [i for i in range(len(text)) if text.startswith("Hunter2Secret", i)]
    assert len(spans) == 2
    assert sorted(s for s, _ in spans) == occurrences


def test_url_password_containing_raw_at_sign_fully_covered(engine: DetectionEngine) -> None:
    text = "postgres://app:p@ss@word1@db.example.com:5432/x"
    (f,) = [f for f in engine.scan(text).findings if f.category is Category.SECRET]
    assert text[f.start : f.end] == "p@ss@word1"


def test_jwt_in_bearer_header_both_reported_by_scanner(engine: DetectionEngine) -> None:
    # The scanner keeps different entity types; the policy layer folds them (test_policy).
    token = synth.jwt(random.Random(5))
    text = f"Authorization: Bearer {token}"
    types = {f.entity_type for f in engine.scan(text).findings if f.category is Category.SECRET}
    assert {"JWT", "BEARER_TOKEN"} <= types


def test_input_size_limit() -> None:
    small = DetectionEngine(max_input_chars=10)
    with pytest.raises(InputTooLargeError):
        small.scan("x" * 11)
    assert small.scan("x" * 10).findings == ()


def test_non_string_rejected(engine: DetectionEngine) -> None:
    with pytest.raises(TypeError):
        engine.scan(b"bytes")  # type: ignore[arg-type]


def test_empty_and_whitespace(engine: DetectionEngine) -> None:
    assert engine.scan("").findings == ()
    assert engine.scan(" \n\t ").findings == ()


def test_lone_surrogate_does_not_crash(engine: DetectionEngine) -> None:
    engine.scan("broken \ud800 text password=abc12345")


def test_disabled_rule_is_not_run() -> None:
    e = DetectionEngine(disabled_rules=["email", "high-entropy-string"])
    assert "email" not in e.rule_ids
    assert not e.scan("mail a.b@example.com").findings


def test_rule_ids_unique_and_patterns_clean() -> None:
    ids = [r.rule_id for r in BUILTIN_RULES]
    assert len(ids) == len(set(ids))
    for r in BUILTIN_RULES:
        # Guards against escape bugs such as a literal backspace instead of \b.
        assert not any(ord(c) < 32 and c not in "\t\n" for c in r.pattern.pattern), r.rule_id
        assert 0 < r.confidence <= 1


def _f(rule: str, start: int, end: int, sev: Severity, conf: float, **kw: object) -> Finding:
    return Finding(
        rule_id=rule,
        entity_type=str(kw.get("entity", "X")),
        category=kw.get("category", Category.SECRET),  # type: ignore[arg-type]
        severity=sev,
        confidence=conf,
        detector=kw.get("detector", DetectorKind.REGEX),  # type: ignore[arg-type]
        start=start,
        end=end,
        value="v" * (end - start),
        redactable=bool(kw.get("redactable", True)),
    )


def test_same_entity_contained_corroborates() -> None:
    a = _f("a", 0, 10, Severity.HIGH, 0.9)
    b = _f("b", 2, 8, Severity.HIGH, 0.8)
    (win,), merged = merge_same_entity([b, a])
    assert win.rule_id == "a"
    assert win.corroborated_by == ("b",)
    assert (win.start, win.end) == (0, 10)
    assert merged == 1


def test_same_entity_partial_overlap_widens_to_union() -> None:
    a = _f("a", 0, 10, Severity.HIGH, 0.9)
    b = _f("b", 5, 15, Severity.HIGH, 0.8)
    (win,), _ = merge_same_entity([a, b])
    assert (win.start, win.end) == (0, 15)
    assert win.value == ""  # caller must recompute the value for a widened span


def test_different_entities_are_never_dropped() -> None:
    a = _f("a", 0, 10, Severity.CRITICAL, 0.9, entity="PASSWORD")
    b = _f("b", 5, 30, Severity.LOW, 0.9, entity="EMAIL", category=Category.PII)
    c = _f("c", 2, 4, Severity.CRITICAL, 0.9, entity="CREDIT_CARD", category=Category.FINANCIAL)
    found, merged = merge_same_entity([a, b, c])
    assert {f.entity_type for f in found} == {"PASSWORD", "EMAIL", "CREDIT_CARD"}
    assert merged == 0


def test_specific_rule_beats_entropy_at_equal_severity() -> None:
    a = _f("specific", 0, 10, Severity.HIGH, 0.7)
    b = _f("entropy", 0, 10, Severity.HIGH, 0.9, detector=DetectorKind.ENTROPY)
    (win,), _ = merge_same_entity([b, a])
    assert win.rule_id == "specific"


def test_below_threshold_ranks_last() -> None:
    weak = _f("weak", 0, 10, Severity.CRITICAL, 0.4)
    strong = _f("strong", 0, 10, Severity.LOW, 0.9)
    assert engine_mod.priority(strong, 0.6) < engine_mod.priority(weak, 0.6)


def test_merge_is_fast_for_many_findings() -> None:
    import time

    many = [_f(f"r{i}", i * 3, i * 3 + 2, Severity.LOW, 0.9) for i in range(50_000)]
    t0 = time.perf_counter()
    found, _ = merge_same_entity(many)
    assert len(found) == 50_000
    assert time.perf_counter() - t0 < 2.0


def test_candidate_cap_sets_truncated(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(engine_mod, "MAX_CANDIDATES", 5)
    result = DetectionEngine().scan(" ".join(f"u{i}@example.com" for i in range(20)))
    assert result.truncated
    assert len(result.findings) == 5


@pytest.mark.parametrize(
    "hidden",
    ["\u200b", "\ufe0f", "\U000e0041", "\u3164", "\u115f", "\u180b", "\u2800",
     "\u17b4", "\u0301", "\ufff9", "\U0001d173", "\x00"],
)  # fmt: skip
def test_invisible_character_inside_key_is_seen_through(
    engine: DetectionEngine, hidden: str
) -> None:
    key = synth.aws_access_key(random.Random(9))
    text = f"key {key[:8]}{hidden}{key[8:]}"
    (f,) = [f for f in engine.scan(text).findings if f.entity_type == "AWS_ACCESS_KEY"]
    assert text[f.start : f.end] == f"{key[:8]}{hidden}{key[8:]}"


def test_cyrillic_homoglyph_prefix_detected(engine: DetectionEngine) -> None:
    key = synth.aws_access_key(random.Random(10))
    text = "key \u0410" + key[1:]  # Cyrillic capital A
    assert any(f.entity_type == "AWS_ACCESS_KEY" for f in engine.scan(text).findings)


def test_expanding_compatibility_chars_are_bounded(engine: DetectionEngine) -> None:
    from app.detection.normalize import normalize

    text = "\ufdfa" * 1000  # NFKC would expand each to 18 characters
    assert len(normalize(text).text) <= 3 * len(text)


def test_length_changing_lowercase_does_not_shift_context(engine: DetectionEngine) -> None:
    # "\u0130".lower() is two code points; a whole-text lower() would misalign windows.
    text = "\u0130" * 60 + " phone 9876543210"
    (f,) = engine.scan(text).findings
    assert f.entity_type == "PHONE"
    assert "context keyword 'phone'" in f.explanation
