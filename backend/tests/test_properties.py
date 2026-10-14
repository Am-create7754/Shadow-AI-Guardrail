"""Property-based tests (Hypothesis): invariants that must hold for any input."""

from __future__ import annotations

import itertools
import random

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from app.guardrail import Guardrail
from app.policy.models import Action
from evaluation import synth

SECRET_GENERATORS = [
    synth.aws_access_key,
    synth.github_token,
    synth.stripe_key,
    synth.openai_key,
    synth.anthropic_key,
    synth.slack_token,
    synth.gitlab_token,
    synth.npm_token,
    synth.jwt,
]

# Surrounding text that ends/starts at a token boundary so the secret stays a whole token.
filler = st.text(
    alphabet=st.characters(codec="utf-8", exclude_categories=("Cs",)), max_size=200
).map(lambda s: s + " ")

HSETTINGS = settings(
    max_examples=150, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture]
)


@HSETTINGS
@given(
    prefix=filler,
    suffix=filler,
    which=st.integers(0, len(SECRET_GENERATORS) - 1),
    seed=st.integers(0, 10_000),
)
def test_vendor_secret_never_survives(
    guard: Guardrail, prefix: str, suffix: str, which: int, seed: int
) -> None:
    secret = SECRET_GENERATORS[which](random.Random(seed))
    text = prefix + secret + " " + suffix
    insp = guard.inspect(text)
    assert insp.action is not Action.ALLOW
    assert secret not in insp.redaction.text
    public = str(insp.to_public())
    assert secret not in public


@HSETTINGS
@given(text=st.text(max_size=2000))
def test_arbitrary_text_never_crashes_and_spans_are_valid(guard: Guardrail, text: str) -> None:
    insp = guard.inspect(text)
    for d in insp.decision.findings:
        f = d.finding
        assert 0 <= f.start < f.end <= len(text)
    redactable = [f for f in insp.scan.findings if f.redactable]
    for a, b in itertools.pairwise(redactable):
        assert a.end <= b.start
    assert 0 <= insp.decision.risk_score <= 100


@HSETTINGS
@given(text=st.text(alphabet=st.characters(max_codepoint=0x7F), max_size=500))
def test_redaction_preserves_unflagged_text(guard: Guardrail, text: str) -> None:
    """Everything outside redacted spans is forwarded byte-for-byte."""
    insp = guard.inspect(text)
    out = insp.redaction.text
    cursor = 0
    rebuilt = []
    for r in insp.redaction.replacements:
        rebuilt.append(text[cursor : r.start])
        rebuilt.append(r.placeholder)
        cursor = r.end
    rebuilt.append(text[cursor:])
    assert out == "".join(rebuilt)
