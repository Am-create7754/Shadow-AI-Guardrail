"""ReDoS regression: every rule must stay fast on pathological input.

Python's ``re`` backtracks, so a careless pattern can take exponential time on
crafted input and freeze the gateway. These inputs target the shapes our rules
use (long runs of the same class, repeated keywords, unterminated structures).
The budget is generous to avoid flaky CI but far below catastrophic behaviour.
"""

from __future__ import annotations

import time

import pytest

from app.detection.engine import DetectionEngine
from app.detection.rules import BUILTIN_RULES

N = 50_000
PATHOLOGICAL = {
    "same-char": "a" * N,
    "digits": "1" * N,
    "digits-spaced": "1 " * (N // 2),
    "base64ish": "Ab3+" * (N // 4),
    "equals": "=" * N,
    "keyword-spam": "password=" * (N // 9),
    "keyword-no-value": "password " * (N // 9),
    "secret-key-spam": "api_key_" * (N // 8),
    "at-signs": "a@" * (N // 2),
    "url-prefix-spam": "postgres://u:" * (N // 13),
    "pem-unterminated": "-----BEGIN " + "PRIVATE KEY-----" + "A" * N,  # split: repo hygiene
    "jwt-prefix-spam": "eyJ" * (N // 3),
    "dots": "1." * (N // 2),
    "mysql-spam": "mysql " * (N // 6),
    "bearer-spam": "Bearer " * (N // 7),
    "mixed-unicode": "\uff41\u200b" * (N // 2),
}

BUDGET_SECONDS = 1.5


@pytest.mark.slow
@pytest.mark.parametrize("rule", BUILTIN_RULES, ids=lambda r: r.rule_id)
def test_rule_linear_on_pathological_inputs(rule: object) -> None:
    pattern = rule.pattern  # type: ignore[attr-defined]
    for name, text in PATHOLOGICAL.items():
        t0 = time.perf_counter()
        for _ in pattern.finditer(text):
            pass
        elapsed = time.perf_counter() - t0
        assert elapsed < BUDGET_SECONDS, f"{name}: {elapsed:.2f}s"


@pytest.mark.slow
@pytest.mark.parametrize("name", list(PATHOLOGICAL))
def test_full_engine_scan_bounded(name: str) -> None:
    engine = DetectionEngine(max_input_chars=N + 100)
    t0 = time.perf_counter()
    engine.scan(PATHOLOGICAL[name])
    assert time.perf_counter() - t0 < 5.0
