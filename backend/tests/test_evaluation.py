"""Regression floor on the labeled datasets.

Thresholds are set slightly below the measured numbers so that a regression in
detection quality fails CI. Raising them requires re-running the evaluation;
lowering them requires a written justification in docs/STATUS.md.
"""

from __future__ import annotations

from app.guardrail import Guardrail
from evaluation.evaluate import DATASET, HOLDOUT, load_templates, run


def test_datasets_well_formed() -> None:
    assert len(load_templates(DATASET)) >= 90
    assert len(load_templates(HOLDOUT)) >= 50


def test_development_set_floor(guard: Guardrail) -> None:
    m = run(seeds=3, guard=guard, dataset=DATASET).metrics()
    assert m["entity_recall"] >= 0.98
    assert m["finding_precision"] >= 0.98
    assert m["leaked_values"] == 0
    assert m["negative_prompt_fp_rate"] <= 0.02
    assert m["action_accuracy"] == 1.0


def test_holdout_floor(guard: Guardrail) -> None:
    report = run(seeds=3, guard=guard, dataset=HOLDOUT)
    m = report.metrics()
    assert m["entity_recall"] >= 0.93
    assert m["finding_precision"] >= 0.95
    # Every remaining miss must be a documented known gap.
    undocumented = [f for f in report.failures if not f["known_gap"]]
    assert not undocumented, undocumented
