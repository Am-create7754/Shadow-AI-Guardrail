"""Detection-quality evaluation on the labeled synthetic dataset.

Usage (PowerShell, from backend/)::

    .venv\\Scripts\\python -m evaluation.evaluate --seeds 5
    .venv\\Scripts\\python -m evaluation.evaluate --seeds 5 --report ..\\docs\\EVALUATION.md

Metrics
-------
* **Entity recall** - an expected sensitive span counts as detected only if it is
  *fully* covered by findings the policy acts on (partial masking still leaks).
* **Finding precision** - an actioned finding is a true positive if it overlaps an
  expected span; otherwise it is a false positive.
* **Prompt-level FP rate** - share of benign prompts whose decision is not ALLOW.
* **Leaks** - expected values that would still appear in text leaving the gateway.
* **Action accuracy** - for samples labeled with ``expect_action``.
"""

from __future__ import annotations

import argparse
import json
import random
import re
import statistics
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from app.core.config import Environment, Settings
from app.guardrail import Guardrail, Inspection
from app.policy.models import Action
from evaluation.synth import GENERATORS

DATASET = Path(__file__).with_name("dataset.yaml")
HOLDOUT = Path(__file__).with_name("holdout.yaml")
_TOKEN = re.compile(r"\{\{([A-Z_]+)\}\}|\[\[(.+?)\|([A-Z_]+)\]\]")


@dataclass(frozen=True)
class Expected:
    start: int
    end: int
    label: str  # generator name or literal entity type
    accepted: frozenset[str]


@dataclass
class Sample:
    id: str
    text: str
    expected: list[Expected]
    tags: list[str]
    expect_action: Action | None
    known_gap: str | None

    @property
    def negative(self) -> bool:
        """Benign sample: nothing sensitive and no stricter decision expected."""
        return not self.expected and self.expect_action in (None, Action.ALLOW)


def _zero_width(value: str) -> str:
    mid = len(value) // 2
    return value[:mid] + "\u200b" + value[mid:]


def _fullwidth(value: str) -> str:
    return "".join(chr(ord(c) + 0xFEE0) if c.isascii() and c.isalnum() else c for c in value)


_TRANSFORMS = {"zero_width": _zero_width, "fullwidth": _fullwidth}


def render(raw: dict[str, Any], rng: random.Random) -> Sample:
    transform = _TRANSFORMS.get(raw.get("transform", ""), lambda s: s)
    template: str = raw["text"]
    out: list[str] = []
    expected: list[Expected] = []
    cursor = 0
    pos = 0
    for m in _TOKEN.finditer(template):
        out.append(template[cursor : m.start()])
        pos += m.start() - cursor
        if m.group(1):
            gen, accepted = GENERATORS[m.group(1)]
            value, label = transform(gen(rng)), m.group(1)
        else:
            value, label, accepted = m.group(2), m.group(3), frozenset({m.group(3)})
        out.append(value)
        expected.append(Expected(pos, pos + len(value), label, accepted))
        pos += len(value)
        cursor = m.end()
    out.append(template[cursor:])
    action = raw.get("expect_action")
    return Sample(
        id=raw["id"],
        text="".join(out),
        expected=expected,
        tags=list(raw.get("tags", [])),
        expect_action=Action(action) if action else None,
        known_gap=raw.get("known_gap"),
    )


def load_templates(path: Path = DATASET) -> list[dict[str, Any]]:
    with path.open(encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    ids = [d["id"] for d in data]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate sample ids in dataset")
    return list(data)


def _covered(start: int, end: int, spans: list[tuple[int, int]]) -> bool:
    pos = start
    for s, e in sorted(spans):
        if s <= pos < e:
            pos = e
        if pos >= end:
            return True
    return pos >= end


@dataclass
class Counts:
    expected: int = 0
    detected: int = 0
    typed_ok: int = 0


@dataclass
class Report:
    samples: int = 0
    positives: int = 0
    negatives: int = 0
    entity: Counts = field(default_factory=Counts)
    by_label: dict[str, Counts] = field(default_factory=lambda: defaultdict(Counts))
    finding_tp: int = 0
    finding_fp: int = 0
    negative_flagged: int = 0
    positive_missed: int = 0
    leaks: int = 0
    action_checked: int = 0
    action_correct: int = 0
    latencies_ms: list[float] = field(default_factory=list)
    failures: list[dict[str, Any]] = field(default_factory=list)

    def metrics(self) -> dict[str, Any]:
        recall = self.entity.detected / self.entity.expected if self.entity.expected else 1.0
        flagged = self.finding_tp + self.finding_fp
        precision = self.finding_tp / flagged if flagged else 1.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        lat = sorted(self.latencies_ms)
        return {
            "samples": self.samples,
            "positive_samples": self.positives,
            "negative_samples": self.negatives,
            "expected_entities": self.entity.expected,
            "entity_recall": round(recall, 4),
            "finding_precision": round(precision, 4),
            "f1": round(f1, 4),
            "type_accuracy": round(self.entity.typed_ok / max(1, self.entity.detected), 4),
            "false_positive_findings": self.finding_fp,
            "negative_prompt_fp_rate": round(self.negative_flagged / max(1, self.negatives), 4),
            "positive_prompts_missed": self.positive_missed,
            "leaked_values": self.leaks,
            "action_accuracy": round(self.action_correct / max(1, self.action_checked), 4),
            "latency_ms_mean": round(statistics.fmean(lat), 3) if lat else 0.0,
            "latency_ms_p95": round(lat[int(0.95 * (len(lat) - 1))], 3) if lat else 0.0,
            "per_label_recall": {
                k: round(c.detected / c.expected, 4)
                for k, c in sorted(self.by_label.items())
                if c.expected
            },
        }


def evaluate_sample(guard: Guardrail, sample: Sample, report: Report) -> None:
    insp: Inspection = guard.inspect(sample.text)
    report.samples += 1
    report.latencies_ms.append(insp.scan.duration_ms)
    acted = [d.finding for d in insp.decision.findings if d.action is not Action.ALLOW]
    masked = [f for f in acted if f.redactable]
    spans = [(f.start, f.end) for f in masked]
    problems: list[str] = []

    if sample.negative:
        report.negatives += 1
        if insp.action is not Action.ALLOW:
            report.negative_flagged += 1
            problems.append(f"benign prompt -> {insp.action.value}")
    else:
        report.positives += 1
        if insp.action is Action.ALLOW:
            report.positive_missed += 1
            problems.append("sensitive prompt -> ALLOW")

    for exp in sample.expected:
        report.entity.expected += 1
        lab = report.by_label[exp.label]
        lab.expected += 1
        if _covered(exp.start, exp.end, spans):
            report.entity.detected += 1
            lab.detected += 1
            types = {f.entity_type for f in masked if f.start < exp.end and exp.start < f.end}
            if types & exp.accepted:
                report.entity.typed_ok += 1
                lab.typed_ok += 1
        else:
            problems.append(f"missed {exp.label}")
        if insp.action is not Action.BLOCK:
            value = sample.text[exp.start : exp.end]
            if value in insp.redaction.text:
                report.leaks += 1
                problems.append(f"leak of {exp.label}")

    for f in masked:
        if any(f.start < e.end and e.start < f.end for e in sample.expected):
            report.finding_tp += 1
        else:
            report.finding_fp += 1
            problems.append(f"false positive {f.entity_type} via {f.rule_id}")

    if sample.expect_action is not None:
        report.action_checked += 1
        if insp.action is sample.expect_action:
            report.action_correct += 1
        else:
            problems.append(f"action {insp.action.value} != expected {sample.expect_action.value}")

    if problems:
        report.failures.append(
            {"id": sample.id, "problems": problems, "known_gap": sample.known_gap}
        )


def run(seeds: int = 5, guard: Guardrail | None = None, dataset: Path = DATASET) -> Report:
    guard = guard or Guardrail.from_settings(Settings(environment=Environment.TEST))
    templates = load_templates(dataset)
    report = Report()
    for seed in range(seeds):
        rng = random.Random(seed)  # deterministic synthetic data, not security-sensitive
        for raw in templates:
            evaluate_sample(guard, render(raw, rng), report)
    return report


def to_markdown(report: Report, seeds: int, dataset: Path = DATASET, title: str = "") -> str:
    m = report.metrics()
    lines = [
        f"## {title or dataset.stem}",
        "",
        "Generated by `python -m evaluation.evaluate` on the synthetic labeled dataset",
        f"(`backend/evaluation/{dataset.name}`, {seeds} random seeds per template).",
        "These numbers describe this dataset only; they are not a claim of",
        "comprehensive real-world secret detection.",
        "",
        "| Metric | Value |",
        "|---|---|",
    ]
    for k, v in m.items():
        if k != "per_label_recall":
            lines.append(f"| {k} | {v} |")
    lines += ["", "### Recall by entity", "", "| Entity | Recall |", "|---|---|"]
    lines += [f"| {k} | {v} |" for k, v in m["per_label_recall"].items()]
    unique: dict[str, dict[str, Any]] = {}
    for fail in report.failures:
        entry = unique.setdefault(fail["id"], {"count": 0, **fail})
        entry["count"] += 1
    lines += ["", "### Failing samples", ""]
    if not unique:
        lines.append("None.")
    for sid, fail in sorted(unique.items()):
        gap = f" - known gap: {fail['known_gap']}" if fail.get("known_gap") else ""
        probs = "; ".join(sorted(set(fail["problems"])))
        lines.append(f"- `{sid}` ({fail['count']}/{seeds} seeds): {probs}{gap}")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--seeds", type=int, default=5)
    parser.add_argument("--report", type=Path, help="write a markdown report to this path")
    parser.add_argument("--json", action="store_true", help="print metrics as JSON")
    args = parser.parse_args(argv)
    sections = [
        "# Detection Evaluation",
        "",
        "Two datasets are reported. The *development* set was used while building and",
        "tuning the rules, so its numbers are optimistic. The *held-out* set was written",
        "after the rules were frozen and was not used for tuning; treat it as the",
        "honest estimate. Both are synthetic and small - they are evidence for this",
        "project, not a claim of comprehensive secret detection.",
        "",
    ]
    results: dict[str, dict[str, Any]] = {}
    for path, title in ((DATASET, "Development set"), (HOLDOUT, "Held-out set")):
        if not path.exists():
            continue
        report = run(args.seeds, dataset=path)
        results[path.stem] = report.metrics()
        sections.append(to_markdown(report, args.seeds, path, title))
    frozen = Path(__file__).parent / "results" / "holdout_v1_frozen.json"
    if frozen.exists():
        v1 = json.loads(frozen.read_text(encoding="utf-8"))["holdout"]
        sections += [
            "## Held-out history",
            "",
            "The first (blind) held-out run, before any rule changes it prompted, is kept",
            "in `evaluation/results/holdout_v1_frozen.json`. That run exposed four genuine",
            "defects (documentation IP ranges treated as private, `await`/code references",
            "taken as passwords, connection-string keys over-matching, `ssh user@host`",
            "taken as an email) which were then fixed - so the held-out set is no longer",
            "fully blind. A fresh held-out set is needed for the next unbiased estimate.",
            "",
            "| Metric | Blind v1 run | Current |",
            "|---|---|---|",
        ]
        current = results.get("holdout", {})
        for key in ("entity_recall", "finding_precision", "f1", "negative_prompt_fp_rate",
                    "false_positive_findings", "leaked_values"):  # fmt: skip
            sections.append(f"| {key} | {v1.get(key)} | {current.get(key)} |")
        sections.append("")
    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print("\n".join(sections))
    if args.report:
        args.report.write_text("\n".join(sections), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
