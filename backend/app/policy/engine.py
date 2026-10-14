"""Policy evaluation: turn findings into an explainable, enforceable decision."""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass, replace
from pathlib import Path

import yaml

from app.detection.engine import DetectionEngine, priority
from app.detection.entropy import EntropyConfig
from app.detection.models import DetectorKind, Finding, Severity
from app.detection.rules import BUILTIN_RULES, PatternRule
from app.policy.models import Action, PolicyConfig, compile_custom_pattern

# Contribution of a single finding to the overall risk score, by severity.
_SEVERITY_WEIGHT = {
    Severity.LOW: 0.15,
    Severity.MEDIUM: 0.35,
    Severity.HIGH: 0.65,
    Severity.CRITICAL: 0.9,
}


@dataclass(frozen=True, slots=True)
class FindingDecision:
    finding: Finding
    action: Action
    reason: str

    def to_public(self) -> dict[str, object]:
        return {**self.finding.to_public(), "action": self.action.value, "reason": self.reason}


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    action: Action
    risk_score: int  # 0-100
    reasons: tuple[str, ...]
    findings: tuple[FindingDecision, ...]
    policy_name: str

    @property
    def risk_level(self) -> str:
        if self.risk_score >= 85:
            return "CRITICAL"
        if self.risk_score >= 60:
            return "HIGH"
        if self.risk_score >= 30:
            return "MEDIUM"
        if self.risk_score > 0:
            return "LOW"
        return "NONE"

    @property
    def to_redact(self) -> tuple[Finding, ...]:
        """Findings whose spans must be masked before anything is forwarded."""
        return tuple(
            d.finding
            for d in self.findings
            if d.finding.redactable and d.action is not Action.ALLOW
        )


def load_policy(path: Path) -> PolicyConfig:
    with path.open(encoding="utf-8") as fh:
        raw = yaml.safe_load(fh) or {}
    return PolicyConfig.model_validate(raw)


def risk_score(findings: Sequence[Finding]) -> int:
    """Probabilistic-OR of per-finding risk: 1 - prod(1 - weight * confidence)."""
    remaining = 1.0
    for f in findings:
        remaining *= 1.0 - _SEVERITY_WEIGHT[f.severity] * f.confidence
    return round((1.0 - remaining) * 100)


class PolicyEngine:
    def __init__(self, config: PolicyConfig) -> None:
        self.config = config

    def _action_for(self, f: Finding) -> tuple[Action, str]:
        cfg = self.config
        if f.confidence < cfg.min_confidence:
            return Action.ALLOW, (
                f"confidence {f.confidence:.2f} below policy threshold "
                f"{cfg.min_confidence:.2f}; recorded for monitoring"
            )
        if f.rule_id in cfg.rule_actions:
            action, why = cfg.rule_actions[f.rule_id], f"rule '{f.rule_id}'"
        elif f.entity_type in cfg.entity_actions:
            action, why = cfg.entity_actions[f.entity_type], f"entity type {f.entity_type}"
        elif f.category in cfg.category_actions:
            action, why = cfg.category_actions[f.category], f"category {f.category.value}"
        else:
            action, why = cfg.default_action, "policy default"
        if action is Action.REDACT and not f.redactable:
            return Action.ALLOW, f"{why} -> REDACT, but finding is informational; recorded"
        return action, f"{why} -> {action.value}"

    def evaluate(self, findings: Sequence[Finding], *, truncated: bool = False) -> PolicyDecision:
        """Decide on a request.

        Every finding is evaluated on its own - including findings that overlap
        other findings - so the overall action is never weaker than the strictest
        individual finding. Only afterwards are redundant findings folded into a
        containing finding for presentation (see :func:`_fold_redundant`).
        """
        all_decisions = [FindingDecision(f, *self._action_for(f)) for f in findings]
        overall = Action.ALLOW
        for d in all_decisions:
            if d.action.rank > overall.rank:
                overall = d.action
        decisions = _fold_redundant(all_decisions, self.config.min_confidence)
        score = risk_score([d.finding for d in decisions])
        reasons: list[str] = []
        if all_decisions:
            worst = max(all_decisions, key=lambda d: (d.action.rank, d.finding.severity))
            if worst.action is not Action.ALLOW:
                reasons.append(f"{worst.finding.entity_type}: {worst.reason}")

        if truncated:
            overall = Action.BLOCK
            reasons.append("too many candidate detections to inspect safely (fail closed)")

        actionable = _count_actionable(decisions)
        esc = self.config.escalation
        if esc.block_at_findings and actionable >= esc.block_at_findings:
            overall = Action.BLOCK
            reasons.append(f"{actionable} sensitive items in one request (bulk-exfiltration rule)")
        elif (
            esc.approval_at_findings
            and actionable >= esc.approval_at_findings
            and overall.rank < Action.REQUIRE_APPROVAL.rank
        ):
            overall = Action.REQUIRE_APPROVAL
            reasons.append(f"{actionable} sensitive items in one request require review")
        if esc.block_at_risk_score and score >= esc.block_at_risk_score:
            overall = Action.BLOCK
            reasons.append(f"risk score {score} >= block threshold {esc.block_at_risk_score}")

        if not reasons:
            reasons.append("no actionable sensitive data detected")
        return PolicyDecision(overall, score, tuple(reasons), tuple(decisions), self.config.name)


def _fold_redundant(
    decisions: list[FindingDecision], min_confidence: float
) -> list[FindingDecision]:
    """Fold a finding into another one that makes it redundant.

    ``d`` is folded into ``k`` only if all of these hold, so folding can never
    weaken enforcement or hide anything from redaction:

    * same category, and ``k``'s span fully contains ``d``'s span;
    * ``d``'s action is no stricter than ``k``'s;
    * if ``d`` would be redacted, ``k`` is redacted too.

    Example: a JWT inside an ``Authorization: Bearer`` value is one finding
    (JWT, corroborated by bearer-token) instead of two.
    """
    ordered = sorted(
        decisions,
        key=lambda d: (d.finding.start, -d.finding.end, priority(d.finding, min_confidence)),
    )
    kept: list[FindingDecision] = []
    active: list[int] = []  # indexes into kept whose span may still contain later findings
    for d in ordered:
        f = d.finding
        active = [i for i in active if kept[i].finding.end > f.start]
        host = next(
            (
                i
                for i in active
                if (k := kept[i]).finding.category is f.category
                and k.finding.start <= f.start
                and k.finding.end >= f.end
                and k.action.rank >= d.action.rank
                and (k.finding.redactable or not f.redactable or d.action is Action.ALLOW)
            ),
            None,
        )
        if host is None:
            kept.append(d)
            active.append(len(kept) - 1)
            continue
        k = kept[host]
        if f.rule_id not in k.finding.corroborated_by and f.rule_id != k.finding.rule_id:
            kept[host] = replace(
                k,
                finding=replace(k.finding, corroborated_by=(*k.finding.corroborated_by, f.rule_id)),
            )
    return sorted(kept, key=lambda d: (d.finding.start, d.finding.end))


def _count_actionable(decisions: Sequence[FindingDecision]) -> int:
    """Distinct sensitive items: overlapping redacted spans count once."""
    acted = [d.finding for d in decisions if d.action is not Action.ALLOW]
    informational = sum(1 for f in acted if not f.redactable)
    spans = sorted((f.start, f.end) for f in acted if f.redactable)
    regions = 0
    end = -1
    for s, e in spans:
        if s >= end:
            regions += 1
            end = e
        else:
            end = max(end, e)
    return regions + informational


def custom_rules(config: PolicyConfig) -> list[PatternRule]:
    rules: list[PatternRule] = []
    for i, t in enumerate(config.custom_terms):
        flags = 0 if t.case_sensitive else re.IGNORECASE
        rules.append(
            PatternRule(
                rule_id=f"custom-term-{i + 1}",
                entity_type=t.entity_type,
                category=t.category,
                severity=t.severity,
                pattern=re.compile(r"(?<!\w)" + re.escape(t.term) + r"(?!\w)", flags),
                confidence=0.95,
                detector=DetectorKind.KEYWORD,
                redactable=t.redact,
                description="Organisation-defined sensitive term",
            )
        )
    for p in config.custom_patterns:
        rules.append(
            PatternRule(
                rule_id=p.rule_id,
                entity_type=p.entity_type,
                category=p.category,
                severity=p.severity,
                pattern=compile_custom_pattern(p.pattern),  # RE2: linear time
                confidence=p.confidence,
                group=p.group,
                description=p.description or "Custom policy pattern",
            )
        )
    return rules


def build_detection_engine(config: PolicyConfig, *, max_input_chars: int) -> DetectionEngine:
    builtin_ids = {r.rule_id for r in BUILTIN_RULES}
    extra = custom_rules(config)
    clash = builtin_ids & {r.rule_id for r in extra}
    if clash:
        raise ValueError(f"custom rule ids clash with built-in rules: {sorted(clash)}")
    e = config.entropy
    return DetectionEngine(
        (*BUILTIN_RULES, *extra),
        entropy=EntropyConfig(
            enabled=e.enabled,
            min_length=e.min_length,
            min_entropy_base64=e.min_entropy_base64,
            min_entropy_hex=e.min_entropy_hex,
        ),
        disabled_rules=config.disabled_rules,
        max_input_chars=max_input_chars,
    )
