"""Facade combining detection, policy and redaction into one inspection call.

This is the single entry point the gateway (Phase 3) uses for prompts and the
output engine (Phase 4) uses for model responses.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.core.config import Settings, get_settings
from app.detection.engine import DetectionEngine, ScanResult
from app.detection.redaction import RedactionResult, redact
from app.policy.engine import PolicyDecision, PolicyEngine, build_detection_engine, load_policy
from app.policy.models import Action, PolicyConfig


@dataclass(frozen=True, slots=True)
class Inspection:
    scan: ScanResult
    decision: PolicyDecision
    redaction: RedactionResult

    @property
    def action(self) -> Action:
        return self.decision.action

    @property
    def forwardable_text(self) -> str | None:
        """Text that may leave the gateway, or ``None`` when it must not be sent."""
        if self.decision.action in (Action.BLOCK, Action.REQUIRE_APPROVAL):
            return None
        return self.redaction.text

    def to_public(self) -> dict[str, object]:
        """Safe summary: no raw values, no placeholder->value mapping."""
        return {
            "action": self.decision.action.value,
            "risk_score": self.decision.risk_score,
            "risk_level": self.decision.risk_level,
            "reasons": list(self.decision.reasons),
            "policy": self.decision.policy_name,
            "findings": [d.to_public() for d in self.decision.findings],
            "sanitized_text": (
                self.redaction.text if self.decision.action is not Action.BLOCK else None
            ),
            "replacements": [r.to_public() for r in self.redaction.replacements],
            "normalized": self.scan.normalized,
            "merged_candidates": self.scan.suppressed,
            "truncated": self.scan.truncated,
            "scan_ms": self.scan.duration_ms,
        }


class Guardrail:
    def __init__(self, policy: PolicyConfig, settings: Settings) -> None:
        self.policy = policy
        self.settings = settings
        self.detector: DetectionEngine = build_detection_engine(
            policy, max_input_chars=settings.max_input_chars
        )
        self.policy_engine = PolicyEngine(policy)
        self._key = settings.fingerprint_key_bytes()

    @classmethod
    def from_settings(cls, settings: Settings | None = None) -> Guardrail:
        settings = settings or get_settings()
        return cls(load_policy(settings.policy_path), settings)

    def inspect(self, text: str) -> Inspection:
        scan = self.detector.scan(text)
        decision = self.policy_engine.evaluate(scan.findings, truncated=scan.truncated)
        redaction = redact(text, decision.to_redact, self._key)
        return Inspection(scan, decision, redaction)
