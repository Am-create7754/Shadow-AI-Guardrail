"""Facade combining detection, policy and redaction into one inspection call.

This is the single entry point the gateway (Phase 3) uses for prompts and the
output engine (Phase 4) uses for model responses.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, replace

from app.core.config import Settings, get_settings
from app.detection.engine import DetectionEngine, InputTooLargeError, ScanResult
from app.detection.models import Finding
from app.detection.normalize import normalize
from app.detection.redaction import PlaceholderAllocator, RedactionResult, redact
from app.policy.engine import PolicyDecision, PolicyEngine, build_detection_engine, load_policy
from app.policy.models import Action, PolicyConfig

# Room for separators when a conversation is scanned as one joined string.
MAX_JOIN_OVERHEAD = 1_000


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


@dataclass(frozen=True, slots=True)
class ConversationInspection:
    """Inspection of several messages that leave the gateway together."""

    messages: tuple[Inspection, ...]
    decision: PolicyDecision  # combined over all messages

    @property
    def action(self) -> Action:
        return self.decision.action

    @property
    def forwardable_texts(self) -> list[str] | None:
        if self.decision.action in (Action.BLOCK, Action.REQUIRE_APPROVAL):
            return None
        return [m.redaction.text for m in self.messages]

    @property
    def sanitized_texts(self) -> list[str]:
        """Redacted texts regardless of decision (e.g. to hold for approval)."""
        return [m.redaction.text for m in self.messages]

    @property
    def entity_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for d in self.decision.findings:
            if d.action is not Action.ALLOW:
                counts[d.finding.entity_type] = counts.get(d.finding.entity_type, 0) + 1
        return dict(sorted(counts.items()))

    @property
    def placeholders(self) -> list[str]:
        return sorted({r.placeholder for m in self.messages for r in m.redaction.replacements})

    def to_public(self) -> dict[str, object]:
        return {
            "action": self.decision.action.value,
            "risk_score": self.decision.risk_score,
            "risk_level": self.decision.risk_level,
            "reasons": list(self.decision.reasons),
            "policy": self.decision.policy_name,
            "messages": [
                {k: v for k, v in m.to_public().items() if k not in ("policy",)}
                for m in self.messages
            ],
        }


class Guardrail:
    def __init__(self, policy: PolicyConfig, settings: Settings) -> None:
        self.policy = policy
        self.settings = settings
        self.detector: DetectionEngine = build_detection_engine(
            policy, max_input_chars=settings.max_input_chars
        )
        # Scans whole conversations joined together (limit allows the separators).
        self._joined_detector = build_detection_engine(
            policy, max_input_chars=settings.max_input_chars + MAX_JOIN_OVERHEAD
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

    def inspect_conversation(self, texts: Sequence[str]) -> ConversationInspection:
        """Inspect messages that are sent together.

        * The size limit applies to the conversation as a whole.
        * One placeholder allocator spans all messages, so a placeholder means the
          same value everywhere and never collides with placeholder-like text in
          any message.
        * The combined decision is evaluated over the findings of all messages
          (shifted to distinct offsets), so escalation thresholds such as "10
          sensitive items" count across messages, not per message.
        """
        total = sum(len(t) for t in texts)
        if total > self.settings.max_input_chars:
            raise InputTooLargeError(total, self.settings.max_input_chars)
        allocator = PlaceholderAllocator(self._key, texts)
        scans = [self.detector.scan(text) for text in texts]
        cross = self._cross_message_findings(texts, scans)
        inspections = []
        shifted = []
        truncated = False
        offset = 0
        for text, scan, extra in zip(texts, scans, cross, strict=True):
            if extra:
                scan = replace(
                    scan,
                    findings=tuple(
                        sorted(
                            (*scan.findings, *extra), key=lambda f: (f.start, f.end, f.entity_type)
                        )
                    ),
                )
            decision = self.policy_engine.evaluate(scan.findings, truncated=scan.truncated)
            redaction = redact(text, decision.to_redact, self._key, allocator)
            inspections.append(Inspection(scan, decision, redaction))
            shifted += [
                replace(f, start=f.start + offset, end=f.end + offset) for f in scan.findings
            ]
            truncated = truncated or scan.truncated
            offset += len(text) + 1
        combined = self.policy_engine.evaluate(shifted, truncated=truncated)
        return ConversationInspection(tuple(inspections), combined)

    def _cross_message_findings(
        self, texts: Sequence[str], scans: Sequence[ScanResult]
    ) -> list[list[Finding]]:
        """Findings that only exist when messages are read together.

        A secret split across two messages ("ghp_A1b2..." + "...Q7r8") or a phrase
        split across them ("Project" + "Nightingale") is invisible to per-message
        scanning. The conversation is therefore also scanned joined with no
        separator (re-assembles split tokens) and with a space (re-assembles split
        phrases). Every finding that spans a message boundary is mapped back onto
        each message it touches, so the parts are redacted - or the whole request
        escalated - exactly like a finding inside one message.

        Joining without a separator also glues unrelated text together
        ("...db_password=hunter2hunter" + "Is it strong?"). A cross finding is
        therefore dropped when its part in the first message it touches is
        already detected, as the same entity type, inside that message alone:
        then nothing was split, and extending the match would only redact the
        user's next words.
        """
        per_message: list[list[Finding]] = [[] for _ in texts]
        if len(texts) < 2:
            return per_message
        for sep in ("", " "):
            starts: list[int] = []
            pos = 0
            for t in texts:
                starts.append(pos)
                pos += len(t) + len(sep)
            joined = sep.join(texts)
            for f in self._joined_detector.scan(joined).findings:
                touched = [
                    i
                    for i, (st, t) in enumerate(zip(starts, texts, strict=True))
                    if f.start < st + len(t) and st < f.end and t
                ]
                if len(touched) < 2:
                    continue  # inside one message: the per-message scan has it
                first = touched[0]
                lo0 = max(f.start, starts[first]) - starts[first]
                hi0 = min(f.end, starts[first] + len(texts[first])) - starts[first]
                if any(
                    g.entity_type == f.entity_type and g.start <= lo0 and g.end >= hi0
                    for g in scans[first].findings
                ):
                    continue
                for i in touched:
                    lo = max(f.start, starts[i]) - starts[i]
                    hi = min(f.end, starts[i] + len(texts[i])) - starts[i]
                    if lo >= hi:
                        continue
                    per_message[i].append(
                        replace(
                            f,
                            start=lo,
                            end=hi,
                            value=normalize(texts[i][lo:hi]).text,
                            explanation=f.explanation + " [split across messages]",
                        )
                    )
        return per_message
