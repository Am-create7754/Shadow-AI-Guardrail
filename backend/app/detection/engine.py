"""Detection engine: runs all detectors, merges duplicates, returns findings.

Pipeline::

    raw text -> size check -> normalise (invisibles / homoglyphs / NFKC)
             -> pattern rules + entropy heuristic (capped at MAX_CANDIDATES)
             -> merge same-entity overlaps -> repeated-secret propagation
             -> sorted findings (different entity types MAY overlap)
"""

from __future__ import annotations

import bisect
import hashlib
import hmac
import itertools
import re
import time
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass, replace

from app.detection.entropy import EntropyConfig, EntropyDetector
from app.detection.models import Category, DetectorKind, Finding
from app.detection.normalize import NormalizedText, normalize
from app.detection.rules import BUILTIN_RULES, PatternRule

CONTEXT_WINDOW = 48
SUPPRESS_WINDOW = 12
CORROBORATION_BOOST = 0.05
MIN_REPEAT_LEN = 6
MAX_REPEATS = 200  # occurrences searched per repeated value
MAX_REPEAT_VALUES = 200  # distinct values searched for repeats
# Upper bound on raw candidates per scan. Beyond this a prompt is bulk data, and
# inspecting it fully would cost more than the gateway's latency budget.
MAX_CANDIDATES = 5_000


class InputTooLargeError(ValueError):
    def __init__(self, size: int, limit: int) -> None:
        super().__init__(f"input of {size} characters exceeds the limit of {limit}")
        self.size = size
        self.limit = limit


@dataclass(frozen=True, slots=True)
class ScanResult:
    findings: tuple[Finding, ...]
    suppressed: int  # same-entity candidates merged into another finding
    normalized: bool  # True if invisible/look-alike characters were folded
    input_chars: int
    duration_ms: float
    truncated: bool = False  # MAX_CANDIDATES hit: the policy must fail closed

    @property
    def redactable(self) -> tuple[Finding, ...]:
        return tuple(f for f in self.findings if f.redactable)


def fingerprint(value: str, key: bytes) -> str:
    """Keyed, non-reversible identifier for a detected value (first 128 bits of HMAC-SHA256)."""
    return hmac.new(key, value.encode("utf-8", "surrogatepass"), hashlib.sha256).hexdigest()[:32]


def priority(f: Finding, min_confidence: float = 0.0) -> tuple[int, int, int, float, int, int]:
    """Sort key, best first: actionable confidence, severity, specific rules before
    the generic entropy heuristic, confidence, length, position."""
    return (
        int(f.confidence < min_confidence),
        -int(f.severity),
        int(f.detector is DetectorKind.ENTROPY),
        -f.confidence,
        -f.length,
        f.start,
    )


def merge_same_entity(candidates: Iterable[Finding]) -> tuple[list[Finding], int]:
    """Merge overlapping candidates that report the SAME entity type.

    Two rules seeing the same password (e.g. ``password-assignment`` and
    ``password-natural-language``) become one finding whose span is the union -
    when detectors disagree on boundaries, covering more is the safe failure.

    Findings of *different* entity types are never merged or dropped here, even
    if they overlap: each one must reach the policy engine so that, for example,
    a card number inside a URL password still triggers the card's BLOCK action.
    Overlapping spans are unioned later, at redaction time.

    O(n log n): one sort plus a linear sweep per entity type.
    """
    by_type: dict[str, list[Finding]] = {}
    for c in candidates:
        by_type.setdefault(c.entity_type, []).append(c)
    out: list[Finding] = []
    merged_away = 0
    for group in by_type.values():
        group.sort(key=lambda f: (f.start, -f.end))
        current: Finding | None = None
        for f in group:
            if current is None or f.start >= current.end:
                if current is not None:
                    out.append(current)
                current = f
                continue
            merged_away += 1
            best, other = (current, f) if priority(current) <= priority(f) else (f, current)
            widened = (min(current.start, f.start), max(current.end, f.end)) != (
                best.start,
                best.end,
            )
            corroborated = best.corroborated_by
            if other.rule_id != best.rule_id and other.rule_id not in corroborated:
                corroborated = (*corroborated, other.rule_id)
            boost = CORROBORATION_BOOST if other.rule_id != best.rule_id else 0.0
            current = replace(
                best,
                start=min(current.start, f.start),
                end=max(current.end, f.end),
                value="" if widened else best.value,  # recomputed by the caller
                confidence=round(min(0.99, max(current.confidence, f.confidence) + boost), 3),
                corroborated_by=corroborated,
                redactable=current.redactable or f.redactable,
            )
        if current is not None:
            out.append(current)
    out.sort(key=lambda f: (f.start, f.end, f.entity_type))
    return out, merged_away


class DetectionEngine:
    def __init__(
        self,
        rules: Sequence[PatternRule] = BUILTIN_RULES,
        *,
        entropy: EntropyConfig | None = None,
        disabled_rules: Iterable[str] = (),
        max_input_chars: int = 100_000,
    ) -> None:
        disabled = set(disabled_rules)
        self.rules: tuple[PatternRule, ...] = tuple(r for r in rules if r.rule_id not in disabled)
        entropy_cfg = entropy or EntropyConfig()
        if EntropyDetector.rule_id in disabled:
            entropy_cfg = replace(entropy_cfg, enabled=False)
        self.entropy = EntropyDetector(entropy_cfg)
        self.max_input_chars = max_input_chars
        ids = [r.rule_id for r in self.rules]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate rule_id in detection rules")

    @property
    def rule_ids(self) -> tuple[str, ...]:
        return (*(r.rule_id for r in self.rules), EntropyDetector.rule_id)

    def scan(self, text: str) -> ScanResult:
        if not isinstance(text, str):
            raise TypeError("text must be str")
        if len(text) > self.max_input_chars:
            raise InputTooLargeError(len(text), self.max_input_chars)
        t0 = time.perf_counter()
        nt = normalize(text)
        candidates: list[Finding] = []
        truncated = False
        for cand in itertools.chain(self._pattern_findings(nt), self.entropy.detect(nt)):
            if len(candidates) >= MAX_CANDIDATES:
                truncated = True
                break
            candidates.append(cand)
        findings, merged = merge_same_entity(candidates)
        findings = _restore_values(text, findings)
        repeats = list(_repeated_secrets(nt, findings))
        if repeats:
            findings, more = merge_same_entity([*findings, *repeats])
            findings = _restore_values(text, findings)
            merged += more
        return ScanResult(
            findings=tuple(findings),
            suppressed=merged,
            normalized=nt.changed,
            input_chars=len(text),
            duration_ms=round((time.perf_counter() - t0) * 1000, 3),
            truncated=truncated,
        )

    def _pattern_findings(self, nt: NormalizedText) -> Iterator[Finding]:
        text = nt.text
        for rule in self.rules:
            for m in rule.pattern.finditer(text):
                start, end = m.span(rule.group)
                if start < 0 or start == end:
                    continue
                value = text[start:end]
                if rule.validator is not None and not rule.validator(value):
                    continue
                if rule.value_check is not None and not rule.value_check(
                    value, text[end : end + 2]
                ):
                    continue
                confidence = rule.confidence
                explanation = rule.description
                # Slice before lowercasing: str.lower() can change length (U+0130 becomes
                # two code points), so indices into a lowercased copy of the text would drift.
                if rule.suppress_keywords:
                    before = text[max(0, start - SUPPRESS_WINDOW) : start].lower()
                    if any(_word_in(k, before) for k in rule.suppress_keywords):
                        continue
                if rule.context_keywords:
                    window = text[max(0, start - CONTEXT_WINDOW) : end + CONTEXT_WINDOW].lower()
                    hit = next((k for k in rule.context_keywords if _word_in(k, window)), None)
                    if hit:
                        confidence = min(0.99, confidence + rule.context_boost)
                        explanation += f" (context keyword '{hit}')"
                o_start, o_end = nt.to_original_span(start, end)
                yield Finding(
                    rule_id=rule.rule_id,
                    entity_type=rule.entity_type,
                    category=rule.category,
                    severity=rule.severity,
                    confidence=round(confidence, 3),
                    detector=rule.detector,
                    start=o_start,
                    end=o_end,
                    value=value,
                    redactable=rule.redactable,
                    explanation=explanation
                    + (
                        " [normalised: hidden/look-alike characters removed]"
                        if nt.changed and nt.original[o_start:o_end] != value
                        else ""
                    ),
                )


def _restore_values(text: str, findings: list[Finding]) -> list[Finding]:
    """Fill in values for spans widened during merging (normalised, like detection)."""
    return [
        f if f.value else replace(f, value=normalize(text[f.start : f.end]).text) for f in findings
    ]


def _repeated_secrets(nt: NormalizedText, findings: Sequence[Finding]) -> Iterator[Finding]:
    """Find other occurrences of an already-detected secret value.

    ``postgres://u:Pa55word@db ... the password is still Pa55word`` - the second
    occurrence has no recognisable context of its own, but it is the same secret.
    Repeats keep the original ``rule_id`` so rule-level policy applies to them too.
    """
    spans = sorted((f.start, f.end) for f in findings)
    starts = [s for s, _ in spans]
    max_len = max((e - s for s, e in spans), default=0)

    def covered(o_start: int, o_end: int) -> bool:
        # Spans starting before o_start - max_len cannot reach o_start.
        lo = bisect.bisect_left(starts, o_start - max_len)
        hi = bisect.bisect_left(starts, o_end)
        return any(spans[i][1] > o_start for i in range(lo, hi))

    seen: set[str] = set()
    for f in findings:
        if (
            not f.redactable
            or f.category is not Category.SECRET
            or len(f.value) < MIN_REPEAT_LEN
            or f.value in seen
        ):
            continue
        if len(seen) >= MAX_REPEAT_VALUES:
            break
        seen.add(f.value)
        idx = nt.text.find(f.value)
        hits = 0
        while idx != -1 and hits < MAX_REPEATS:
            o_start, o_end = nt.to_original_span(idx, idx + len(f.value))
            if not covered(o_start, o_end):
                hits += 1
                yield replace(
                    f,
                    start=o_start,
                    end=o_end,
                    corroborated_by=(),
                    explanation=f"Repeated occurrence of a value detected by '{f.rule_id}'",
                )
            idx = nt.text.find(f.value, idx + len(f.value))


def _word_in(keyword: str, window: str) -> bool:
    return re.search(r"(?<![a-z])" + re.escape(keyword) + r"(?![a-z])", window) is not None


__all__ = [
    "DetectionEngine",
    "DetectorKind",
    "InputTooLargeError",
    "ScanResult",
    "fingerprint",
    "merge_same_entity",
    "priority",
]
