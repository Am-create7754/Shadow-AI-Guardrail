"""Core data types shared by detectors, the engine, redaction and policy."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import IntEnum, StrEnum

ENTITY_TYPE_RE = re.compile(r"^[A-Z][A-Z0-9_]{1,47}$")


class Category(StrEnum):
    """Broad class of sensitive data; policies can act on a whole category."""

    SECRET = "SECRET"  # noqa: S105 - credentials, API keys, tokens, private keys
    PII = "PII"  # personal identifiers
    FINANCIAL = "FINANCIAL"  # card numbers, bank accounts
    INFRASTRUCTURE = "INFRASTRUCTURE"  # internal hosts / IPs
    CONFIDENTIAL = "CONFIDENTIAL"  # classification markers, codenames


class Severity(IntEnum):
    """Ordered so that ``max()`` picks the worst severity."""

    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class DetectorKind(StrEnum):
    REGEX = "regex"  # known token format
    CONTEXT = "context"  # keyword-anchored assignment (password=..., "my password is ...")
    CHECKSUM = "checksum"  # format + checksum validated (Luhn, Verhoeff, mod-97)
    ENTROPY = "entropy"  # high-entropy string heuristic
    KEYWORD = "keyword"  # organisation-defined terms / markers


@dataclass(frozen=True, slots=True)
class Finding:
    """One detected sensitive span.

    ``start``/``end`` index into the *original* text. ``value`` holds the raw
    matched text; it is excluded from ``repr`` and from :meth:`to_public` so it
    cannot leak through logs or API responses by accident.
    """

    rule_id: str
    entity_type: str
    category: Category
    severity: Severity
    confidence: float
    detector: DetectorKind
    start: int
    end: int
    value: str = field(repr=False)
    redactable: bool = True
    explanation: str = ""
    corroborated_by: tuple[str, ...] = ()

    @property
    def length(self) -> int:
        return self.end - self.start

    def overlaps(self, other: Finding) -> bool:
        return self.start < other.end and other.start < self.end

    def to_public(self) -> dict[str, object]:
        """Serializable view that never includes the raw value."""
        return {
            "rule_id": self.rule_id,
            "entity_type": self.entity_type,
            "category": self.category.value,
            "severity": self.severity.name,
            "confidence": round(self.confidence, 3),
            "detector": self.detector.value,
            "start": self.start,
            "end": self.end,
            "length": self.length,
            "redactable": self.redactable,
            "explanation": self.explanation,
            "corroborated_by": list(self.corroborated_by),
        }
