"""Typed, numbered placeholder redaction.

``db_password=admin_pass_123`` becomes ``db_password=[PASSWORD_1]``.

* Numbering is per entity type, in order of first appearance.
* The same value (by keyed fingerprint) always gets the same placeholder within
  one request, so the model can still reason about "the same password used twice".
* If the input *already* contains placeholder-shaped text (e.g. a user pasting
  ``[PASSWORD_1]`` to confuse later restoration), those numbers are skipped so a
  generated placeholder never collides with user-supplied text.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass, field

from app.detection.engine import fingerprint, priority
from app.detection.models import Finding
from app.detection.normalize import normalize

PLACEHOLDER_RE = re.compile(r"\[([A-Z][A-Z0-9_]*?)_(\d{1,6})\]")


@dataclass(frozen=True, slots=True)
class Replacement:
    placeholder: str
    entity_type: str
    rule_id: str
    start: int  # span in the ORIGINAL text
    end: int
    fingerprint: str

    def to_public(self) -> dict[str, object]:
        return {
            "placeholder": self.placeholder,
            "entity_type": self.entity_type,
            "rule_id": self.rule_id,
            "start": self.start,
            "end": self.end,
            "fingerprint": self.fingerprint,
        }


@dataclass(frozen=True, slots=True)
class RedactionResult:
    text: str
    replacements: tuple[Replacement, ...]
    # placeholder -> original value. In-memory only; never logged or serialised.
    mapping: dict[str, str] = field(repr=False)

    @property
    def redacted(self) -> bool:
        return bool(self.replacements)


def _reserved_numbers(text: str) -> dict[str, set[int]]:
    """Placeholder numbers already present in the input, in raw OR normalised form.

    Normalising first catches look-alikes such as full-width brackets or a
    zero-width character inside ``[PASSWORD_1]``.
    """
    reserved: dict[str, set[int]] = {}
    for candidate in (text, normalize(text).text):
        for m in PLACEHOLDER_RE.finditer(candidate):
            reserved.setdefault(m.group(1), set()).add(int(m.group(2)))
    return reserved


def _regions(findings: Sequence[Finding]) -> list[tuple[int, int, Finding]]:
    """Union overlapping findings into maximal regions.

    Each region is labelled by its highest-priority finding, so ``password: 2345
    6789 0124`` (a PASSWORD overlapping an AADHAAR) becomes one placeholder that
    covers all twelve digits instead of leaking the tail.
    """
    regions: list[tuple[int, int, Finding]] = []
    for f in sorted(findings, key=lambda f: (f.start, -f.end)):
        if regions and f.start < regions[-1][1]:
            s, e, label = regions[-1]
            if priority(f) < priority(label):
                label = f
            regions[-1] = (s, max(e, f.end), label)
        else:
            regions.append((f.start, f.end, f))
    return regions


def redact(text: str, findings: Sequence[Finding], key: bytes) -> RedactionResult:
    """Replace every redactable finding's span with a typed placeholder.

    Findings may overlap; overlapping spans are merged into one region.
    """
    regions = _regions([f for f in findings if f.redactable])
    reserved = _reserved_numbers(text) if regions else {}
    counters: dict[str, int] = {}
    by_fp: dict[tuple[str, str], str] = {}
    mapping: dict[str, str] = {}
    replacements: list[Replacement] = []
    parts: list[str] = []
    cursor = 0

    for start, end, label in regions:
        original = text[start:end]
        fp = fingerprint(normalize(original).text, key)
        etype = label.entity_type
        placeholder = by_fp.get((etype, fp))
        if placeholder is None:
            n = counters.get(etype, 0) + 1
            taken = reserved.get(etype, set())
            while n in taken:
                n += 1
            counters[etype] = n
            placeholder = f"[{etype}_{n}]"
            by_fp[(etype, fp)] = placeholder
            mapping[placeholder] = original
        parts.append(text[cursor:start])
        parts.append(placeholder)
        cursor = end
        replacements.append(Replacement(placeholder, etype, label.rule_id, start, end, fp))
    parts.append(text[cursor:])
    return RedactionResult("".join(parts), tuple(replacements), mapping)
