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


class PlaceholderAllocator:
    """Hands out placeholders; one allocator can span several texts.

    A conversation is redacted with ONE allocator so that ``[PASSWORD_1]`` means
    the same secret in every message, and numbers already present in *any*
    message are never reused.
    """

    def __init__(self, key: bytes, texts: Sequence[str] = ()) -> None:
        self._key = key
        self.reserved: dict[str, set[int]] = {}
        for t in texts:
            self.reserve_from(t)
        self._counters: dict[str, int] = {}
        self._by_fp: dict[tuple[str, str], str] = {}
        self.mapping: dict[str, str] = {}

    def reserve_from(self, text: str) -> None:
        for etype, numbers in _reserved_numbers(text).items():
            self.reserved.setdefault(etype, set()).update(numbers)

    def placeholder_for(self, etype: str, original: str) -> tuple[str, str]:
        fp = fingerprint(normalize(original).text, self._key)
        placeholder = self._by_fp.get((etype, fp))
        if placeholder is None:
            n = self._counters.get(etype, 0) + 1
            taken = self.reserved.get(etype, set())
            while n in taken:
                n += 1
            self._counters[etype] = n
            placeholder = f"[{etype}_{n}]"
            self._by_fp[(etype, fp)] = placeholder
            self.mapping[placeholder] = original
        return placeholder, fp


def redact(
    text: str,
    findings: Sequence[Finding],
    key: bytes,
    allocator: PlaceholderAllocator | None = None,
) -> RedactionResult:
    """Replace every redactable finding's span with a typed placeholder.

    Findings may overlap; overlapping spans are merged into one region. Pass a
    shared ``allocator`` to keep numbering consistent across several texts.
    """
    regions = _regions([f for f in findings if f.redactable])
    if allocator is None:
        allocator = PlaceholderAllocator(key, [text] if regions else [])
    replacements: list[Replacement] = []
    parts: list[str] = []
    cursor = 0
    used: dict[str, str] = {}

    for start, end, label in regions:
        original = text[start:end]
        placeholder, fp = allocator.placeholder_for(label.entity_type, original)
        used[placeholder] = allocator.mapping[placeholder]
        parts.append(text[cursor:start])
        parts.append(placeholder)
        cursor = end
        replacements.append(
            Replacement(placeholder, label.entity_type, label.rule_id, start, end, fp)
        )
    parts.append(text[cursor:])
    return RedactionResult("".join(parts), tuple(replacements), used)
