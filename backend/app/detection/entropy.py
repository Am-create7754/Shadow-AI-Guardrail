"""High-entropy string detector.

Catches random-looking credentials that have no recognisable vendor prefix
(e.g. a homegrown API key). Entropy alone produces many false positives on
hashes, UUIDs, paths and identifiers, so candidates pass several structural
filters and get a confidence that depends on nearby context keywords.
"""

from __future__ import annotations

import math
import re
from collections.abc import Iterator
from dataclasses import dataclass

from app.detection.models import Category, DetectorKind, Finding, Severity
from app.detection.normalize import NormalizedText
from app.detection.validators import char_class_count, shannon_entropy

_CANDIDATE = re.compile(
    r"(?<![A-Za-z0-9+/_\-])([A-Za-z0-9+/_\-]{20,512}={0,2})(?![A-Za-z0-9+/=_\-])"
)
_HEX = re.compile(r"^[0-9a-fA-F]+$")
_UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_WORDISH_PART = re.compile(r"^[A-Za-z]{2,}\d{0,2}$|^\d{1,4}$")
_CAMEL_SPLIT = re.compile(r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])|\d+")

DEFAULT_CONTEXT_KEYWORDS = (
    "key", "secret", "token", "password", "passwd", "pwd", "auth", "credential",
    "bearer", "api", "private", "signature", "salt", "session", "cookie", "vault",
)  # fmt: skip


@dataclass(frozen=True, slots=True)
class EntropyConfig:
    enabled: bool = True
    min_length: int = 20
    # Minimum bits/char for base64-like and hex-like strings respectively.
    min_entropy_base64: float = 4.0
    min_entropy_hex: float = 3.0
    context_window: int = 40
    context_keywords: tuple[str, ...] = DEFAULT_CONTEXT_KEYWORDS
    base_confidence: float = 0.5
    context_confidence: float = 0.8
    long_random_confidence: float = 0.65


def _mixed_alnum(token: str) -> bool:
    return (
        any(c.islower() for c in token)
        and any(c.isupper() for c in token)
        and sum(c.isdigit() for c in token) >= 2
    )


def _looks_like_identifier_or_path(token: str) -> bool:
    """True for things like ``user_profile_picture_url``, ``src/app/main``, ``getUserById``."""
    parts = [p for p in re.split(r"[/_\-.]", token) if p]
    if len(parts) >= 2 and all(_WORDISH_PART.match(p) for p in parts):
        return True
    # camelCase / PascalCase made of word-like chunks
    chunks = _CAMEL_SPLIT.findall(token)
    if chunks and "".join(chunks) == token and len(chunks) >= 3:
        long_lower_words = sum(1 for c in chunks if len(c) >= 3 and c[1:].islower())
        if long_lower_words >= len(chunks) - 1:
            return True
    return False


class EntropyDetector:
    rule_id = "high-entropy-string"

    def __init__(self, config: EntropyConfig | None = None) -> None:
        self.config = config or EntropyConfig()

    def _has_context(self, text: str, start: int, end: int) -> bool:
        w = self.config.context_window
        # Slice, then lowercase: lower() may change length for some characters.
        window = (text[max(0, start - w) : start] + " " + text[end : end + 15]).lower()
        return any(k in window for k in self.config.context_keywords)

    def detect(self, nt: NormalizedText) -> Iterator[Finding]:
        cfg = self.config
        if not cfg.enabled:
            return
        text = nt.text
        for m in _CANDIDATE.finditer(text):
            token = m.group(1).rstrip("=")
            if len(token) < cfg.min_length:
                continue
            if token.isalpha() or token.isdigit() or _UUID.match(token):
                continue
            if _looks_like_identifier_or_path(token):
                continue
            has_context = self._has_context(text, m.start(1), m.end(1))
            ent = shannon_entropy(token)
            # Max possible entropy is log2(len); scale the bar for short tokens.
            ceiling = math.log2(min(len(token), 64))
            if _HEX.match(token):
                # Hex blobs are usually hashes/commit IDs: only flag with context.
                if not has_context or ent < min(cfg.min_entropy_hex, 0.8 * ceiling):
                    continue
            else:
                if char_class_count(token) < 2:
                    continue
                if ent < min(cfg.min_entropy_base64, 0.85 * ceiling):
                    continue
            confidence = cfg.context_confidence if has_context else cfg.base_confidence
            if not has_context and len(token) >= 32 and _mixed_alnum(token):
                # Long random mixed-case alphanumerics are rarely anything but keys.
                confidence = max(confidence, cfg.long_random_confidence)
            confidence = min(0.9, confidence + max(0.0, ent - 4.5) * 0.05)
            start, end = m.start(1), m.start(1) + len(token)
            o_start, o_end = nt.to_original_span(start, end)
            yield Finding(
                rule_id=self.rule_id,
                entity_type="HIGH_ENTROPY_SECRET",
                category=Category.SECRET,
                severity=Severity.HIGH if has_context else Severity.MEDIUM,
                confidence=round(confidence, 3),
                detector=DetectorKind.ENTROPY,
                start=o_start,
                end=o_end,
                value=token,
                explanation=(
                    f"High-entropy string ({ent:.2f} bits/char)"
                    + (" near a credential keyword" if has_context else "")
                ),
            )
